using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Relay;

/// <summary>TCP connections to fake-IP DNS answers: the relay must use the hostname, never the fake address.</summary>
public sealed class FakeIpRelayTests : IAsyncLifetime
{
    private const int ProxiedPid = 1;
    private const int DirectPid = 2;

    private readonly EchoServer echo = new();
    private readonly OriginalDestinationTable table = new();
    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private readonly List<string> resolved = [];
    private FakeProxyServer socks = null!;
    private RelayServer relay = null!;

    public ValueTask InitializeAsync()
    {
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = _ => echo.Endpoint };
        var config = Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = DnsMode.Remote } },
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, socks.Endpoint.Port)],
            Rules = [Configs.Rule("proxied", RuleActionType.Proxy, "socks", new RuleMatch { Processes = ["proxied.exe"] })],
        };
        var processes = new StaticProcessInfoProvider(new ProcessInfo(ProxiedPid, "proxied.exe", null), new ProcessInfo(DirectPid, "direct.exe", null));
        relay = new RelayServer(new ConfigurationStore(config), table, processes, new ConnectionTracker(), NullLogger<RelayServer>.Instance,
            fakeIps: fakeIps, resolver: new RecordingResolver(resolved, IPAddress.Loopback));
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await relay.DisposeAsync();
        await socks.DisposeAsync();
        await echo.DisposeAsync();
    }

    private async Task<Socket> ConnectAsync(IPAddress destination, int port, int pid, CancellationToken ct)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        table.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(new IPEndPoint(destination, port), pid));
        await client.ConnectAsync(relay.LocalEndpoints[0], ct);
        return client;
    }

    [Fact]
    public async Task Proxied_connections_send_the_hostname_to_the_proxy()
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectAsync(fakeIps.GetOrAllocate("dc01.corp.local"), 445, ProxiedPid, ct);

        await client.SendAsync("smb"u8.ToArray(), ct);

        Assert.Equal("smb", await client.ReceiveStringAsync(3, ct));
        var request = Assert.Single(socks.Requests);
        Assert.Equal(("dc01.corp.local", 445), (request.Host, request.Port));
        Assert.Null(request.Address);
    }

    [Fact]
    public async Task Direct_connections_resolve_the_hostname_with_the_service_resolver()
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectAsync(fakeIps.GetOrAllocate("intranet.corp.local"), echo.Endpoint.Port, DirectPid, ct);

        await client.SendAsync("hi"u8.ToArray(), ct);

        Assert.Equal("hi", await client.ReceiveStringAsync(2, ct));
        Assert.Equal(["intranet.corp.local"], resolved);
        Assert.Empty(socks.Requests);
    }

    [Fact]
    public async Task Unknown_fake_addresses_are_refused()
    {
        var ct = TestTimeout.Token();
        try
        {
            using var client = await ConnectAsync(IPAddress.Parse("198.18.200.200"), 80, DirectPid, ct);
            Assert.True(await client.IsClosedByPeerAsync(ct));
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // The reset arrived before the connect completed (see CLAUDE.md gotchas).
        }

        Assert.Equal(0, echo.ConnectionCount);
    }

    private sealed class RecordingResolver(List<string> log, IPAddress address) : IHostResolver
    {
        public ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            lock (log)
            {
                log.Add(host);
            }

            return ValueTask.FromResult<IPAddress[]>([address]);
        }
    }
}
