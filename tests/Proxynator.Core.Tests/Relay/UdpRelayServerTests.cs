using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Proxies;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Relay;

/// <summary>
/// UDP relay tests on loopback. Like the TCP relay tests, they simulate a capture backend: bind the client socket,
/// register its endpoint with the original destination, then send to the relay.
/// </summary>
public sealed class UdpRelayServerTests : IAsyncLifetime
{
    private const int SocksPid = 1;
    private const int DirectPid = 2;
    private const int BlockedPid = 3;
    private const int HttpPid = 4;
    private const int HttpDirectPid = 5;

    private readonly UdpEchoServer echo = new();
    private readonly OriginalDestinationTable table = new();
    private readonly ConnectionTracker tracker = new();
    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private FakeProxyServer socks = null!;
    private FakeDnsServer dns = null!;
    private ConfigurationStore store = null!;
    private UdpRelayServer relay = null!;

    public ValueTask InitializeAsync()
    {
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = _ => echo.Endpoint };
        dns = new FakeDnsServer(new Dictionary<string, IPAddress> { ["real.example"] = IPAddress.Parse("192.0.2.80") });
        store = new ConfigurationStore(Config(DnsMode.Sniff));
        var processes = new StaticProcessInfoProvider(
            new ProcessInfo(SocksPid, "socks.exe", null),
            new ProcessInfo(DirectPid, "direct.exe", null),
            new ProcessInfo(BlockedPid, "blocked.exe", null),
            new ProcessInfo(HttpPid, "http.exe", null),
            new ProcessInfo(HttpDirectPid, "httpdirect.exe", null));
        relay = new UdpRelayServer(store, table, processes, tracker, NullLogger<UdpRelayServer>.Instance, fakeIps, new MapResolver(echo.Endpoint.Address))
        {
            DnsPort = dns.Endpoint.Port,
        };
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await relay.DisposeAsync();
        await socks.DisposeAsync();
        await dns.DisposeAsync();
        await echo.DisposeAsync();
    }

    private ProxynatorConfig Config(DnsMode dnsMode) => Configs.Minimal() with
    {
        Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = dnsMode, RemoteDomains = ["*.corp.test"] } },
        Proxies = [Configs.Proxy("socks", ProxyType.Socks5, socks.Endpoint.Port), Configs.Proxy("http", ProxyType.Http, 1)],
        Rules =
        [
            Configs.Rule("socks", RuleActionType.Proxy, "socks", new RuleMatch { Processes = ["socks.exe"] }),
            Configs.Rule("block", RuleActionType.Block, match: new RuleMatch { Processes = ["blocked.exe"] }),
            Configs.Rule("http", RuleActionType.Proxy, "http", new RuleMatch { Processes = ["http.exe"] }),
            Configs.Rule("http with direct udp", RuleActionType.Proxy, "http", new RuleMatch { Processes = ["httpdirect.exe"] }) with
            {
                Action = new RuleActionDefinition { Type = RuleActionType.Proxy, Target = "http", Udp = UdpFallback.Direct },
            },
        ],
    };

    private Socket Client(IPEndPoint originalDestination, int pid, string? hostname = null)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        table.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(originalDestination, pid, hostname));
        return client;
    }

    private async Task<byte[]?> ExchangeAsync(Socket client, byte[] datagram, int timeoutMs = 2000)
    {
        await client.SendToAsync(datagram, SocketFlags.None, relay.LocalEndpoints[0]);
        using var timeout = new CancellationTokenSource(timeoutMs);
        try
        {
            var buffer = new byte[65535];
            var result = await client.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
            Assert.Equal(relay.LocalEndpoints[0], result.RemoteEndPoint);
            return buffer.AsSpan(0, result.ReceivedBytes).ToArray();
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    [Fact]
    public async Task Unmatched_flows_go_direct()
    {
        using var client = Client(echo.Endpoint, DirectPid);

        Assert.Equal("hello"u8.ToArray(), await ExchangeAsync(client, "hello"u8.ToArray()));
        Assert.Equal("again"u8.ToArray(), await ExchangeAsync(client, "again"u8.ToArray()));
        Assert.Empty(socks.Requests);

        var session = Assert.Single(tracker.GetActive());
        var ct = TestTimeout.Token();
        while (session.BytesSent < 10 || session.BytesReceived < 10)
        {
            await Task.Delay(10, ct); // counted just after the datagrams went out
        }

        Assert.Equal((TransportProtocol.Udp, 10L, 10L), (session.Context.Protocol, session.BytesSent, session.BytesReceived));
    }

    [Fact]
    public async Task Socks5_rules_use_udp_associate()
    {
        using var client = Client(new IPEndPoint(IPAddress.Parse("192.0.2.53"), 5353), SocksPid);

        Assert.Equal("ping"u8.ToArray(), await ExchangeAsync(client, "ping"u8.ToArray()));

        var request = Assert.Single(socks.Requests);
        Assert.True(request.Udp);
        Assert.Equal((IPAddress.Parse("192.0.2.53"), 5353), (request.Address, request.Port));
    }

    [Fact]
    public async Task Socks5_udp_carries_fake_ip_hostnames()
    {
        var fake = fakeIps.GetOrAllocate("dc01.corp.test");
        using var client = Client(new IPEndPoint(fake, 88), SocksPid);

        Assert.Equal("krb"u8.ToArray(), await ExchangeAsync(client, "krb"u8.ToArray()));

        var request = Assert.Single(socks.Requests);
        Assert.Equal(("dc01.corp.test", 88), (request.Host, request.Port));
    }

    [Fact]
    public async Task Quic_is_blocked_for_proxied_processes()
    {
        using var client = Client(new IPEndPoint(echo.Endpoint.Address, 443), SocksPid);

        Assert.Null(await ExchangeAsync(client, "quic"u8.ToArray(), 500));
        Assert.Empty(socks.Requests);
    }

    [Fact]
    public async Task Block_rules_drop_datagrams()
    {
        using var client = Client(echo.Endpoint, BlockedPid);

        Assert.Null(await ExchangeAsync(client, "x"u8.ToArray(), 500));
        Assert.Equal(0, echo.DatagramCount);
    }

    [Fact]
    public async Task Proxies_without_udp_follow_the_rule_fallback()
    {
        using var blocked = Client(echo.Endpoint, HttpPid);
        using var direct = Client(echo.Endpoint, HttpDirectPid);

        Assert.Null(await ExchangeAsync(blocked, "x"u8.ToArray(), 500));
        Assert.Equal("y"u8.ToArray(), await ExchangeAsync(direct, "y"u8.ToArray()));
    }

    [Fact]
    public async Task Unregistered_datagrams_are_dropped()
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        Assert.Null(await ExchangeAsync(client, "x"u8.ToArray(), 500));
    }

    [Fact]
    public async Task Remote_dns_answers_configured_names_with_fake_addresses_and_forwards_the_rest()
    {
        store.TryApply(Config(DnsMode.Remote));
        using var client = Client(dns.Endpoint, DirectPid);

        var faked = await ExchangeAsync(client, DnsWire.BuildQuery(1, "dc01.corp.test", DnsWire.TypeA));
        var forwarded = await ExchangeAsync(client, DnsWire.BuildQuery(2, "real.example", DnsWire.TypeA));

        var fakeAddress = Assert.Single(FakeDnsServer.AddressesIn(faked!));
        Assert.True(fakeIps.TryGetHostname(fakeAddress, out var name));
        Assert.Equal("dc01.corp.test", name);
        Assert.Equal([IPAddress.Parse("192.0.2.80")], FakeDnsServer.AddressesIn(forwarded!));
        Assert.Equal(["real.example"], dns.Queries);
    }

    [Fact]
    public async Task Idle_sessions_are_closed()
    {
        var time = new ManualTimeProvider();
        var idleTable = new OriginalDestinationTable();
        var idleTracker = new ConnectionTracker();
        await using var idleRelay = new UdpRelayServer(store, idleTable, new StaticProcessInfoProvider(), idleTracker, NullLogger<UdpRelayServer>.Instance, timeProvider: time);
        idleRelay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        idleTracker.Closed += (_, _) => closed.TrySetResult();

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        idleTable.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(echo.Endpoint, 99));
        await client.SendToAsync("x"u8.ToArray(), SocketFlags.None, idleRelay.LocalEndpoints[0]);
        await client.ReceiveFromAsync(new byte[16], SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), TestTimeout.Token());

        idleRelay.SweepIdleSessions();
        Assert.Equal(1, idleRelay.SessionCount);

        time.Advance(TimeSpan.FromMinutes(3));
        idleRelay.SweepIdleSessions();
        Assert.Equal(0, idleRelay.SessionCount);
        await closed.Task.WaitAsync(TestTimeout.Token());
    }

    [Fact]
    public async Task Association_can_be_used_directly()
    {
        var ct = TestTimeout.Token();
        var hop = new ProxyHop("socks", ProxyType.Socks5, TargetEndpoint.FromAddress(IPAddress.Loopback, socks.Endpoint.Port), null);
        await using var association = await Socks5UdpAssociation.CreateAsync(hop, TcpConnector.Default, TimeSpan.FromSeconds(5), ct);

        await association.SendAsync(TargetEndpoint.FromHost("echo.test", 7), Encoding.ASCII.GetBytes("direct"), ct);
        var (source, payload) = await association.ReceiveAsync(new byte[1024], ct);

        Assert.Equal("direct", Encoding.ASCII.GetString(payload.Span));
        Assert.Equal(("echo.test", 7), (source.Host, source.Port));
        Assert.Equal(IPAddress.Loopback, association.RelayEndpoint.Address);
    }

    [Fact]
    public async Task Association_is_refused_for_non_socks5_hops()
    {
        var hop = new ProxyHop("http", ProxyType.Http, TargetEndpoint.FromAddress(IPAddress.Loopback, 1), null);

        var ex = await Assert.ThrowsAsync<ProxyException>(() => Socks5UdpAssociation.CreateAsync(hop, TcpConnector.Default, TimeSpan.FromSeconds(1), TestTimeout.Token()));

        Assert.Equal(ProxyFailure.Unsupported, ex.Failure);
    }

    /// <summary>Resolves every name to one address (stands in for the upstream resolver).</summary>
    private sealed class MapResolver(IPAddress address) : IHostResolver
    {
        public ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => ValueTask.FromResult<IPAddress[]>([address]);
    }
}
