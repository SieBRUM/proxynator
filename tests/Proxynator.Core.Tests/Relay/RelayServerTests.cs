using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Rules;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Relay;

/// <summary>
/// End-to-end relay tests on loopback. The "capture backend" is simulated the same way the injection backend
/// works: bind the client socket, register its original destination, then connect to the relay.
/// </summary>
public sealed class RelayServerTests : IAsyncLifetime
{
    private const int TestPid = 1;
    private const int BlockedPid = 2;
    private const int OtherPid = 3;
    private const int DownPid = 4;

    private static readonly IPEndPoint Unroutable = new(IPAddress.Parse("192.0.2.10"), 80);

    private readonly EchoServer echo = new();
    private readonly EchoServer banner = new(banner: "220 ready\r\n");
    private readonly OriginalDestinationTable table = new();
    private readonly ConnectionTracker tracker = new();
    private FakeProxyServer socks = null!;
    private RelayServer relay = null!;

    public ValueTask InitializeAsync()
    {
        // Everything the fake proxy is asked for ends up at the echo server, except port 25 (the banner server).
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = r => r.Port == 25 ? banner.Endpoint : echo.Endpoint };

        var config = Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { SniffTimeoutMs = 200 }, Relay = new RelaySettings { ConnectTimeoutMs = 2000 } },
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, socks.Endpoint.Port), Configs.Proxy("down", ProxyType.Socks5, UnusedPort())],
            Rules =
            [
                Configs.Rule("test via socks", RuleActionType.Proxy, "socks", new RuleMatch { Processes = ["test.exe"] }),
                Configs.Rule("block", RuleActionType.Block, match: new RuleMatch { Processes = ["blocked.exe"] }),
                Configs.Rule("down", RuleActionType.Proxy, "down", new RuleMatch { Processes = ["down.exe"] }),
            ],
        };

        var processes = new StaticProcessInfoProvider(
            new ProcessInfo(TestPid, "test.exe", null),
            new ProcessInfo(BlockedPid, "blocked.exe", null),
            new ProcessInfo(OtherPid, "other.exe", null),
            new ProcessInfo(DownPid, "down.exe", null));

        relay = new RelayServer(new ConfigurationStore(config), table, processes, tracker, NullLogger<RelayServer>.Instance);
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await relay.DisposeAsync();
        await socks.DisposeAsync();
        await echo.DisposeAsync();
        await banner.DisposeAsync();
    }

    private async Task<Socket> ConnectThroughRelayAsync(IPEndPoint originalDestination, int pid, CancellationToken ct, bool register = true)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        if (register)
        {
            table.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(originalDestination, pid));
        }

        await client.ConnectAsync(relay.LocalEndpoints[0], ct);
        return client;
    }

    /// <summary>
    /// Connects and checks the relay closes or resets the connection. Under load the reset can arrive before the
    /// connect completes, which then fails with a reset as well.
    /// </summary>
    private async Task<bool> IsRejectedByRelayAsync(IPEndPoint originalDestination, int pid, CancellationToken ct, bool register = true, byte[]? send = null)
    {
        try
        {
            using var client = await ConnectThroughRelayAsync(originalDestination, pid, ct, register);
            if (send is not null)
            {
                await client.SendAsync(send, ct);
            }

            return await client.IsClosedByPeerAsync(ct);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            return true;
        }
    }

    [Fact]
    public async Task Unmatched_process_goes_direct()
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectThroughRelayAsync(echo.Endpoint, OtherPid, ct);

        await client.SendAsync("hello"u8.ToArray(), ct);

        Assert.Equal("hello", await client.ReceiveStringAsync(5, ct));
        Assert.Empty(socks.Requests);
    }

    [Fact]
    public async Task Matched_process_goes_through_proxy_with_sniffed_hostname()
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectThroughRelayAsync(Unroutable, TestPid, ct);
        const string request = "GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n";

        await client.SendAsync(System.Text.Encoding.ASCII.GetBytes(request), ct);

        Assert.Equal(request, await client.ReceiveStringAsync(request.Length, ct));
        var proxied = Assert.Single(socks.Requests);
        Assert.Equal(("api.example.test", 80), (proxied.Host, proxied.Port));
    }

    [Fact]
    public async Task Server_first_protocols_work_after_the_sniff_timeout()
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectThroughRelayAsync(new IPEndPoint(IPAddress.Parse("192.0.2.25"), 25), TestPid, ct);

        Assert.Equal("220 ready\r\n", await client.ReceiveStringAsync(11, ct));
        await client.SendAsync("EHLO x\r\n"u8.ToArray(), ct);
        Assert.Equal("EHLO x\r\n", await client.ReceiveStringAsync(8, ct));

        var proxied = Assert.Single(socks.Requests);
        Assert.Equal(IPAddress.Parse("192.0.2.25"), proxied.Address);
    }

    [Fact]
    public async Task Blocked_process_is_reset()
    {
        var ct = TestTimeout.Token();

        Assert.True(await IsRejectedByRelayAsync(echo.Endpoint, BlockedPid, ct));
        Assert.Equal(0, echo.ConnectionCount);
    }

    [Fact]
    public async Task Failing_proxy_fails_closed_and_never_goes_direct()
    {
        var ct = TestTimeout.Token();

        Assert.True(await IsRejectedByRelayAsync(echo.Endpoint, DownPid, ct, send: "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"u8.ToArray()));
        Assert.Equal(0, echo.ConnectionCount);
    }

    [Fact]
    public async Task Unregistered_connections_are_dropped()
    {
        var ct = TestTimeout.Token();

        Assert.True(await IsRejectedByRelayAsync(echo.Endpoint, OtherPid, ct, register: false));
        Assert.Equal(0, echo.ConnectionCount);
    }

    [Fact]
    public async Task Connections_are_tracked_with_byte_counts()
    {
        var ct = TestTimeout.Token();
        var closed = new TaskCompletionSource<TrackedConnection>(TaskCreationOptions.RunContinuationsAsynchronously);
        tracker.Closed += (_, connection) => closed.TrySetResult(connection);

        using (var client = await ConnectThroughRelayAsync(echo.Endpoint, OtherPid, ct))
        {
            await client.SendAsync("12345"u8.ToArray(), ct);
            Assert.Equal("12345", await client.ReceiveStringAsync(5, ct));
            Assert.Single(tracker.GetActive());
            client.Shutdown(SocketShutdown.Send);
            Assert.True(await client.IsClosedByPeerAsync(ct));
        }

        var connection = await closed.Task.WaitAsync(ct);
        Assert.Equal((5, 5), (connection.BytesSent, connection.BytesReceived));
        Assert.Equal(RuleDecision.ImplicitRuleName, connection.Decision.RuleName);
        Assert.Equal("other.exe", connection.Context.Process!.Name);
        Assert.Empty(tracker.GetActive());
    }

    [Theory]
    [InlineData(DnsMode.Sniff, "example.test", "93.184.216.34", "example.test", null)]
    [InlineData(DnsMode.Remote, "example.test", "93.184.216.34", "example.test", null)]
    [InlineData(DnsMode.Local, "example.test", "93.184.216.34", null, "93.184.216.34")]
    [InlineData(DnsMode.Local, "example.test", null, "example.test", null)]
    [InlineData(DnsMode.Sniff, null, "93.184.216.34", null, "93.184.216.34")]
    public void Proxy_target_follows_dns_mode(DnsMode mode, string? host, string? address, string? expectedHost, string? expectedAddressOnly)
    {
        var context = new ConnectionContext(null, TransportProtocol.Tcp, address is null ? null : IPAddress.Parse(address), host, 443);

        var target = RelayServer.BuildProxyTarget(context, mode);

        Assert.Equal(expectedHost, target.Host);
        if (expectedAddressOnly is not null)
        {
            Assert.Equal(IPAddress.Parse(expectedAddressOnly), target.Address);
        }
    }

    private static int UnusedPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }
}
