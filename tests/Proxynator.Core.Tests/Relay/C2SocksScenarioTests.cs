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

/// <summary>
/// The DNS problems people hit with C2 and pivot SOCKS servers, reproduced with the real relay and fake proxies. The
/// target network is corp.local: its names (dc01.corp.local) only resolve on the far side, its DNS server is
/// 10.0.0.10 and dc01 is 10.0.0.5. Remote DNS is on for *corp.local, as in the README's pivot example.
/// </summary>
public sealed class C2SocksScenarioTests : IAsyncLifetime
{
    private const int ToolPid = 1;
    private static readonly IPAddress DomainDns = IPAddress.Parse("10.0.0.10");
    private static readonly IPAddress Dc01 = IPAddress.Parse("10.0.0.5");

    private readonly EchoServer service = new();
    private readonly UdpEchoServer udpService = new();
    private readonly FakeTcpDnsServer domainDns = new(addresses: new Dictionary<string, IPAddress> { ["dc01.corp.local"] = Dc01 });
    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private readonly OriginalDestinationTable table = new();
    private readonly StaticProcessInfoProvider processes = new(new ProcessInfo(ToolPid, "nxc", null));
    private readonly RecordingLogger<RelayServer> relayLog = new();
    private readonly List<IAsyncDisposable> owned = [];

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public async ValueTask DisposeAsync()
    {
        foreach (var item in Enumerable.Reverse(owned))
        {
            await item.DisposeAsync();
        }

        await domainDns.DisposeAsync();
        await udpService.DisposeAsync();
        await service.DisposeAsync();
    }

    /// <summary>
    /// <c>ssh -D</c>, chisel and most C2 SOCKS servers implement SOCKS5 without UDP, so DNS packets cannot be
    /// tunnelled. They don't need to be: the name goes to the proxy inside the connect request.
    /// </summary>
    [Fact]
    public async Task Internal_names_reach_a_socks5_server_without_udp_support_as_names()
    {
        var socks = Proxy(FakeProxyKind.Socks5, supportsUdp: false);
        var relay = StartRelay(Config(ProxyType.Socks5, socks));

        await AssertEchoesAsync(relay, "dc01.corp.local", 445);

        var request = Assert.Single(socks.Requests);
        Assert.Equal(("dc01.corp.local", 445, (IPAddress?)null), (request.Host, request.Port, request.Address));
        Assert.Equal(0, socks.UdpAssociateRequests);
    }

    /// <summary>
    /// The program's own lookups never cross the tunnel: A lookups of internal names get a local placeholder answer,
    /// and SRV lookups (domain controller discovery) go to the domain's DNS server as DNS over TCP, so a SOCKS server
    /// without UDP is fine.
    /// </summary>
    [Fact]
    public async Task Dns_lookups_work_through_a_socks_server_without_udp_support()
    {
        var socks = Proxy(FakeProxyKind.Socks5, supportsUdp: false);
        var config = Config(ProxyType.Socks5, socks, remoteServer: new RemoteDnsServer { Address = DomainDns.ToString(), Via = "pivot" });
        var udpRelay = StartUdpRelay(config);
        using var client = UdpClient(udpRelay, new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53));

        var a = await ExchangeAsync(client, udpRelay, DnsWire.BuildQuery(1, "dc01.corp.local", DnsWire.TypeA));
        var fake = Assert.Single(FakeDnsServer.AddressesIn(a!));
        Assert.True(fakeIps.TryGetHostname(fake, out var name));
        Assert.Equal("dc01.corp.local", name);
        Assert.Empty(socks.Requests);

        var srv = await ExchangeAsync(client, udpRelay, DnsWire.BuildQuery(2, "_ldap._tcp.dc._msdcs.corp.local", 33));
        Assert.NotNull(srv);
        Assert.Equal(1, srv[7]); // one answer, from the domain's DNS server
        Assert.Equal(["_ldap._tcp.dc._msdcs.corp.local"], domainDns.Queries);
        var request = Assert.Single(socks.Requests);
        Assert.Equal((DomainDns, 53, false), (request.Address, request.Port, request.Udp));
        Assert.Equal(0, socks.UdpAssociateRequests);
    }

    /// <summary>SOCKS4a listeners (common in C2 frameworks) take names too.</summary>
    [Fact]
    public async Task Socks4a_listeners_receive_the_name()
    {
        var socks = Proxy(FakeProxyKind.Socks4);
        var relay = StartRelay(Config(ProxyType.Socks4a, socks));

        await AssertEchoesAsync(relay, "dc01.corp.local", 445);

        var request = Assert.Single(socks.Requests);
        Assert.Equal(("dc01.corp.local", 445), (request.Host, request.Port));
    }

    /// <summary>
    /// Plain SOCKS4 can only carry addresses. Resolving the name locally would fail (only the far side knows it) or
    /// produce the placeholder address, so the connection is refused instead, and the proxy never sees a fake address.
    /// </summary>
    [Fact]
    public async Task Plain_socks4_refuses_internal_names_instead_of_sending_a_placeholder_address()
    {
        var socks = Proxy(FakeProxyKind.Socks4);
        var relay = StartRelay(Config(ProxyType.Socks4, socks));

        await AssertRefusedAsync(relay, "dc01.corp.local", 445);

        Assert.Empty(socks.Requests);
        Assert.Contains(relayLog.Messages, m => m.Contains("SOCKS4 cannot send the name dc01.corp.local", StringComparison.Ordinal));
    }

    /// <summary>A SOCKS server on a pivot that doesn't use the domain's DNS cannot resolve dc01: fail closed.</summary>
    [Fact]
    public async Task A_pivot_that_cannot_resolve_internal_names_fails_closed()
    {
        var socks = Proxy(FakeProxyKind.Socks5, cannotResolveNames: true);
        var relay = StartRelay(Config(ProxyType.Socks5, socks));

        await AssertRefusedAsync(relay, "dc01.corp.local", 445);

        Assert.Equal("dc01.corp.local", Assert.Single(socks.Requests).Host);
        Assert.Equal(0, service.ConnectionCount);
        Assert.Contains(relayLog.Messages, m => m.Contains("dc01.corp.local", StringComparison.Ordinal) && m.Contains("'pivot'", StringComparison.Ordinal));
    }

    /// <summary>
    /// The fix for such pivots (and for plain SOCKS4): <c>remoteServer.resolveNames</c> asks the domain's DNS
    /// server through the tunnel and gives the proxy the address. The answer is cached, so the second connection does
    /// not ask again.
    /// </summary>
    [Theory]
    [InlineData(FakeProxyKind.Socks5, ProxyType.Socks5)]
    [InlineData(FakeProxyKind.Socks4, ProxyType.Socks4)]
    [InlineData(FakeProxyKind.Http, ProxyType.Http)]
    public async Task Resolve_names_asks_the_domain_dns_through_the_tunnel_and_sends_the_proxy_the_address(FakeProxyKind kind, ProxyType type)
    {
        var socks = Proxy(kind, cannotResolveNames: true);
        var config = Config(type, socks, remoteServer: new RemoteDnsServer { Address = DomainDns.ToString(), Via = "pivot", ResolveNames = true });
        var relay = StartRelay(config);

        await AssertEchoesAsync(relay, "dc01.corp.local", 445);
        await AssertEchoesAsync(relay, "dc01.corp.local", 445);

        Assert.Equal(["dc01.corp.local"], domainDns.Queries);
        var requests = socks.Requests.ToArray();
        Assert.Equal((DomainDns, 53), (requests[0].Address, requests[0].Port)); // the lookup (DNS over TCP)
        Assert.All(requests[1..], request => Assert.Equal((Dc01, 445, (string?)null), (request.Address, request.Port, request.Host)));
        Assert.Equal(3, requests.Length);
    }

    [Fact]
    public async Task Resolve_names_fails_closed_when_the_domain_dns_does_not_know_the_name()
    {
        var socks = Proxy(FakeProxyKind.Socks5);
        var config = Config(ProxyType.Socks5, socks, remoteServer: new RemoteDnsServer { Address = DomainDns.ToString(), Via = "pivot", ResolveNames = true });
        var relay = StartRelay(config);

        await AssertRefusedAsync(relay, "nosuchhost.corp.local", 445);

        Assert.Equal(["nosuchhost.corp.local"], domainDns.Queries);
        Assert.DoesNotContain(socks.Requests, r => r.Port == 445);
        Assert.Equal(0, service.ConnectionCount);
        Assert.Contains(relayLog.Messages, m => m.Contains("has no address for nosuchhost.corp.local", StringComparison.Ordinal));
    }

    /// <summary>
    /// UDP to an internal host (Kerberos on 88, SNMP, ...) through a SOCKS server without UDP is dropped, never sent
    /// direct around the tunnel (the rule's "udp": "block" default).
    /// </summary>
    [Fact]
    public async Task Proxied_udp_through_a_socks_server_without_udp_support_is_dropped_not_sent_direct()
    {
        var socks = Proxy(FakeProxyKind.Socks5, supportsUdp: false);
        var udpRelay = StartUdpRelay(Config(ProxyType.Socks5, socks));
        using var client = UdpClient(udpRelay, new IPEndPoint(fakeIps.GetOrAllocate("dc01.corp.local"), 88));

        var reply = await ExchangeAsync(client, udpRelay, "kerberos"u8.ToArray(), timeoutMs: 1000);

        Assert.Null(reply);
        Assert.Equal(1, socks.UdpAssociateRequests);
        Assert.Equal(0, udpService.DatagramCount);
    }

    private FakeProxyServer Proxy(FakeProxyKind kind, bool supportsUdp = true, bool cannotResolveNames = false)
    {
        var proxy = new FakeProxyServer(kind)
        {
            SupportsUdp = supportsUdp,
            CannotResolveNames = cannotResolveNames,

            // The far side: the domain's DNS server, dc01 (TCP and UDP services) and names it can resolve.
            Resolve = request => request.Port == 53 && Equals(request.Address, DomainDns) ? domainDns.Endpoint
                : request.Udp ? udpService.Endpoint
                : service.Endpoint,
        };
        owned.Add(proxy);
        return proxy;
    }

    private static ProxynatorConfig Config(ProxyType type, FakeProxyServer proxy, RemoteDnsServer? remoteServer = null) => Configs.Minimal() with
    {
        Settings = new ProxynatorSettings
        {
            Dns = new DnsSettings { Mode = DnsMode.Remote, RemoteDomains = ["*corp.local"], RemoteServer = remoteServer },
        },
        Proxies = [Configs.Proxy("pivot", type, proxy.Endpoint.Port)],
        Rules = [Configs.Rule("corp.local via the pivot", RuleActionType.Proxy, "pivot", new RuleMatch { Hosts = ["*corp.local"] })],
    };

    private RelayServer StartRelay(ProxynatorConfig config)
    {
        var relay = new RelayServer(new ConfigurationStore(config), table, processes, new ConnectionTracker(), relayLog, fakeIps: fakeIps);
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        owned.Add(relay);
        return relay;
    }

    private UdpRelayServer StartUdpRelay(ProxynatorConfig config)
    {
        var relay = new UdpRelayServer(new ConfigurationStore(config), table, processes, new ConnectionTracker(), NullLogger<UdpRelayServer>.Instance, fakeIps);
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        owned.Add(relay);
        return relay;
    }

    private async Task<Socket> ConnectAsync(RelayServer relay, string name, int port, CancellationToken cancellationToken)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        table.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(new IPEndPoint(fakeIps.GetOrAllocate(name), port), ToolPid));
        await client.ConnectAsync(relay.LocalEndpoints[0], cancellationToken);
        return client;
    }

    private async Task AssertEchoesAsync(RelayServer relay, string name, int port)
    {
        var ct = TestTimeout.Token();
        using var client = await ConnectAsync(relay, name, port, ct);
        await client.SendAsync("ping"u8.ToArray(), ct);
        Assert.Equal("ping", await client.ReceiveStringAsync(4, ct));
    }

    private async Task AssertRefusedAsync(RelayServer relay, string name, int port)
    {
        var ct = TestTimeout.Token();
        try
        {
            using var client = await ConnectAsync(relay, name, port, ct);
            Assert.True(await client.IsClosedByPeerAsync(ct));
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // The reset arrived before the connect completed (see CLAUDE.md gotchas).
        }
    }

    private Socket UdpClient(UdpRelayServer relay, IPEndPoint originalDestination)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        table.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(originalDestination, ToolPid));
        return client;
    }

    private static async Task<byte[]?> ExchangeAsync(Socket client, UdpRelayServer relay, byte[] datagram, int timeoutMs = 5000)
    {
        await client.SendToAsync(datagram, SocketFlags.None, relay.LocalEndpoints[0]);
        using var timeout = new CancellationTokenSource(timeoutMs);
        try
        {
            var buffer = new byte[65535];
            var result = await client.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
            return buffer.AsSpan(0, result.ReceivedBytes).ToArray();
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }
}
