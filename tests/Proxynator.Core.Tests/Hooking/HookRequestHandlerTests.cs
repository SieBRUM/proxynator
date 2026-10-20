using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.Hooking;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Hooking;

public sealed class HookRequestHandlerTests : IDisposable
{
    private const int ProxiedPid = 10;
    private const int OtherPid = 11;
    private const int ServicePid = 1;

    private static readonly IPEndPoint RelayV4 = IPEndPoint.Parse("127.0.0.1:40000");
    private static readonly IPEndPoint RelayV6 = IPEndPoint.Parse("[::1]:40001");
    private static readonly IPEndPoint Local = IPEndPoint.Parse("127.0.0.1:50000");
    private static readonly IPEndPoint Remote = IPEndPoint.Parse("93.184.215.14:443");

    private readonly OriginalDestinationTable destinations = new();
    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private readonly StaticProcessInfoProvider processes = new(new ProcessInfo(ProxiedPid, "nxc.exe", null), new ProcessInfo(OtherPid, "other.exe", null));
    private HookRequestHandler handler = null!;

    public void Dispose() => handler?.Dispose();

    private HookRequestHandler Create(DnsMode dnsMode = DnsMode.Sniff, UdpFallback udp = UdpFallback.Block, bool ipv6Relay = true, string proxyHost = "10.9.9.9")
    {
        var config = Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = dnsMode, RemoteDomains = ["*.corp.local"] } },
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, 1080, proxyHost)],
            Rules =
            [
                new RuleDefinition
                {
                    Name = "nxc",
                    Match = new RuleMatch { Processes = ["nxc.exe"] },
                    Action = new RuleActionDefinition { Type = RuleActionType.Proxy, Target = "socks", Udp = udp },
                },
            ],
        };
        var context = new CaptureContext(new ConfigurationStore(config), destinations, ipv6Relay ? [RelayV4, RelayV6] : [RelayV4], ServicePid)
        {
            FakeIps = fakeIps,
        };
        handler = new HookRequestHandler(context, processes, NullLogger.Instance);
        return handler;
    }

    private static HookConnectRequest Tcp(IPEndPoint remote, IPEndPoint? local = null, string? hostname = null) =>
        new(TransportProtocol.Tcp, local ?? Local, remote, hostname);

    private static HookConnectRequest Udp(string remote) => new(TransportProtocol.Udp, IPEndPoint.Parse("0.0.0.0:0"), IPEndPoint.Parse(remote), null);

    [Fact]
    public async Task Proxied_connections_are_registered_and_sent_to_the_relay()
    {
        var handler = Create();
        await handler.InitializeAsync(TestTimeout.Token());

        var response = handler.Handle(ProxiedPid, Tcp(Remote, hostname: "example.com"));

        Assert.Equal(new HookConnectResponse(HookVerdict.Relay, RelayV4), response);
        Assert.True(destinations.TryTake(Local, out var original));
        Assert.Equal(new OriginalDestination(Remote, ProxiedPid, "example.com", HostnameIsHint: true), original);
    }

    [Fact]
    public void Ipv6_sockets_get_the_ipv6_relay()
    {
        var handler = Create();
        var local = IPEndPoint.Parse("[::1]:50002");

        var response = handler.Handle(ProxiedPid, Tcp(IPEndPoint.Parse("[2001:db8::1]:443"), local));

        Assert.Equal(new HookConnectResponse(HookVerdict.Relay, RelayV6), response);
        Assert.True(destinations.TryTake(local, out _));
    }

    [Fact]
    public void Without_a_relay_for_the_family_the_connection_is_refused()
    {
        var handler = Create(ipv6Relay: false);

        var response = handler.Handle(ProxiedPid, Tcp(IPEndPoint.Parse("[2001:db8::1]:443"), IPEndPoint.Parse("[::1]:50002")));

        Assert.Equal(HookConnectResponse.Block, response);
    }

    [Fact]
    public void Unmatched_processes_go_direct_without_registration()
    {
        var handler = Create();

        Assert.Equal(HookConnectResponse.Direct, handler.Handle(OtherPid, Tcp(Remote)));
        Assert.Equal(0, destinations.Count);
    }

    [Theory]
    [InlineData("127.0.0.1:8080")]
    [InlineData("[::1]:8080")]
    [InlineData("0.0.0.0:80")]
    public void Loopback_and_unspecified_destinations_go_direct(string remote)
    {
        var handler = Create();

        Assert.Equal(HookConnectResponse.Direct, handler.Handle(ProxiedPid, Tcp(IPEndPoint.Parse(remote))));
    }

    [Fact]
    public async Task Connections_to_the_proxy_itself_go_direct()
    {
        var handler = Create();
        await handler.InitializeAsync(TestTimeout.Token());

        Assert.Equal(HookConnectResponse.Direct, handler.Handle(ProxiedPid, Tcp(IPEndPoint.Parse("10.9.9.9:1080"))));
        Assert.Equal(HookVerdict.Relay, ((HookConnectResponse)handler.Handle(ProxiedPid, Tcp(IPEndPoint.Parse("10.9.9.9:1081")))).Verdict);
    }

    [Fact]
    public void Requests_from_the_service_itself_go_direct()
    {
        var handler = Create();

        Assert.Equal(HookConnectResponse.Direct, handler.Handle(ServicePid, Tcp(Remote)));
    }

    [Fact]
    public void Fake_addresses_always_go_to_the_relay_with_their_exact_hostname()
    {
        var handler = Create(DnsMode.Remote);
        var fake = fakeIps.GetOrAllocate("dc01.corp.local");

        var response = handler.Handle(OtherPid, Tcp(new IPEndPoint(fake, 445), hostname: "wrong.example"));

        Assert.Equal(HookVerdict.Relay, ((HookConnectResponse)response).Verdict);
        Assert.True(destinations.TryTake(Local, out var original));
        Assert.Equal(("dc01.corp.local", false), (original.Hostname, original.HostnameIsHint));
    }

    [Fact]
    public void Remote_dns_fakes_only_the_configured_domains()
    {
        var handler = Create(DnsMode.Remote);

        var faked = (HookResolveResponse)handler.Handle(ProxiedPid, new HookResolveRequest("dc01.corp.local."));
        var real = (HookResolveResponse)handler.Handle(ProxiedPid, new HookResolveRequest("example.com"));

        Assert.NotNull(faked.FakeAddress);
        Assert.True(fakeIps.TryGetHostname(faked.FakeAddress, out var hostname));
        Assert.Equal("dc01.corp.local", hostname);
        Assert.Null(real.FakeAddress);
    }

    [Fact]
    public void Names_are_resolved_normally_outside_remote_dns_mode()
    {
        var handler = Create(DnsMode.Sniff);

        Assert.Equal(HookResolveResponse.ResolveNormally, handler.Handle(ProxiedPid, new HookResolveRequest("dc01.corp.local")));
    }

    [Theory]
    [InlineData(UdpFallback.Block, "8.8.8.8:53", HookVerdict.Block)]
    [InlineData(UdpFallback.Direct, "8.8.8.8:53", HookVerdict.Direct)]
    [InlineData(UdpFallback.Direct, "142.250.0.1:443", HookVerdict.Block)] // QUIC is blocked for proxied processes
    public void Udp_from_proxied_processes_follows_the_fallback(UdpFallback fallback, string remote, HookVerdict expected)
    {
        var handler = Create(udp: fallback);

        Assert.Equal(expected, ((HookConnectResponse)handler.Handle(ProxiedPid, Udp(remote))).Verdict);
        Assert.Equal(0, destinations.Count);
    }

    [Fact]
    public void Udp_from_other_processes_goes_direct()
    {
        var handler = Create();

        Assert.Equal(HookConnectResponse.Direct, handler.Handle(OtherPid, Udp("142.250.0.1:443")));
    }

    [Fact]
    public void Udp_to_fake_addresses_is_blocked()
    {
        var handler = Create(DnsMode.Remote, udp: UdpFallback.Direct);
        var fake = fakeIps.GetOrAllocate("dc01.corp.local");

        Assert.Equal(HookConnectResponse.Block, handler.Handle(OtherPid, new HookConnectRequest(TransportProtocol.Udp, IPEndPoint.Parse("0.0.0.0:0"), new IPEndPoint(fake, 88), null)));
    }

    [Fact]
    public void Hello_returns_the_service_pid()
    {
        var handler = Create();

        Assert.Equal(new HookHelloResponse(ServicePid), handler.Handle(ProxiedPid, new HookHelloRequest(64)));
    }
}
