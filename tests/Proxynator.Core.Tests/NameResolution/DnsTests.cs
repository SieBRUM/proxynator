using System.Net;
using System.Net.Sockets;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.NameResolution;

public class DnsTests
{
    private static FakeIpPool Pool(string range = "198.18.0.0/15") => new(AddressRange.TryParse(range, out var r) ? r : throw new ArgumentException(range));

    [Fact]
    public void Query_round_trips_through_the_parser()
    {
        var query = DnsWire.BuildQuery(0x1234, "Api.Example.COM", DnsWire.TypeA);

        Assert.True(DnsWire.TryParseQuery(query, out var question));
        Assert.Equal((0x1234, "api.example.com", DnsWire.TypeA, DnsWire.ClassIn, true), (question.Id, question.Name, question.Type, question.Class, question.RecursionDesired));
        Assert.Equal(query.Length, question.End);
    }

    [Fact]
    public void Response_carries_the_answer()
    {
        var query = DnsWire.BuildQuery(7, "example.com", DnsWire.TypeA);
        Assert.True(DnsWire.TryParseQuery(query, out var question));

        var response = DnsWire.BuildResponse(query, question, IPAddress.Parse("198.18.0.5"), 10);

        Assert.True(DnsWire.TryParseAddresses(response, 7, out var addresses, out var rcode));
        Assert.Equal(0, rcode);
        Assert.Equal([IPAddress.Parse("198.18.0.5")], addresses);
        Assert.False(DnsWire.TryParseQuery(response, out _)); // a response is not a query
    }

    [Fact]
    public void Compressed_names_are_followed_and_loops_rejected()
    {
        byte[] message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, (byte)'a', (byte)'b', (byte)'c', 0, 0xC0, 12];
        var offset = 17;
        Assert.True(DnsWire.TryReadName(message, ref offset, out var name));
        Assert.Equal(("abc", 19), (name, offset));

        byte[] loop = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC0, 12];
        var loopOffset = 12;
        Assert.False(DnsWire.TryReadName(loop, ref loopOffset, out _));
    }

    [Theory]
    [InlineData(new byte[] { 1, 2, 3 })]
    [InlineData(new byte[] { 0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 })] // a response
    [InlineData(new byte[] { 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, (byte)'a' })] // truncated name
    public void Malformed_queries_are_rejected(byte[] message) => Assert.False(DnsWire.TryParseQuery(message, out _));

    [Fact]
    public void Pool_gives_each_name_a_stable_address_and_maps_it_back()
    {
        var pool = Pool();

        var a = pool.GetOrAllocate("a.example");
        var b = pool.GetOrAllocate("B.example");

        Assert.NotEqual(a, b);
        Assert.Equal(a, pool.GetOrAllocate("A.EXAMPLE"));
        Assert.True(pool.Contains(a));
        Assert.Equal(IPAddress.Parse("198.18.0.1"), a);
        Assert.True(pool.TryGetHostname(b, out var name));
        Assert.Equal("b.example", name);
        Assert.False(pool.TryGetHostname(IPAddress.Parse("198.18.9.9"), out _));
        Assert.False(pool.TryGetHostname(IPAddress.Parse("10.0.0.1"), out _));
    }

    [Fact]
    public void Pool_reuses_the_oldest_address_when_full()
    {
        var pool = Pool("10.9.9.0/30"); // two usable addresses

        var first = pool.GetOrAllocate("one.test");
        pool.GetOrAllocate("two.test");
        var third = pool.GetOrAllocate("three.test");

        Assert.Equal(first, third);
        Assert.False(pool.TryGetHostname(first, out var name) && name == "one.test");
        Assert.Equal(2, pool.Count);
    }

    [Fact]
    public void Pool_rejects_ipv6_and_tiny_ranges()
    {
        Assert.Throws<ArgumentException>(() => Pool("fd00::/64"));
        Assert.Throws<ArgumentException>(() => Pool("10.0.0.0/31"));
    }

    [Fact]
    public void Responder_fakes_a_records_and_hides_aaaa_and_https()
    {
        var responder = new FakeDnsResponder(Pool());

        var a = responder.TryAnswer(DnsWire.BuildQuery(1, "dc01.corp.local", DnsWire.TypeA), _ => true);
        var aaaa = responder.TryAnswer(DnsWire.BuildQuery(2, "dc01.corp.local", DnsWire.TypeAaaa), _ => true);
        var https = responder.TryAnswer(DnsWire.BuildQuery(3, "dc01.corp.local", DnsWire.TypeHttps), _ => true);
        var mx = responder.TryAnswer(DnsWire.BuildQuery(4, "dc01.corp.local", 15), _ => true);
        var excluded = responder.TryAnswer(DnsWire.BuildQuery(5, "real.example", DnsWire.TypeA), _ => false);

        Assert.True(responder.Pool.TryGetHostname(Assert.Single(FakeDnsServer.AddressesIn(a!)), out var name));
        Assert.Equal("dc01.corp.local", name);
        Assert.Empty(FakeDnsServer.AddressesIn(aaaa!));
        Assert.Empty(FakeDnsServer.AddressesIn(https!));
        Assert.Null(mx);
        Assert.Null(excluded);
    }

    [Theory]
    [InlineData("dc01.corp.local", true)]
    [InlineData("CORP.LOCAL", false)]
    [InlineData("example.com", false)]
    [InlineData("proxy.corp.local", false)]
    [InlineData("wpad", false)]
    [InlineData("1.0.0.10.in-addr.arpa", false)]
    public void Only_configured_domains_are_faked(string name, bool expected)
    {
        var active = ActiveConfiguration.Create(Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = DnsMode.Remote, RemoteDomains = ["*.corp.local"] } },
            Proxies = [Configs.Proxy("pivot", ProxyType.Socks5, 1080, host: "proxy.corp.local")],
        });

        Assert.Equal(expected, active.ShouldFakeResolve(name));
    }

    /// <summary>
    /// "Only corp.local through the proxy": a leading * without a dot also covers the domain itself; everything else
    /// resolves normally.
    /// </summary>
    [Theory]
    [InlineData("dc01.corp.local", true)]
    [InlineData("corp.local", true)]
    [InlineData("dc01.corp.local.", true)]
    [InlineData("google.com", false)]
    [InlineData("www.google.com", false)]
    [InlineData("corp.local.example.com", false)]
    public void A_leading_wildcard_fakes_a_domain_and_its_subdomains(string name, bool expected)
    {
        var active = ActiveConfiguration.Create(Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = DnsMode.Remote, RemoteDomains = ["*corp.local"] } },
        });

        Assert.Equal(expected, active.ShouldFakeResolve(name));
    }

    [Fact]
    public void Default_remote_domains_fake_everything_except_special_names()
    {
        var active = ActiveConfiguration.Create(Configs.Minimal());

        Assert.True(active.ShouldFakeResolve("anything.example"));
        Assert.False(active.ShouldFakeResolve("localhost"));
        Assert.False(active.ShouldFakeResolve("app.localhost"));
    }

    [Fact]
    public async Task Upstream_resolver_queries_the_servers_in_order()
    {
        var ct = TestTimeout.Token();
        await using var silent = new FakeDnsServer(silent: true);
        await using var working = new FakeDnsServer(new Dictionary<string, IPAddress> { ["target.test"] = IPAddress.Parse("192.0.2.7") });
        var resolver = new UpstreamDnsResolver([silent.Endpoint, working.Endpoint], TimeSpan.FromMilliseconds(300));

        var addresses = await resolver.ResolveAsync("target.test", ct);

        Assert.Equal([IPAddress.Parse("192.0.2.7")], addresses);
        Assert.Contains("target.test", silent.Queries);
        Assert.Equal([IPAddress.Loopback], await resolver.ResolveAsync("127.0.0.1", ct));
    }

    [Fact]
    public async Task Upstream_resolver_reports_unknown_names()
    {
        await using var server = new FakeDnsServer();
        var resolver = new UpstreamDnsResolver([server.Endpoint]);

        var ex = await Assert.ThrowsAsync<SocketException>(async () => await resolver.ResolveAsync("missing.test", TestTimeout.Token()));

        Assert.Equal(SocketError.HostNotFound, ex.SocketErrorCode);
    }
}
