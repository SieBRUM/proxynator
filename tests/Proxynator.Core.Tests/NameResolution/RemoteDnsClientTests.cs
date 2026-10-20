using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.NameResolution;

/// <summary>Domain controller lookups (SRV) of remote domains go to the DNS server behind the proxy.</summary>
public sealed class RemoteDnsClientTests : IAsyncLifetime
{
    private const ushort TypeSrv = 33;
    private const ushort TypeTxt = 16;

    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private readonly FakeTcpDnsServer domainController = new();
    private readonly FakeDnsServer localDns = new();
    private FakeProxyServer socks = null!;
    private DnsForwarder forwarder = null!;

    public ValueTask InitializeAsync()
    {
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = _ => domainController.Endpoint };
        forwarder = new DnsForwarder(new ConfigurationStore(Config()), fakeIps, [localDns.Endpoint], NullLogger.Instance);
        forwarder.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await forwarder.DisposeAsync();
        await socks.DisposeAsync();
        await localDns.DisposeAsync();
        await domainController.DisposeAsync();
    }

    private ProxynatorConfig Config(DnsMode mode = DnsMode.Remote, bool remoteServer = true) => Configs.Minimal() with
    {
        Settings = new ProxynatorSettings
        {
            Dns = new DnsSettings
            {
                Mode = mode,
                RemoteDomains = ["corp.local", "*.corp.local"],
                RemoteServer = remoteServer ? new RemoteDnsServer { Address = "10.0.0.10", Via = "pivot" } : null,
            },
        },
        Proxies = [Configs.Proxy("pivot", ProxyType.Socks5, socks?.Endpoint.Port ?? 1080)],
    };

    private async Task<byte[]> AskAsync(string name, ushort type, CancellationToken ct)
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await client.ConnectAsync(forwarder.LocalEndpoints[0], ct);
        await client.SendAsync(DnsWire.BuildQuery(77, name, type), ct);
        var buffer = new byte[1024];
        var length = await client.ReceiveAsync(buffer, ct);
        return buffer[..length];
    }

    [Fact]
    public async Task Srv_lookups_of_remote_domains_are_answered_by_the_server_behind_the_proxy()
    {
        var response = await AskAsync("_ldap._tcp.dc._msdcs.corp.local", TypeSrv, TestTimeout.Token());

        Assert.Equal(77, (response[0] << 8) | response[1]);
        Assert.Equal(1, (response[6] << 8) | response[7]); // one answer: the SRV record
        Assert.Equal(["_ldap._tcp.dc._msdcs.corp.local"], domainController.Queries);
        var request = Assert.Single(socks.Requests);
        Assert.Equal((IPAddress.Parse("10.0.0.10"), 53), (request.Address, request.Port));
        Assert.Empty(localDns.Queries);
    }

    [Fact]
    public async Task Address_lookups_still_get_fake_answers()
    {
        var addresses = FakeDnsServer.AddressesIn(await AskAsync("dc01.corp.local", DnsWire.TypeA, TestTimeout.Token()));

        Assert.True(fakeIps.Contains(Assert.Single(addresses)));
        Assert.Empty(socks.Requests);
    }

    [Fact]
    public void Only_non_address_lookups_of_remote_domains_in_remote_mode_are_handled()
    {
        var active = ActiveConfiguration.Create(Config());

        Assert.True(RemoteDnsClient.Handles(active, DnsWire.BuildQuery(1, "_kerberos._tcp.corp.local", TypeSrv)));
        Assert.True(RemoteDnsClient.Handles(active, DnsWire.BuildQuery(1, "corp.local", TypeTxt)));
        Assert.False(RemoteDnsClient.Handles(active, DnsWire.BuildQuery(1, "dc01.corp.local", DnsWire.TypeA)));
        Assert.False(RemoteDnsClient.Handles(active, DnsWire.BuildQuery(1, "_ldap._tcp.example.com", TypeSrv)));
        Assert.False(RemoteDnsClient.Handles(ActiveConfiguration.Create(Config(DnsMode.Sniff)), DnsWire.BuildQuery(1, "_ldap._tcp.corp.local", TypeSrv)));
        Assert.False(RemoteDnsClient.Handles(ActiveConfiguration.Create(Config(remoteServer: false)), DnsWire.BuildQuery(1, "_ldap._tcp.corp.local", TypeSrv)));
    }

    [Fact]
    public async Task An_unreachable_server_gives_servfail()
    {
        await socks.DisposeAsync(); // the pivot is down (the configured port no longer listens)
        socks = new FakeProxyServer(FakeProxyKind.Socks5); // for DisposeAsync

        var response = await AskAsync("_ldap._tcp.corp.local", TypeSrv, TestTimeout.Token());

        Assert.Equal(2, response[3] & 0x0F); // SERVFAIL, never a silent fallback to the local DNS
        Assert.Empty(localDns.Queries);
    }
}
