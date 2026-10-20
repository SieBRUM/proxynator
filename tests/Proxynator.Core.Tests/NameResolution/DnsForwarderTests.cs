using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.NameResolution;

public sealed class DnsForwarderTests : IAsyncLifetime
{
    private readonly FakeIpPool fakeIps = new(AddressRange.TryParse("198.18.0.0/15", out var range) ? range : null!);
    private readonly FakeDnsServer upstream = new(new Dictionary<string, IPAddress> { ["example.com"] = IPAddress.Parse("93.184.215.14") });
    private DnsForwarder forwarder = null!;

    public ValueTask InitializeAsync()
    {
        var config = Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = DnsMode.Remote, RemoteDomains = ["*.corp.local"] } },
        };
        forwarder = new DnsForwarder(new ConfigurationStore(config), fakeIps, [upstream.Endpoint], NullLogger.Instance);
        forwarder.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await forwarder.DisposeAsync();
        await upstream.DisposeAsync();
    }

    private async Task<byte[]> AskAsync(string name, CancellationToken ct)
    {
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        await client.ConnectAsync(forwarder.LocalEndpoints[0], ct);
        await client.SendAsync(DnsWire.BuildQuery(42, name, DnsWire.TypeA), ct);
        var buffer = new byte[512];
        var length = await client.ReceiveAsync(buffer, ct);
        return buffer[..length];
    }

    [Fact]
    public async Task Remote_domains_get_fake_answers_without_asking_upstream()
    {
        var addresses = FakeDnsServer.AddressesIn(await AskAsync("dc01.corp.local", TestTimeout.Token()));

        var address = Assert.Single(addresses);
        Assert.True(fakeIps.TryGetHostname(address, out var hostname));
        Assert.Equal("dc01.corp.local", hostname);
        Assert.Empty(upstream.Queries);
    }

    [Fact]
    public async Task Other_names_are_forwarded()
    {
        var addresses = FakeDnsServer.AddressesIn(await AskAsync("example.com", TestTimeout.Token()));

        Assert.Equal([IPAddress.Parse("93.184.215.14")], addresses);
        Assert.Contains("example.com", upstream.Queries);
    }
}
