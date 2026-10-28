using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Proxies;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.NameResolution;

/// <summary>
/// settings.dns.cacheSeconds: how long Proxynator reuses the answers it resolved itself (0 = off, -1 = until cleared),
/// and clearing the cache.
/// </summary>
public sealed class DnsCacheTests : IAsyncLifetime
{
    private const ushort TypeSrv = 33;
    private static readonly IPAddress Dc01 = IPAddress.Parse("10.0.0.21");

    private readonly ManualTimeProvider clock = new();
    private readonly FakeTcpDnsServer domainController = new(addresses: new Dictionary<string, IPAddress> { ["dc01.corp.local"] = Dc01 });
    private readonly FakeDnsServer upstreamDns = new(new Dictionary<string, IPAddress> { ["api.example.com"] = IPAddress.Parse("192.0.2.80") });
    private FakeProxyServer socks = null!;

    public ValueTask InitializeAsync()
    {
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = _ => domainController.Endpoint };
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await socks.DisposeAsync();
        await upstreamDns.DisposeAsync();
        await domainController.DisposeAsync();
    }

    public static TheoryData<int, TimeSpan?> Lifetimes => new()
    {
        { 60, TimeSpan.FromSeconds(60) },
        { 1, TimeSpan.FromSeconds(1) },
        { 0, TimeSpan.Zero },
        { DnsSettings.CacheUntilCleared, null },
    };

    [Theory]
    [MemberData(nameof(Lifetimes))]
    public void Cache_seconds_become_a_lifetime(int seconds, TimeSpan? lifetime) =>
        Assert.Equal(lifetime, DnsCache.Lifetime(new DnsSettings { CacheSeconds = seconds }));

    [Fact]
    public void The_default_is_one_minute() => Assert.Equal(60, new DnsSettings().CacheSeconds);

    [Fact]
    public void Answers_expire_after_their_lifetime()
    {
        var cache = new DnsCache(clock);
        var lifetime = TimeSpan.FromSeconds(30);
        cache.Set("a", "answer", lifetime);

        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.True(cache.TryGet<string>("a", lifetime, out var value));
        Assert.Equal("answer", value);

        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.False(cache.TryGet<string>("a", lifetime, out _));
        Assert.Equal(0, cache.Count); // expired entries are dropped when found
    }

    [Fact]
    public void Answers_kept_until_cleared_never_expire()
    {
        var cache = new DnsCache(clock);
        cache.Set("a", "answer", null);

        clock.Advance(TimeSpan.FromDays(365));

        Assert.True(cache.TryGet<string>("a", null, out _));
        Assert.Equal(1, cache.Clear());
        Assert.False(cache.TryGet<string>("a", null, out _));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void Nothing_is_stored_or_returned_while_caching_is_off()
    {
        var cache = new DnsCache(clock);
        cache.Set("a", "answer", TimeSpan.Zero);
        Assert.Equal(0, cache.Count);

        cache.Set("a", "answer", null);
        Assert.False(cache.TryGet<string>("a", TimeSpan.Zero, out _)); // turned off after it was stored
    }

    [Fact]
    public void A_new_lifetime_applies_to_answers_already_cached()
    {
        var cache = new DnsCache(clock);
        cache.Set("a", "answer", null); // stored while kept until cleared
        clock.Advance(TimeSpan.FromMinutes(5));

        Assert.False(cache.TryGet<string>("a", TimeSpan.FromSeconds(60), out _)); // then cacheSeconds became 60
    }

    [Theory]
    [InlineData(60, 1)]
    [InlineData(DnsSettings.CacheUntilCleared, 1)]
    [InlineData(0, 3)]
    public async Task Remote_server_lookups_are_cached(int cacheSeconds, int expectedQueries)
    {
        var client = new RemoteDnsClient(new ProxyRouteDialer(TcpConnector.Default), NullLogger.Instance, new DnsCache(clock));
        var active = ActiveConfiguration.Create(Config(cacheSeconds));

        for (ushort id = 1; id <= 3; id++)
        {
            var response = await client.QueryAsync(active, DnsWire.BuildQuery(id, "_ldap._tcp.dc._msdcs.corp.local", TypeSrv), TestTimeout.Token());
            Assert.Equal(id, (response[0] << 8) | response[1]); // a cached answer carries the new query's ID
            Assert.Equal(1, (response[6] << 8) | response[7]);
        }

        Assert.Equal(expectedQueries, domainController.Queries.Count);
    }

    [Fact]
    public async Task Resolved_addresses_are_kept_until_cleared()
    {
        var cache = new DnsCache(clock);
        var client = new RemoteDnsClient(new ProxyRouteDialer(TcpConnector.Default), NullLogger.Instance, cache);
        var active = ActiveConfiguration.Create(Config(DnsSettings.CacheUntilCleared));

        Assert.Equal(Dc01, await client.ResolveAsync(active, "dc01.corp.local", TestTimeout.Token()));
        clock.Advance(TimeSpan.FromDays(1));
        Assert.Equal(Dc01, await client.ResolveAsync(active, "DC01.corp.local.", TestTimeout.Token()));
        Assert.Single(domainController.Queries);

        Assert.Equal(1, cache.Clear());
        Assert.Equal(Dc01, await client.ResolveAsync(active, "dc01.corp.local", TestTimeout.Token()));
        Assert.Equal(2, domainController.Queries.Count); // asked again after clearing
    }

    [Fact]
    public async Task Unknown_names_and_failures_are_not_cached()
    {
        var client = new RemoteDnsClient(new ProxyRouteDialer(TcpConnector.Default), NullLogger.Instance, new DnsCache(clock));
        var active = ActiveConfiguration.Create(Config(DnsSettings.CacheUntilCleared));

        Assert.Null(await client.ResolveAsync(active, "new.corp.local", TestTimeout.Token()));
        Assert.Null(await client.ResolveAsync(active, "new.corp.local", TestTimeout.Token()));
        Assert.Equal(2, domainController.Queries.Count); // the name may exist by the next connection

        await socks.DisposeAsync(); // the pivot goes down
        socks = new FakeProxyServer(FakeProxyKind.Socks5); // for DisposeAsync
        var failed = await client.QueryAsync(active, DnsWire.BuildQuery(9, "_kerberos._tcp.corp.local", TypeSrv), TestTimeout.Token());
        Assert.Equal(2, failed[3] & 0x0F); // SERVFAIL
        Assert.Equal(2, domainController.Queries.Count);
    }

    [Theory]
    [InlineData(60, 1)]
    [InlineData(DnsSettings.CacheUntilCleared, 1)]
    [InlineData(0, 2)]
    public async Task The_services_own_lookups_are_cached(int cacheSeconds, int expectedQueries)
    {
        var cache = new DnsCache(clock);
        var store = new ConfigurationStore(Config(cacheSeconds));
        var resolver = new ModeAwareResolver(store, new UpstreamDnsResolver([upstreamDns.Endpoint]), cache);

        Assert.Equal([IPAddress.Parse("192.0.2.80")], await resolver.ResolveAsync("api.example.com", TestTimeout.Token()));
        Assert.Equal([IPAddress.Parse("192.0.2.80")], await resolver.ResolveAsync("api.example.com", TestTimeout.Token()));

        Assert.Equal(expectedQueries, upstreamDns.Queries.Count);
    }

    [Fact]
    public async Task Shortening_the_cache_time_applies_at_once()
    {
        var store = new ConfigurationStore(Config(DnsSettings.CacheUntilCleared));
        var resolver = new ModeAwareResolver(store, new UpstreamDnsResolver([upstreamDns.Endpoint]), new DnsCache(clock));
        await resolver.ResolveAsync("api.example.com", TestTimeout.Token());
        clock.Advance(TimeSpan.FromMinutes(10));

        Assert.Empty(store.TryApply(Config(60)));
        await resolver.ResolveAsync("api.example.com", TestTimeout.Token());

        Assert.Equal(2, upstreamDns.Queries.Count);
    }

    private ProxynatorConfig Config(int cacheSeconds) => Configs.Minimal() with
    {
        Settings = new ProxynatorSettings
        {
            Dns = new DnsSettings
            {
                Mode = DnsMode.Remote,
                RemoteDomains = ["*corp.local"],
                RemoteServer = new RemoteDnsServer { Address = "10.0.0.10", Via = "pivot", ResolveNames = true },
                CacheSeconds = cacheSeconds,
            },
        },
        Proxies = [Configs.Proxy("pivot", ProxyType.Socks5, socks?.Endpoint.Port ?? 1080)],
    };
}
