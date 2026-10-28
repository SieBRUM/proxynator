namespace Proxynator.Core.Configuration;

/// <summary>DNS / hostname handling settings.</summary>
public sealed record DnsSettings
{
    /// <summary>Default fake-IP range used by <see cref="DnsMode.Remote"/>.</summary>
    public const string DefaultFakeIpRange = "198.18.0.0/15";

    /// <summary>How hostnames are obtained and passed to proxies.</summary>
    public DnsMode Mode { get; set; } = DnsMode.Sniff;

    /// <summary>Address range handed out as fake DNS answers in <see cref="DnsMode.Remote"/>.</summary>
    public string FakeIpRange { get; set; } = DefaultFakeIpRange;

    /// <summary>
    /// Names answered with fake addresses in <see cref="DnsMode.Remote"/> (wildcards, e.g. <c>*.corp.local</c>).
    /// <c>*</c> means every name. Names of configured proxies, single-label names and reverse lookups are never faked.
    /// </summary>
    public IReadOnlyList<string> RemoteDomains { get; set; } = ["*"];

    /// <summary>
    /// Where queries for <see cref="RemoteDomains"/> that are not answered with fake addresses go (through a proxy),
    /// e.g. the SRV lookups that locate domain controllers. Without it they go to the local DNS servers.
    /// </summary>
    public RemoteDnsServer? RemoteServer { get; set; }

    /// <summary>How long to wait for the client's first bytes when sniffing a hostname.</summary>
    public int SniffTimeoutMs { get; set; } = 250;

    /// <summary>The <see cref="CacheSeconds"/> value that keeps answers until the cache is cleared or the service stops.</summary>
    public const int CacheUntilCleared = -1;

    /// <summary>The longest <see cref="CacheSeconds"/> value other than <see cref="CacheUntilCleared"/> (one week).</summary>
    public const int MaxCacheSeconds = 604_800;

    /// <summary>
    /// How long Proxynator reuses the DNS answers it resolved itself (see <c>NameResolution.DnsCache</c>), in seconds.
    /// 0 turns caching off; <see cref="CacheUntilCleared"/> keeps answers until the cache is cleared or the service stops.
    /// </summary>
    public int CacheSeconds { get; set; } = 60;
}
