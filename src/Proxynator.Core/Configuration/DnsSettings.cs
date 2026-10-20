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

    /// <summary>How long to wait for the client's first bytes when sniffing a hostname.</summary>
    public int SniffTimeoutMs { get; set; } = 250;
}
