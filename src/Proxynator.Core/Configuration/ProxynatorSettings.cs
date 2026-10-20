namespace Proxynator.Core.Configuration;

/// <summary>Global settings.</summary>
public sealed record ProxynatorSettings
{
    /// <summary>Traffic capture settings.</summary>
    public CaptureSettings Capture { get; set; } = new();

    /// <summary>DNS / hostname handling settings.</summary>
    public DnsSettings Dns { get; set; } = new();

    /// <summary>UDP handling settings.</summary>
    public UdpSettings Udp { get; set; } = new();

    /// <summary>Local relay settings.</summary>
    public RelaySettings Relay { get; set; } = new();
}
