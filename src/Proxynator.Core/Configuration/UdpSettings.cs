namespace Proxynator.Core.Configuration;

/// <summary>UDP handling settings.</summary>
public sealed record UdpSettings
{
    /// <summary>Drop UDP/443 (QUIC) for proxied processes so they fall back to TCP.</summary>
    public bool BlockQuic { get; set; } = true;
}
