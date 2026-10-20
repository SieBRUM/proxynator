namespace Proxynator.Core.Configuration;

/// <summary>Local relay settings.</summary>
public sealed record RelaySettings
{
    /// <summary>Timeout for establishing an upstream connection, including all proxy handshakes.</summary>
    public int ConnectTimeoutMs { get; set; } = 10_000;
}
