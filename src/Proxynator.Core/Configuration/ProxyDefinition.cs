namespace Proxynator.Core.Configuration;

/// <summary>An upstream proxy.</summary>
public sealed record ProxyDefinition
{
    /// <summary>Unique identifier (shared namespace with chain identifiers, case-insensitive).</summary>
    public required string Id { get; init; }

    /// <summary>The proxy protocol.</summary>
    public required ProxyType Type { get; init; }

    /// <summary>Hostname or IP address of the proxy.</summary>
    public required string Host { get; init; }

    /// <summary>TCP port of the proxy.</summary>
    public required int Port { get; init; }

    /// <summary>Optional credentials.</summary>
    public ProxyAuth? Auth { get; set; }
}
