namespace Proxynator.Core.Configuration;

/// <summary>An ordered sequence of proxies; each hop is tunnelled through the previous one.</summary>
public sealed record ChainDefinition
{
    /// <summary>Unique identifier (shared namespace with proxy identifiers, case-insensitive).</summary>
    public required string Id { get; init; }

    /// <summary>Proxy identifiers, from the first hop (connected to directly) to the last.</summary>
    public required IReadOnlyList<string> Hops { get; init; }
}
