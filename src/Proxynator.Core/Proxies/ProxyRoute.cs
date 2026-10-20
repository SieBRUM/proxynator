namespace Proxynator.Core.Proxies;

/// <summary>A single proxy or a chain: the hops a connection is tunnelled through, in order.</summary>
public sealed record ProxyRoute
{
    /// <summary>Creates a route.</summary>
    public ProxyRoute(string id, IReadOnlyList<ProxyHop> hops)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(hops);
        if (hops.Count == 0)
        {
            throw new ArgumentException("A route needs at least one hop.", nameof(hops));
        }

        Id = id;
        Hops = hops;
    }

    /// <summary>The proxy or chain identifier.</summary>
    public string Id { get; }

    /// <summary>The hops, first (connected to directly) to last.</summary>
    public IReadOnlyList<ProxyHop> Hops { get; }
}
