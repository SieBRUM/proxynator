namespace Proxynator.Core.Proxies;

/// <summary>Establishing a connection through a proxy failed.</summary>
public sealed class ProxyException : Exception
{
    /// <summary>Creates the exception.</summary>
    public ProxyException(ProxyFailure failure, string message, string? hopId = null, Exception? innerException = null)
        : base(message, innerException)
    {
        Failure = failure;
        HopId = hopId;
    }

    /// <summary>The failure category.</summary>
    public ProxyFailure Failure { get; }

    /// <summary>The identifier of the hop that failed, when known.</summary>
    public string? HopId { get; }

    /// <summary>Returns a copy attributed to <paramref name="hopId"/>.</summary>
    public ProxyException WithHop(string hopId) =>
        new(Failure, $"Proxy '{hopId}': {Message}", hopId, InnerException ?? this);
}
