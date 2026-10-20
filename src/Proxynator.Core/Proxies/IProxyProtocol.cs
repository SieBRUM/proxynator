using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>A proxy handshake performed over an already connected stream.</summary>
public interface IProxyProtocol
{
    /// <summary>
    /// Asks the proxy at the other end of <paramref name="transport"/> to connect to <paramref name="target"/>.
    /// Returns the stream to use for the tunnelled connection (the same stream, or a wrapper such as TLS).
    /// </summary>
    /// <exception cref="ProxyException">The proxy refused or failed.</exception>
    ValueTask<Stream> ConnectAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken);
}
