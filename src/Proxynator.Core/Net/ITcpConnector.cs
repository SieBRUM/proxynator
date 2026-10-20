namespace Proxynator.Core.Net;

/// <summary>
/// Opens outbound TCP connections. Platform modules can supply their own implementation, e.g. to mark sockets so
/// the capture backend does not redirect the relay's own traffic.
/// </summary>
public interface ITcpConnector
{
    /// <summary>Connects to <paramref name="endpoint"/>, resolving its hostname if no address is known.</summary>
    ValueTask<Stream> ConnectAsync(TargetEndpoint endpoint, CancellationToken cancellationToken);
}
