using System.Net.Sockets;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>
/// Connects to a target through a <see cref="ProxyRoute"/>: TCP to the first hop, then one handshake per hop, each
/// asking the current proxy to connect to the next hop (or, for the last hop, to the target).
/// </summary>
public sealed class ProxyRouteDialer(ITcpConnector connector)
{
    /// <summary>
    /// Establishes a tunnelled connection to <paramref name="target"/>. The whole operation, including all handshakes,
    /// must complete within <paramref name="timeout"/>.
    /// </summary>
    /// <exception cref="ProxyException">Any hop failed; <see cref="ProxyException.HopId"/> names it.</exception>
    public async ValueTask<Stream> ConnectAsync(ProxyRoute route, TargetEndpoint target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(target);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var token = timeoutSource.Token;

        var hops = route.Hops;
        var hop = hops[0];
        Stream? stream = null;
        try
        {
            try
            {
                stream = await connector.ConnectAsync(hop.Endpoint, token).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                throw new ProxyException(ProxyFailure.ConnectFailed, $"Could not connect to proxy at {hop.Endpoint}: {ex.Message}", innerException: ex);
            }

            for (var i = 0; i < hops.Count; i++)
            {
                hop = hops[i];
                var next = i + 1 < hops.Count ? hops[i + 1].Endpoint : target;
                stream = await ProxyProtocolFactory.Create(hop).ConnectAsync(stream, next, token).ConfigureAwait(false);
            }

            return stream;
        }
        catch (ProxyException ex)
        {
            await DisposeAsync(stream).ConfigureAwait(false);
            throw ex.WithHop(hop.Id);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            await DisposeAsync(stream).ConfigureAwait(false);
            throw new ProxyException(ProxyFailure.Timeout, $"Timed out after {timeout.TotalSeconds:0.#}s.", innerException: ex).WithHop(hop.Id);
        }
        catch (IOException ex)
        {
            await DisposeAsync(stream).ConfigureAwait(false);
            throw new ProxyException(ProxyFailure.ProtocolError, $"Connection to proxy failed during handshake: {ex.Message}", innerException: ex).WithHop(hop.Id);
        }
        catch
        {
            await DisposeAsync(stream).ConfigureAwait(false);
            throw;
        }
    }

    private static ValueTask DisposeAsync(Stream? stream) => stream?.DisposeAsync() ?? ValueTask.CompletedTask;
}
