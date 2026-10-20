using System.Net;
using System.Net.Sockets;

namespace Proxynator.Core.Net;

/// <summary>Default <see cref="ITcpConnector"/> using plain sockets.</summary>
/// <param name="configureSocket">Optional hook to set socket options before connecting.</param>
public sealed class TcpConnector(Action<Socket>? configureSocket = null) : ITcpConnector
{
    /// <summary>A connector without socket customisation.</summary>
    public static TcpConnector Default { get; } = new();

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(TargetEndpoint endpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        IPAddress[] addresses = endpoint.Address is { } known
            ? [known]
            : await System.Net.Dns.GetHostAddressesAsync(endpoint.Host!, cancellationToken).ConfigureAwait(false);

        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        SocketException? lastError = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.NoDelay = true;
                configureSocket?.Invoke(socket);
                await socket.ConnectAsync(address, endpoint.Port, cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw lastError!;
    }
}
