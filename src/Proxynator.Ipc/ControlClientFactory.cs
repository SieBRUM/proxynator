using System.IO.Pipes;
using System.Net.Sockets;
using System.Security.Principal;
using Grpc.Net.Client;
using Proxynator.Ipc.V1;

namespace Proxynator.Ipc;

/// <summary>Creates clients for the control API over the local IPC transport.</summary>
public static class ControlClientFactory
{
    /// <summary>How long to wait for the service to accept the connection.</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Creates a channel to the service at <paramref name="endpoint"/> (see <see cref="IpcEndpoint"/>). Dispose it when
    /// done. Connection problems surface as <see cref="Grpc.Core.RpcException"/> with status Unavailable on the first call.
    /// </summary>
    public static GrpcChannel CreateChannel(string? endpoint = null)
    {
        endpoint ??= IpcEndpoint.Default;
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = (_, cancellationToken) => ConnectAsync(endpoint, cancellationToken),
        };

        // The authority is ignored by the transport; HTTP/2 without TLS is fine on a local pipe/socket.
        return GrpcChannel.ForAddress("http://proxynator", new GrpcChannelOptions { HttpHandler = handler, DisposeHttpClient = true });
    }

    /// <summary>Creates a client on a new channel.</summary>
    public static Control.ControlClient CreateClient(GrpcChannel channel) => new(channel);

    private static async ValueTask<Stream> ConnectAsync(string endpoint, CancellationToken cancellationToken)
    {
        try
        {
            return await ConnectCoreAsync(endpoint, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // A missing named pipe is not an error on Windows, the connect just waits. Report the timeout as an I/O
            // failure so gRPC surfaces it as Unavailable (like a refused Unix socket) instead of a cancellation.
            throw new IOException($"Timed out after {ConnectTimeout.TotalSeconds:0}s connecting to {IpcEndpoint.Describe(endpoint)}.", ex);
        }
    }

    private static async ValueTask<Stream> ConnectCoreAsync(string endpoint, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ConnectTimeout);

        if (OperatingSystem.IsWindows())
        {
            var pipe = new NamedPipeClientStream(".", endpoint, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
            try
            {
                await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
                return pipe;
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(endpoint), timeout.Token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
