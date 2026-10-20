using System.Buffers;
using System.Net.Security;
using System.Net.Sockets;

namespace Proxynator.Core.Relay;

/// <summary>Copies data in both directions between the client and upstream, propagating half-closes.</summary>
internal static class StreamPump
{
    private const int BufferSize = 32 * 1024;

    public static async Task RunAsync(Stream client, Stream upstream, ClientPrelude prelude, TrackedConnection connection, CancellationToken cancellationToken)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var toUpstream = PumpClientToUpstreamAsync(client, upstream, prelude, connection, abort);
        var toClient = PumpAsync(upstream, client, connection.AddReceived, abort);
        await Task.WhenAll(toUpstream, toClient).ConfigureAwait(false);
    }

    private static async Task PumpClientToUpstreamAsync(Stream client, Stream upstream, ClientPrelude prelude, TrackedConnection connection, CancellationTokenSource abort)
    {
        try
        {
            var clientClosed = await prelude.ForwardAsync(upstream, connection.AddSent, abort.Token).ConfigureAwait(false);
            if (!clientClosed)
            {
                await CopyAsync(client, upstream, connection.AddSent, abort.Token).ConfigureAwait(false);
            }

            await ShutdownSendAsync(upstream).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsConnectionError(ex))
        {
            await abort.CancelAsync().ConfigureAwait(false);
        }
    }

    private static async Task PumpAsync(Stream source, Stream destination, Action<int> onBytes, CancellationTokenSource abort)
    {
        try
        {
            await CopyAsync(source, destination, onBytes, abort.Token).ConfigureAwait(false);
            await ShutdownSendAsync(destination).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsConnectionError(ex))
        {
            await abort.CancelAsync().ConfigureAwait(false);
        }
    }

    private static async Task CopyAsync(Stream source, Stream destination, Action<int> onBytes, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            int count;
            while ((count = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await destination.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                onBytes(count);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ShutdownSendAsync(Stream stream)
    {
        try
        {
            switch (stream)
            {
                case NetworkStream network:
                    network.Socket.Shutdown(SocketShutdown.Send);
                    break;
                case SslStream ssl:
                    await ssl.ShutdownAsync().ConfigureAwait(false);
                    break;
            }
        }
        catch (Exception ex) when (IsConnectionError(ex))
        {
            // The peer is already gone; nothing to shut down.
        }
    }

    private static bool IsConnectionError(Exception ex) =>
        ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException;
}
