using System.Buffers;
using System.Diagnostics;
using Proxynator.Core.Sniffing;

namespace Proxynator.Core.Relay;

/// <summary>
/// The first bytes read from a client while sniffing its hostname. They are replayed to the upstream side before
/// normal relaying starts. If the client had not sent anything when the sniff timeout expired (server-speaks-first
/// protocols), the outstanding read is kept and completed later instead of being cancelled, so no data is lost.
/// </summary>
internal sealed class ClientPrelude : IDisposable
{
    public static readonly ClientPrelude None = new(null);

    private byte[]? buffer;
    private int length;
    private Task<int>? pendingRead;

    private ClientPrelude(byte[]? buffer)
    {
        this.buffer = buffer;
    }

    public string? Hostname { get; private set; }

    public bool ClientClosed { get; private set; }

    public static async Task<ClientPrelude> ReadAsync(Stream client, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var prelude = new ClientPrelude(ArrayPool<byte>.Shared.Rent(HostnameSniffer.MaxSniffLength));
        var started = Stopwatch.GetTimestamp();
        try
        {
            while (prelude.length < HostnameSniffer.MaxSniffLength)
            {
                var remaining = timeout - Stopwatch.GetElapsedTime(started);
                if (remaining <= TimeSpan.Zero)
                {
                    break;
                }

                var read = client.ReadAsync(prelude.buffer.AsMemory(prelude.length, HostnameSniffer.MaxSniffLength - prelude.length), cancellationToken).AsTask();
                int count;
                try
                {
                    count = await read.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
                {
                    prelude.pendingRead = read;
                    if (ex is OperationCanceledException)
                    {
                        throw;
                    }

                    break;
                }

                if (count == 0)
                {
                    prelude.ClientClosed = true;
                    break;
                }

                prelude.length += count;
                var status = HostnameSniffer.TrySniff(prelude.buffer.AsSpan(0, prelude.length), out var hostname);
                if (status != SniffStatus.NeedMoreData)
                {
                    prelude.Hostname = hostname;
                    break;
                }
            }

            return prelude;
        }
        catch
        {
            prelude.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Writes the buffered bytes (and the result of a pending read) to <paramref name="upstream"/>.
    /// Returns <see langword="true"/> if the client has closed its sending side.
    /// </summary>
    public async Task<bool> ForwardAsync(Stream upstream, Action<int> onBytes, CancellationToken cancellationToken)
    {
        if (buffer is null)
        {
            return false;
        }

        if (length > 0)
        {
            await upstream.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            onBytes(length);
        }

        if (ClientClosed)
        {
            return true;
        }

        if (pendingRead is { } read)
        {
            pendingRead = null;
            var count = await read.ConfigureAwait(false);
            if (count == 0)
            {
                ClientClosed = true;
                return true;
            }

            await upstream.WriteAsync(buffer.AsMemory(length, count), cancellationToken).ConfigureAwait(false);
            onBytes(count);
        }

        return false;
    }

    public void Dispose()
    {
        var rented = buffer;
        if (rented is null)
        {
            return;
        }

        buffer = null;
        if (pendingRead is { IsCompleted: false } read)
        {
            // The read still owns the buffer; return it only once the read has finished (the socket is being closed).
            read.ContinueWith(
                static (task, state) =>
                {
                    _ = task.Exception;
                    ArrayPool<byte>.Shared.Return((byte[])state!);
                },
                rented,
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        else
        {
            _ = pendingRead?.Exception;
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
