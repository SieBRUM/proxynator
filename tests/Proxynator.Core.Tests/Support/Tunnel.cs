using System.Net.Sockets;

namespace Proxynator.Core.Tests.Support;

internal static class Tunnel
{
    /// <summary>Pumps both directions until both sides are done, propagating half-closes.</summary>
    public static async Task PumpAsync(Socket a, Socket b, CancellationToken cancellationToken)
    {
        await Task.WhenAll(CopyAsync(a, b, cancellationToken), CopyAsync(b, a, cancellationToken));
    }

    private static async Task CopyAsync(Socket from, Socket to, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        try
        {
            int count;
            while ((count = await from.ReceiveAsync(buffer, cancellationToken)) > 0)
            {
                await to.SendAsync(buffer.AsMemory(0, count), cancellationToken);
            }

            to.Shutdown(SocketShutdown.Send);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }
}
