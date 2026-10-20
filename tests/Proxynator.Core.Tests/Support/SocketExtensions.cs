using System.Net.Sockets;
using System.Text;

namespace Proxynator.Core.Tests.Support;

internal static class SocketExtensions
{
    /// <summary>Reads until <paramref name="expectedLength"/> bytes arrived or the peer closed.</summary>
    public static async Task<string> ReceiveStringAsync(this Socket socket, int expectedLength, CancellationToken cancellationToken)
    {
        var buffer = new byte[expectedLength];
        var total = 0;
        while (total < expectedLength)
        {
            var count = await socket.ReceiveAsync(buffer.AsMemory(total), cancellationToken);
            if (count == 0)
            {
                break;
            }

            total += count;
        }

        return Encoding.ASCII.GetString(buffer, 0, total);
    }

    /// <summary>True if the peer closed or reset the connection without sending data.</summary>
    public static async Task<bool> IsClosedByPeerAsync(this Socket socket, CancellationToken cancellationToken)
    {
        try
        {
            return await socket.ReceiveAsync(new byte[1], cancellationToken) == 0;
        }
        catch (SocketException)
        {
            return true;
        }
    }
}
