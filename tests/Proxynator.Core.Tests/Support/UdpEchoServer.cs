using System.Net;
using System.Net.Sockets;

namespace Proxynator.Core.Tests.Support;

/// <summary>A loopback UDP server that sends every datagram back to its sender.</summary>
internal sealed class UdpEchoServer : IAsyncDisposable
{
    private readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;
    private int datagrams;

    public UdpEchoServer()
    {
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        loop = LoopAsync();
    }

    public IPEndPoint Endpoint => (IPEndPoint)socket.LocalEndPoint!;

    public int DatagramCount => Volatile.Read(ref datagrams);

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        socket.Dispose();
        await loop;
        stop.Dispose();
    }

    private async Task LoopAsync()
    {
        var buffer = new byte[65535];
        try
        {
            while (true)
            {
                var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token);
                Interlocked.Increment(ref datagrams);
                await socket.SendToAsync(buffer.AsMemory(0, result.ReceivedBytes), SocketFlags.None, result.RemoteEndPoint, stop.Token);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }
}
