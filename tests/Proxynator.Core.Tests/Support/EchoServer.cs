using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.Core.Tests.Support;

/// <summary>A loopback TCP server that echoes everything back, optionally sending a banner first.</summary>
internal sealed class EchoServer : IAsyncDisposable
{
    private readonly Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    private readonly CancellationTokenSource stop = new();
    private readonly Task acceptLoop;
    private readonly byte[]? banner;
    private int connectionCount;

    public EchoServer(string? banner = null)
    {
        this.banner = banner is null ? null : Encoding.ASCII.GetBytes(banner);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        acceptLoop = AcceptLoopAsync();
    }

    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndPoint!;

    public int ConnectionCount => Volatile.Read(ref connectionCount);

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        listener.Dispose();
        await acceptLoop;
        stop.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (true)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref connectionCount);
            _ = EchoAsync(client);
        }
    }

    private async Task EchoAsync(Socket client)
    {
        using (client)
        {
            try
            {
                if (banner is not null)
                {
                    await client.SendAsync(banner, stop.Token);
                }

                var buffer = new byte[8192];
                int count;
                while ((count = await client.ReceiveAsync(buffer, stop.Token)) > 0)
                {
                    await client.SendAsync(buffer.AsMemory(0, count), stop.Token);
                }

                client.Shutdown(SocketShutdown.Send);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
            {
            }
        }
    }
}
