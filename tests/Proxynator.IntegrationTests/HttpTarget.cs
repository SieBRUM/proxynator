using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.IntegrationTests;

/// <summary>
/// A tiny HTTP server on every address, reached through the machine's own non-loopback address: capture backends
/// never redirect loopback, and tests must not depend on internet access.
/// </summary>
internal sealed class HttpTarget : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Any, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;
    private int requests;

    public HttpTarget()
    {
        Address = FindLocalAddress();
        listener.Start();
        loop = ServeAsync();
    }

    /// <summary>A non-loopback IPv4 address of this machine.</summary>
    public IPAddress Address { get; }

    public IPEndPoint Endpoint => new(Address, ((IPEndPoint)listener.LocalEndpoint).Port);

    public int Requests => Volatile.Read(ref requests);

    public string Url(string host = "") => $"http://{(host.Length > 0 ? host : Address.ToString())}:{Endpoint.Port}/";

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        listener.Stop();
        await loop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        stop.Dispose();
    }

    private static IPAddress FindLocalAddress() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(i => i.OperationalStatus == OperationalStatus.Up && i.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(i => i.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
        ?? throw new InvalidOperationException("No non-loopback IPv4 address found.");

    private async Task ServeAsync()
    {
        while (!stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = AnswerAsync(client);
        }
    }

    private async Task AnswerAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var buffer = new byte[4096];
                var received = new StringBuilder();
                while (!received.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var count = await stream.ReadAsync(buffer, stop.Token);
                    if (count == 0)
                    {
                        return;
                    }

                    received.Append(Encoding.ASCII.GetString(buffer, 0, count));
                }

                Interlocked.Increment(ref requests);
                await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray(), stop.Token);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
            {
                // Client gone.
            }
        }
    }
}
