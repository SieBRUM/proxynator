using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Proxynator.Core.NameResolution;

namespace Proxynator.Core.Tests.Support;

/// <summary>A loopback UDP DNS server answering A queries from a fixed table (NXDOMAIN otherwise).</summary>
internal sealed class FakeDnsServer : IAsyncDisposable
{
    private readonly Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;

    public FakeDnsServer(IReadOnlyDictionary<string, IPAddress>? records = null, bool silent = false)
    {
        Records = records ?? new Dictionary<string, IPAddress>();
        Silent = silent;
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        loop = LoopAsync();
    }

    public IReadOnlyDictionary<string, IPAddress> Records { get; }

    public bool Silent { get; }

    public IPEndPoint Endpoint => (IPEndPoint)socket.LocalEndPoint!;

    public ConcurrentQueue<string> Queries { get; } = new();

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        socket.Dispose();
        await loop;
        stop.Dispose();
    }

    private async Task LoopAsync()
    {
        var buffer = new byte[4096];
        try
        {
            while (true)
            {
                var result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), stop.Token);
                var query = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
                if (!DnsWire.TryParseQuery(query, out var question))
                {
                    continue;
                }

                Queries.Enqueue(question.Name);
                if (Silent)
                {
                    continue;
                }

                byte[] response;
                if (Records.TryGetValue(question.Name, out var address))
                {
                    response = DnsWire.BuildResponse(query, question, question.Type == DnsWire.TypeA ? address : null, 60);
                }
                else
                {
                    response = DnsWire.BuildResponse(query, question, null, 60);
                    response[3] |= 3; // NXDOMAIN
                }

                await socket.SendToAsync(response, SocketFlags.None, result.RemoteEndPoint, stop.Token);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }

    /// <summary>The A-record addresses in a response, for assertions.</summary>
    public static List<IPAddress> AddressesIn(byte[] response) =>
        DnsWire.TryParseAddresses(response, BinaryPrimitives.ReadUInt16BigEndian(response), out var addresses, out _) ? addresses : [];
}
