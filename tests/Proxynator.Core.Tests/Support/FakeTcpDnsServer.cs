using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.Core.Tests.Support;

/// <summary>
/// A DNS-over-TCP server on loopback, standing in for a domain controller's DNS: every SRV query is answered with one
/// record pointing at <see cref="SrvTarget"/> on port 389, A queries from <see cref="Addresses"/>; other queries get an
/// empty answer. Records the names asked.
/// </summary>
internal sealed class FakeTcpDnsServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;

    public FakeTcpDnsServer(string srvTarget = "dc01.corp.local", IReadOnlyDictionary<string, IPAddress>? addresses = null)
    {
        SrvTarget = srvTarget;
        Addresses = addresses ?? new Dictionary<string, IPAddress>();
        listener.Start();
        loop = ServeAsync();
    }

    public string SrvTarget { get; }

    /// <summary>A records: name → IPv4 address. Other names get an empty answer.</summary>
    public IReadOnlyDictionary<string, IPAddress> Addresses { get; }

    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndpoint;

    public ConcurrentQueue<string> Queries { get; } = new();

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        listener.Stop();
        await loop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        stop.Dispose();
    }

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
            var stream = client.GetStream();
            try
            {
                var header = new byte[2];
                while (await stream.ReadAtLeastAsync(header, 2, throwOnEndOfStream: false, stop.Token) == 2)
                {
                    var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
                    await stream.ReadExactlyAsync(query, stop.Token);
                    var response = Respond(query);
                    var framed = new byte[2 + response.Length];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)response.Length);
                    response.CopyTo(framed, 2);
                    await stream.WriteAsync(framed, stop.Token);
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
            {
                // Client gone.
            }
        }
    }

    private byte[] Respond(byte[] query)
    {
        // Question: name labels from offset 12, then type and class.
        var offset = 12;
        var labels = new List<string>();
        while (query[offset] != 0)
        {
            labels.Add(Encoding.ASCII.GetString(query, offset + 1, query[offset]));
            offset += query[offset] + 1;
        }

        var questionEnd = offset + 5;
        var type = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset + 1));
        Queries.Enqueue(string.Join('.', labels));

        var response = new List<byte>(query[..questionEnd]);
        response[2] = (byte)(0x80 | (query[2] & 0x01));
        response[3] = 0x80;
        var name = string.Join('.', labels);
        var address = type == 1 && Addresses.TryGetValue(name, out var found) ? found : null;
        var answers = type == 33 || address is not null ? 1 : 0;
        response[6] = 0;
        response[7] = (byte)answers;
        response[8] = response[9] = response[10] = response[11] = 0;
        if (address is not null)
        {
            response.AddRange([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]); // name pointer, A, IN, TTL 60, length 4
            response.AddRange(address.GetAddressBytes());
        }
        else if (answers == 1)
        {
            var target = new List<byte>();
            foreach (var label in SrvTarget.Split('.'))
            {
                target.Add((byte)label.Length);
                target.AddRange(Encoding.ASCII.GetBytes(label));
            }

            target.Add(0);
            response.AddRange([0xC0, 0x0C, 0, 33, 0, 1, 0, 0, 0, 60]); // name pointer, SRV, IN, TTL 60
            response.AddRange([(byte)((target.Count + 6) >> 8), (byte)(target.Count + 6), 0, 0, 0, 100, 0x01, 0x85]); // priority 0, weight 100, port 389
            response.AddRange(target);
        }

        return [.. response];
    }
}
