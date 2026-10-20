using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.IntegrationTests;

/// <summary>
/// A minimal LDAPv3 server (BER over TCP, loopback): answers every bind with success and every search with one entry,
/// <c>cn=proxynator,dc=corp,dc=local</c> (<c>cn: proxynator</c>). Enough for real LDAP clients (curl's ldap:// with
/// OpenLDAP or WinLDAP) to complete a bind + search through the capture, the relay and a proxy.
/// </summary>
internal sealed class FakeLdapServer : IAsyncDisposable
{
    public const string EntryDn = "cn=proxynator,dc=corp,dc=local";

    private const byte Sequence = 0x30;
    private const byte BindRequest = 0x60;
    private const byte UnbindRequest = 0x42;
    private const byte SearchRequest = 0x63;

    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;

    public FakeLdapServer()
    {
        listener.Start();
        loop = ServeAsync();
    }

    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndpoint;

    /// <summary>The LDAP operations received, e.g. "bind", "search".</summary>
    public ConcurrentQueue<string> Operations { get; } = new();

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

            _ = HandleAsync(client);
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            var stream = client.GetStream();
            try
            {
                while (await ReadMessageAsync(stream) is { } message)
                {
                    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp, ... }
                    var position = 0;
                    if (!TryReadElement(message, ref position, out var tag, out var id) || tag != 0x02 ||
                        !TryReadElement(message, ref position, out var operation, out _))
                    {
                        return;
                    }

                    var messageId = id.Aggregate(0, (value, b) => (value << 8) | b);
                    switch (operation)
                    {
                        case BindRequest:
                            Operations.Enqueue("bind");
                            await stream.WriteAsync(Message(messageId, Element(0x61, Result())), stop.Token);
                            break;
                        case SearchRequest:
                            Operations.Enqueue("search");
                            var attribute = Element(Sequence, [.. OctetString("cn"), .. Element(0x31, OctetString("proxynator"))]);
                            var entry = Element(0x64, [.. OctetString(EntryDn), .. Element(Sequence, attribute)]);
                            await stream.WriteAsync(Message(messageId, entry), stop.Token);
                            await stream.WriteAsync(Message(messageId, Element(0x65, Result())), stop.Token);
                            break;
                        case UnbindRequest:
                            Operations.Enqueue("unbind");
                            return;
                        default:
                            Operations.Enqueue($"0x{operation:x2}");
                            return;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or SocketException)
            {
                // Client gone.
            }
        }
    }

    /// <summary>Reads one top-level SEQUENCE; returns its content, or null at the end of the stream.</summary>
    private async Task<byte[]?> ReadMessageAsync(NetworkStream stream)
    {
        var header = new byte[2];
        if (await stream.ReadAtLeastAsync(header, 2, throwOnEndOfStream: false, stop.Token) < 2 || header[0] != Sequence)
        {
            return null;
        }

        var length = header[1];
        int contentLength = length;
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7f;
            var bytes = new byte[count];
            await stream.ReadExactlyAsync(bytes, stop.Token);
            contentLength = bytes.Aggregate(0, (value, b) => (value << 8) | b);
        }

        var content = new byte[contentLength];
        await stream.ReadExactlyAsync(content, stop.Token);
        return content;
    }

    private static bool TryReadElement(byte[] data, ref int position, out byte tag, out byte[] value)
    {
        tag = 0;
        value = [];
        if (position + 2 > data.Length)
        {
            return false;
        }

        tag = data[position++];
        int length = data[position++];
        if ((length & 0x80) != 0)
        {
            var count = length & 0x7f;
            length = 0;
            for (var i = 0; i < count; i++)
            {
                length = (length << 8) | data[position++];
            }
        }

        if (position + length > data.Length)
        {
            return false;
        }

        value = data[position..(position + length)];
        position += length;
        return true;
    }

    private static byte[] Message(int messageId, byte[] operation) =>
        Element(Sequence, [.. Element(0x02, IntegerBytes(messageId)), .. operation]);

    /// <summary>LDAPResult: success, empty matchedDN and diagnosticMessage.</summary>
    private static byte[] Result() => [.. Element(0x0a, [0]), .. OctetString(string.Empty), .. OctetString(string.Empty)];

    private static byte[] OctetString(string value) => Element(0x04, Encoding.UTF8.GetBytes(value));

    private static byte[] IntegerBytes(int value)
    {
        var bytes = BitConverter.GetBytes(value).Reverse().SkipWhile(b => b == 0).ToArray();
        return bytes.Length == 0 ? [0] : (bytes[0] & 0x80) != 0 ? [0, .. bytes] : bytes;
    }

    private static byte[] Element(byte tag, byte[] content)
    {
        byte[] length = content.Length < 0x80
            ? [(byte)content.Length]
            : content.Length < 0x100 ? [0x81, (byte)content.Length] : [0x82, (byte)(content.Length >> 8), (byte)content.Length];
        return [tag, .. length, .. content];
    }
}
