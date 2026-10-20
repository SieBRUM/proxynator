using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.Core.Tests.Support;

public enum FakeProxyKind
{
    Socks4,
    Socks5,
    Http,
}

/// <summary>What a fake proxy was asked to connect to (or, for SOCKS5 UDP, to send a datagram to).</summary>
internal sealed record FakeProxyRequest(string? Host, IPAddress? Address, int Port, string? Username, string? Password, string? UserId, bool Udp = false);

/// <summary>
/// A minimal but real SOCKS4/4a, SOCKS5 or HTTP CONNECT proxy on loopback. It records every request and then
/// connects to the endpoint chosen by <see cref="Resolve"/> (by default: the requested address), so it can be used
/// as a hop in chain tests.
/// </summary>
internal sealed class FakeProxyServer : IAsyncDisposable
{
    private readonly Socket listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> sessions = [];
    private readonly Task acceptLoop;

    public FakeProxyServer(FakeProxyKind kind)
    {
        Kind = kind;
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        acceptLoop = AcceptLoopAsync();
    }

    public FakeProxyKind Kind { get; }

    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndPoint!;

    public ConcurrentQueue<FakeProxyRequest> Requests { get; } = new();

    /// <summary>Required username/password (SOCKS5, HTTP Basic). Null means no authentication.</summary>
    public (string User, string Password)? RequiredCredentials { get; init; }

    /// <summary>Refuse every connect request.</summary>
    public bool RejectAll { get; init; }

    /// <summary>Accept connections but never answer (to test timeouts).</summary>
    public bool NeverRespond { get; init; }

    /// <summary>Maps a request to the endpoint actually connected to.</summary>
    public Func<FakeProxyRequest, IPEndPoint> Resolve { get; init; } =
        request => new IPEndPoint(request.Address ?? IPAddress.Loopback, request.Port);

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        listener.Dispose();
        await acceptLoop;
        await Task.WhenAll(sessions);
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

            sessions.Add(HandleAsync(client));
        }
    }

    private async Task HandleAsync(Socket client)
    {
        using (client)
        {
            try
            {
                using var stream = new NetworkStream(client, ownsSocket: false);
                if (NeverRespond)
                {
                    await Task.Delay(Timeout.Infinite, stop.Token);
                }

                var request = Kind switch
                {
                    FakeProxyKind.Socks4 => await HandshakeSocks4Async(stream),
                    FakeProxyKind.Socks5 => await HandshakeSocks5Async(stream),
                    _ => await HandshakeHttpAsync(stream),
                };
                if (request is null)
                {
                    return;
                }

                using var upstream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await upstream.ConnectAsync(Resolve(request), stop.Token);
                await Tunnel.PumpAsync(client, upstream, stop.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
            }
        }
    }

    private async Task<FakeProxyRequest?> HandshakeSocks4Async(NetworkStream stream)
    {
        var header = await ReadAsync(stream, 8);
        var port = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        var userId = await ReadNullTerminatedAsync(stream);
        string? host = null;
        IPAddress? address = new(header.AsSpan(4, 4));
        if (header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0)
        {
            host = await ReadNullTerminatedAsync(stream);
            address = null;
        }

        var request = new FakeProxyRequest(host, address, port, null, null, userId);
        Requests.Enqueue(request);
        await stream.WriteAsync(new byte[] { 0, (byte)(RejectAll ? 91 : 90), 0, 0, 0, 0, 0, 0 }, stop.Token);
        return RejectAll ? null : request;
    }

    private async Task<FakeProxyRequest?> HandshakeSocks5Async(NetworkStream stream)
    {
        var greeting = await ReadAsync(stream, 2);
        var methods = await ReadAsync(stream, greeting[1]);
        string? user = null, password = null;
        if (RequiredCredentials is { } required)
        {
            if (!methods.Contains((byte)2))
            {
                await stream.WriteAsync(new byte[] { 5, 0xFF }, stop.Token);
                return null;
            }

            await stream.WriteAsync(new byte[] { 5, 2 }, stop.Token);
            var version = await ReadAsync(stream, 2);
            user = Encoding.UTF8.GetString(await ReadAsync(stream, version[1]));
            var passwordLength = (await ReadAsync(stream, 1))[0];
            password = Encoding.UTF8.GetString(await ReadAsync(stream, passwordLength));
            var ok = user == required.User && password == required.Password;
            await stream.WriteAsync(new byte[] { 1, (byte)(ok ? 0 : 1) }, stop.Token);
            if (!ok)
            {
                return null;
            }
        }
        else
        {
            await stream.WriteAsync(new byte[] { 5, 0 }, stop.Token);
        }

        var header = await ReadAsync(stream, 4);
        string? host = null;
        IPAddress? address = null;
        if (header[1] == 3)
        {
            await ReadAsync(stream, header[3] == 4 ? 18 : 6); // the (unused) client address of UDP ASSOCIATE
            await RunUdpAssociationAsync(stream);
            return null;
        }

        switch (header[3])
        {
            case 1:
                address = new IPAddress(await ReadAsync(stream, 4));
                break;
            case 4:
                address = new IPAddress(await ReadAsync(stream, 16));
                break;
            default:
                var length = (await ReadAsync(stream, 1))[0];
                host = Encoding.ASCII.GetString(await ReadAsync(stream, length));
                break;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(await ReadAsync(stream, 2));
        var request = new FakeProxyRequest(host, address, port, user, password, null);
        Requests.Enqueue(request);
        await stream.WriteAsync(new byte[] { 5, (byte)(RejectAll ? 5 : 0), 0, 1, 0, 0, 0, 0, 0, 0 }, stop.Token);
        return RejectAll ? null : request;
    }

    private async Task<FakeProxyRequest?> HandshakeHttpAsync(NetworkStream stream)
    {
        var head = new StringBuilder();
        var one = new byte[1];
        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            await stream.ReadExactlyAsync(one, stop.Token);
            head.Append((char)one[0]);
        }

        var lines = head.ToString().Split("\r\n");
        var authority = lines[0].Split(' ')[1];
        var colon = authority.LastIndexOf(':');
        var hostPart = authority[..colon].Trim('[', ']');
        var port = int.Parse(authority[(colon + 1)..], CultureInfo.InvariantCulture);

        string? user = null, password = null;
        var authHeader = lines.FirstOrDefault(l => l.StartsWith("Proxy-Authorization: Basic ", StringComparison.OrdinalIgnoreCase));
        if (authHeader is not null)
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader["Proxy-Authorization: Basic ".Length..]));
            user = decoded[..decoded.IndexOf(':', StringComparison.Ordinal)];
            password = decoded[(decoded.IndexOf(':', StringComparison.Ordinal) + 1)..];
        }

        var isAddress = IPAddress.TryParse(hostPart, out var address);
        var request = new FakeProxyRequest(isAddress ? null : hostPart, isAddress ? address : null, port, user, password, null);
        Requests.Enqueue(request);

        if (RequiredCredentials is { } required && (user != required.User || password != required.Password))
        {
            await stream.WriteAsync("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\n\r\n"u8.ToArray(), stop.Token);
            return null;
        }

        if (RejectAll)
        {
            await stream.WriteAsync("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"u8.ToArray(), stop.Token);
            return null;
        }

        await stream.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray(), stop.Token);
        return request;
    }

    /// <summary>
    /// SOCKS5 UDP ASSOCIATE: relays datagrams between the client and the resolved targets until the client closes the
    /// control connection. Replies carry the address the client asked for, as RFC 1928 requires.
    /// </summary>
    private async Task RunUdpAssociationAsync(NetworkStream control)
    {
        using var relay = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        relay.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)relay.LocalEndPoint!).Port;
        await control.WriteAsync(new byte[] { 5, (byte)(RejectAll ? 5 : 0), 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }, stop.Token);
        if (RejectAll)
        {
            return;
        }

        using var association = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
        _ = Task.Run(async () =>
        {
            try
            {
                while (await control.ReadAsync(new byte[1], association.Token) > 0)
                {
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
            }

            await association.CancelAsync();
        });

        var upstreams = new Dictionary<IPEndPoint, Socket>();
        var buffer = new byte[65535];
        try
        {
            while (true)
            {
                var result = await relay.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), association.Token);
                var client = (IPEndPoint)result.RemoteEndPoint;
                var datagram = buffer.AsSpan(0, result.ReceivedBytes);
                var addressStart = 3;
                var (host, address, addressLength) = datagram[addressStart] switch
                {
                    1 => ((string?)null, new IPAddress(datagram.Slice(addressStart + 1, 4)), 1 + 4),
                    4 => (null, new IPAddress(datagram.Slice(addressStart + 1, 16)), 1 + 16),
                    _ => (Encoding.ASCII.GetString(datagram.Slice(addressStart + 2, datagram[addressStart + 1])), (IPAddress?)null, 2 + datagram[addressStart + 1]),
                };
                var targetPort = BinaryPrimitives.ReadUInt16BigEndian(datagram[(addressStart + addressLength)..]);
                var requestedAddress = datagram.Slice(addressStart, addressLength + 2).ToArray();
                var payload = datagram[(addressStart + addressLength + 2)..].ToArray();
                var request = new FakeProxyRequest(host, address, targetPort, null, null, null, Udp: true);
                Requests.Enqueue(request);

                var target = Resolve(request);
                if (!upstreams.TryGetValue(target, out var upstream))
                {
                    upstream = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    await upstream.ConnectAsync(target, association.Token);
                    upstreams[target] = upstream;
                    _ = RelayRepliesAsync(upstream, relay, client, requestedAddress, association.Token);
                }

                await upstream.SendAsync(payload, association.Token);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            foreach (var upstream in upstreams.Values)
            {
                upstream.Dispose();
            }
        }
    }

    private static async Task RelayRepliesAsync(Socket upstream, Socket relay, IPEndPoint client, byte[] requestedAddress, CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];
        try
        {
            while (true)
            {
                var length = await upstream.ReceiveAsync(buffer, cancellationToken);
                byte[] reply = [0, 0, 0, .. requestedAddress, .. buffer.AsSpan(0, length)];
                await relay.SendToAsync(reply, SocketFlags.None, client, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }

    private async Task<byte[]> ReadAsync(NetworkStream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, stop.Token);
        return buffer;
    }

    private async Task<string> ReadNullTerminatedAsync(NetworkStream stream)
    {
        var bytes = new List<byte>();
        var one = new byte[1];
        while (true)
        {
            await stream.ReadExactlyAsync(one, stop.Token);
            if (one[0] == 0)
            {
                return Encoding.ASCII.GetString(bytes.ToArray());
            }

            bytes.Add(one[0]);
        }
    }
}
