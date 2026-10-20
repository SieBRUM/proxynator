using System.Net;
using System.Net.Sockets;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>
/// A SOCKS5 UDP ASSOCIATE session (RFC 1928 section 7): a TCP control connection that keeps the association alive,
/// and a UDP socket exchanging datagrams with the proxy's UDP relay, each prefixed with the real destination.
/// </summary>
public sealed class Socks5UdpAssociation : IAsyncDisposable
{
    private const int HeaderReserved = 3; // RSV (2) + FRAG (1)

    private readonly Stream control;
    private readonly Socket udp;
    private readonly CancellationTokenSource closed = new();

    private Socks5UdpAssociation(Stream control, Socket udp, IPEndPoint relayEndpoint)
    {
        this.control = control;
        this.udp = udp;
        RelayEndpoint = relayEndpoint;
        Closed = WatchControlConnectionAsync();
    }

    /// <summary>The proxy's UDP relay endpoint.</summary>
    public IPEndPoint RelayEndpoint { get; }

    /// <summary>Completes when the proxy closes the control connection, which ends the association.</summary>
    public Task Closed { get; }

    /// <summary>Opens an association through a single SOCKS5 <paramref name="hop"/>.</summary>
    /// <exception cref="ProxyException">The proxy refused or failed.</exception>
    public static async Task<Socks5UdpAssociation> CreateAsync(ProxyHop hop, ITcpConnector connector, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hop);
        ArgumentNullException.ThrowIfNull(connector);
        if (hop.Type != ProxyType.Socks5)
        {
            throw new ProxyException(ProxyFailure.Unsupported, $"{hop.Type} proxies cannot carry UDP.", hop.Id);
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var token = timeoutSource.Token;
        Stream? control = null;
        Socket? udp = null;
        try
        {
            try
            {
                control = await connector.ConnectAsync(hop.Endpoint, token).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                throw new ProxyException(ProxyFailure.ConnectFailed, $"Could not connect to proxy at {hop.Endpoint}: {ex.Message}", innerException: ex);
            }

            await Socks5Protocol.NegotiateAuthenticationAsync(control, hop.Credentials, token).ConfigureAwait(false);
            await control.WriteAsync(Socks5Protocol.BuildUdpAssociateRequest(), token).ConfigureAwait(false);
            var bound = await Socks5Protocol.ReadReplyAsync(control, "UDP ASSOCIATE", token).ConfigureAwait(false);

            // Many proxies answer 0.0.0.0 ("same address as the control connection").
            var proxyAddress = (control as NetworkStream)?.Socket.RemoteEndPoint is IPEndPoint remote ? remote.Address.Normalize() : null;
            var relayAddress = bound is null || bound.Address.Equals(IPAddress.Any) || bound.Address.Equals(IPAddress.IPv6Any)
                ? proxyAddress ?? throw new ProxyException(ProxyFailure.ProtocolError, "The SOCKS5 proxy did not say where to send UDP datagrams.")
                : bound.Address.Normalize();
            var relayEndpoint = new IPEndPoint(relayAddress, bound?.Port ?? 0);
            if (relayEndpoint.Port == 0)
            {
                throw new ProxyException(ProxyFailure.ProtocolError, "The SOCKS5 proxy returned no UDP relay port.");
            }

            udp = new Socket(relayEndpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            await udp.ConnectAsync(relayEndpoint, token).ConfigureAwait(false);
            return new Socks5UdpAssociation(control, udp, relayEndpoint);
        }
        catch (Exception ex)
        {
            udp?.Dispose();
            if (control is not null)
            {
                await control.DisposeAsync().ConfigureAwait(false);
            }

            throw ex switch
            {
                ProxyException proxy => proxy.WithHop(hop.Id),
                OperationCanceledException when !cancellationToken.IsCancellationRequested =>
                    new ProxyException(ProxyFailure.Timeout, $"Timed out after {timeout.TotalSeconds:0.#}s.", innerException: ex).WithHop(hop.Id),
                IOException or SocketException =>
                    new ProxyException(ProxyFailure.ProtocolError, $"UDP ASSOCIATE failed: {ex.Message}", innerException: ex).WithHop(hop.Id),
                _ => ex,
            };
        }
    }

    /// <summary>Sends <paramref name="payload"/> to <paramref name="destination"/> through the proxy.</summary>
    public async ValueTask SendAsync(TargetEndpoint destination, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var address = Socks5Protocol.EncodeAddress(destination);
        var datagram = new byte[HeaderReserved + address.Length + payload.Length];
        address.CopyTo(datagram, HeaderReserved);
        payload.Span.CopyTo(datagram.AsSpan(HeaderReserved + address.Length));
        await udp.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives the next datagram from the proxy into <paramref name="buffer"/>. Returns its source and the payload
    /// (a slice of <paramref name="buffer"/>). Fragmented or malformed datagrams are skipped.
    /// </summary>
    public async ValueTask<(TargetEndpoint Source, Memory<byte> Payload)> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            var length = await udp.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            var datagram = buffer[..length];
            if (length <= HeaderReserved || datagram.Span[2] != 0)
            {
                continue;
            }

            var addressLength = Socks5Protocol.TryDecodeAddress(datagram.Span[HeaderReserved..], out var source);
            if (addressLength > 0)
            {
                return (source!, datagram[(HeaderReserved + addressLength)..]);
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await closed.CancelAsync().ConfigureAwait(false);
        udp.Dispose();
        await control.DisposeAsync().ConfigureAwait(false);
        await Closed.ConfigureAwait(false);
        closed.Dispose();
    }

    private async Task WatchControlConnectionAsync()
    {
        var buffer = new byte[64];
        try
        {
            while (await control.ReadAsync(buffer, closed.Token).ConfigureAwait(false) > 0)
            {
                // The proxy sends nothing on the control connection; ignore anything it does send.
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Closed or disposed.
        }
    }
}
