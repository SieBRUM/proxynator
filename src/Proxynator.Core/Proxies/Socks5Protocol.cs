using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>SOCKS5 <c>CONNECT</c> (RFC 1928) with optional username/password authentication (RFC 1929).</summary>
public sealed class Socks5Protocol(ProxyCredentials? credentials) : IProxyProtocol
{
    private const byte Version = 5;
    private const byte MethodNoAuth = 0x00;
    private const byte MethodUserPass = 0x02;
    private const byte MethodNoneAcceptable = 0xFF;
    private const byte CommandConnect = 1;
    private const byte CommandUdpAssociate = 3;
    private const byte AddressIPv4 = 1;
    private const byte AddressDomain = 3;
    private const byte AddressIPv6 = 4;

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(target);

        await NegotiateAuthenticationAsync(transport, credentials, cancellationToken).ConfigureAwait(false);
        await transport.WriteAsync(BuildConnectRequest(target), cancellationToken).ConfigureAwait(false);
        await ReadReplyAsync(transport, $"the connection to {target}", cancellationToken).ConfigureAwait(false);
        return transport;
    }

    internal static byte[] BuildConnectRequest(TargetEndpoint target) => [Version, CommandConnect, 0, .. EncodeAddress(target)];

    /// <summary>UDP ASSOCIATE with an unspecified client address: the proxy accepts datagrams from any source port.</summary>
    internal static byte[] BuildUdpAssociateRequest() => [Version, CommandUdpAssociate, 0, AddressIPv4, 0, 0, 0, 0, 0, 0];

    /// <summary>ATYP, address and port, as used in requests, replies and UDP headers.</summary>
    internal static byte[] EncodeAddress(TargetEndpoint target)
    {
        byte[] address;
        if (target.Host is { } host)
        {
            var hostBytes = Encoding.ASCII.GetBytes(host);
            address = [AddressDomain, (byte)hostBytes.Length, .. hostBytes];
        }
        else if (target.Address!.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address = [AddressIPv6, .. target.Address.GetAddressBytes()];
        }
        else
        {
            address = [AddressIPv4, .. target.Address.GetAddressBytes()];
        }

        return [.. address, (byte)(target.Port >> 8), (byte)target.Port];
    }

    /// <summary>Decodes ATYP, address and port; returns the number of bytes used, or 0 if malformed.</summary>
    internal static int TryDecodeAddress(ReadOnlySpan<byte> data, out TargetEndpoint? endpoint)
    {
        endpoint = null;
        if (data.IsEmpty)
        {
            return 0;
        }

        int addressLength, offset;
        switch (data[0])
        {
            case AddressIPv4:
                (offset, addressLength) = (1, 4);
                break;
            case AddressIPv6:
                (offset, addressLength) = (1, 16);
                break;
            case AddressDomain when data.Length > 1:
                (offset, addressLength) = (2, data[1]);
                break;
            default:
                return 0;
        }

        if (data.Length < offset + addressLength + 2)
        {
            return 0;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + addressLength)..]);
        if (port == 0)
        {
            return 0;
        }

        var address = data.Slice(offset, addressLength);
        try
        {
            endpoint = data[0] == AddressDomain
                ? TargetEndpoint.FromHost(Encoding.ASCII.GetString(address), port)
                : TargetEndpoint.FromAddress(new IPAddress(address), port);
        }
        catch (ArgumentException)
        {
            return 0;
        }

        return offset + addressLength + 2;
    }

    internal static async Task NegotiateAuthenticationAsync(Stream transport, ProxyCredentials? credentials, CancellationToken cancellationToken)
    {
        byte[] greeting = credentials is null
            ? [Version, 1, MethodNoAuth]
            : [Version, 2, MethodNoAuth, MethodUserPass];
        await transport.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);

        var choice = new byte[2];
        await transport.ReadExactlyAsync(choice, cancellationToken).ConfigureAwait(false);
        if (choice[0] != Version)
        {
            throw new ProxyException(ProxyFailure.ProtocolError, $"Unexpected SOCKS5 version {choice[0]} in method selection.");
        }

        switch (choice[1])
        {
            case MethodNoAuth:
                return;
            case MethodUserPass when credentials is not null:
                await AuthenticateAsync(transport, credentials, cancellationToken).ConfigureAwait(false);
                return;
            case MethodNoneAcceptable:
                throw new ProxyException(
                    ProxyFailure.AuthenticationFailed,
                    credentials is null
                        ? "The SOCKS5 proxy requires authentication but no credentials are configured."
                        : "The SOCKS5 proxy accepted none of the offered authentication methods.");
            default:
                throw new ProxyException(ProxyFailure.ProtocolError, $"The SOCKS5 proxy selected unsupported method {choice[1]}.");
        }
    }

    private static async Task AuthenticateAsync(Stream transport, ProxyCredentials credentials, CancellationToken cancellationToken)
    {
        var user = Encoding.UTF8.GetBytes(credentials.Username);
        var password = Encoding.UTF8.GetBytes(credentials.Password);
        if (user.Length > 255 || password.Length > 255)
        {
            throw new ProxyException(ProxyFailure.Unsupported, "SOCKS5 user names and passwords are limited to 255 bytes.");
        }

        byte[] request = [1, (byte)user.Length, .. user, (byte)password.Length, .. password];
        await transport.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var reply = new byte[2];
        await transport.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
        if (reply[1] != 0)
        {
            throw new ProxyException(ProxyFailure.AuthenticationFailed, "The SOCKS5 proxy rejected the username/password.");
        }
    }

    /// <summary>Reads a reply; returns the bound address (null for a domain), or throws if the request was refused.</summary>
    internal static async Task<IPEndPoint?> ReadReplyAsync(Stream transport, string what, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await transport.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        if (header[0] != Version)
        {
            throw new ProxyException(ProxyFailure.ProtocolError, $"Unexpected SOCKS5 reply version {header[0]}.");
        }

        if (header[1] != 0)
        {
            throw new ProxyException(ProxyFailure.Rejected, $"SOCKS5 proxy refused {what}: {DescribeReply(header[1])}.");
        }

        var remaining = header[3] switch
        {
            AddressIPv4 => 4 + 2,
            AddressIPv6 => 16 + 2,
            AddressDomain => await ReadByteAsync(transport, cancellationToken).ConfigureAwait(false) + 2,
            _ => throw new ProxyException(ProxyFailure.ProtocolError, $"Unknown SOCKS5 address type {header[3]} in reply."),
        };
        var bound = new byte[remaining];
        await transport.ReadExactlyAsync(bound, cancellationToken).ConfigureAwait(false);
        if (header[3] == AddressDomain)
        {
            return null;
        }

        return new IPEndPoint(new IPAddress(bound.AsSpan(0, remaining - 2)), BinaryPrimitives.ReadUInt16BigEndian(bound.AsSpan(remaining - 2)));
    }

    private static async Task<int> ReadByteAsync(Stream transport, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        await transport.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer[0];
    }

    private static string DescribeReply(byte code) => code switch
    {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => $"error code {code}",
    };
}
