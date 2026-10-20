using System.Buffers.Binary;
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
    private const byte AddressIPv4 = 1;
    private const byte AddressDomain = 3;
    private const byte AddressIPv6 = 4;

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(target);

        await NegotiateAuthenticationAsync(transport, cancellationToken).ConfigureAwait(false);
        await transport.WriteAsync(BuildConnectRequest(target), cancellationToken).ConfigureAwait(false);
        await ReadConnectReplyAsync(transport, target, cancellationToken).ConfigureAwait(false);
        return transport;
    }

    internal static byte[] BuildConnectRequest(TargetEndpoint target)
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

        var request = new byte[3 + address.Length + 2];
        request[0] = Version;
        request[1] = CommandConnect;
        address.CopyTo(request, 3);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(3 + address.Length), (ushort)target.Port);
        return request;
    }

    private async Task NegotiateAuthenticationAsync(Stream transport, CancellationToken cancellationToken)
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

    private static async Task ReadConnectReplyAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await transport.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        if (header[0] != Version)
        {
            throw new ProxyException(ProxyFailure.ProtocolError, $"Unexpected SOCKS5 reply version {header[0]}.");
        }

        if (header[1] != 0)
        {
            throw new ProxyException(ProxyFailure.Rejected, $"SOCKS5 proxy refused the connection to {target}: {DescribeReply(header[1])}.");
        }

        // Skip the bound address and port.
        var remaining = header[3] switch
        {
            AddressIPv4 => 4 + 2,
            AddressIPv6 => 16 + 2,
            AddressDomain => await ReadByteAsync(transport, cancellationToken).ConfigureAwait(false) + 2,
            _ => throw new ProxyException(ProxyFailure.ProtocolError, $"Unknown SOCKS5 address type {header[3]} in reply."),
        };
        await transport.ReadExactlyAsync(new byte[remaining], cancellationToken).ConfigureAwait(false);
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
