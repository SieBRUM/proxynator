using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>SOCKS4 and SOCKS4a <c>CONNECT</c>.</summary>
/// <param name="allowHostnames">Use the SOCKS4a extension to send hostnames to the proxy.</param>
/// <param name="userId">The SOCKS4 user ID (may be empty).</param>
public sealed class Socks4Protocol(bool allowHostnames, string userId) : IProxyProtocol
{
    private const byte Version = 4;
    private const byte CommandConnect = 1;
    private const byte RequestGranted = 90;

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(target);

        byte[] address;
        byte[]? hostBytes = null;
        if (allowHostnames && target.Host is { } host)
        {
            address = [0, 0, 0, 1];
            hostBytes = Encoding.ASCII.GetBytes(host);
        }
        else if (target.Address is { } targetAddress)
        {
            if (targetAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ProxyException(ProxyFailure.Unsupported, $"SOCKS4 cannot connect to IPv6 address {targetAddress}.");
            }

            address = targetAddress.GetAddressBytes();
        }
        else
        {
            address = (await ResolveIPv4Async(target.Host!, cancellationToken).ConfigureAwait(false)).GetAddressBytes();
        }

        var userIdBytes = Encoding.UTF8.GetBytes(userId);
        var request = new byte[8 + userIdBytes.Length + 1 + (hostBytes is null ? 0 : hostBytes.Length + 1)];
        request[0] = Version;
        request[1] = CommandConnect;
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), (ushort)target.Port);
        address.CopyTo(request, 4);
        userIdBytes.CopyTo(request, 8);
        hostBytes?.CopyTo(request, 8 + userIdBytes.Length + 1);

        await transport.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var reply = new byte[8];
        await transport.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
        if (reply[0] is not (0 or Version))
        {
            throw new ProxyException(ProxyFailure.ProtocolError, $"Unexpected SOCKS4 reply version {reply[0]}.");
        }

        if (reply[1] != RequestGranted)
        {
            throw new ProxyException(ProxyFailure.Rejected, $"SOCKS4 proxy rejected the connection to {target} (code {reply[1]}).");
        }

        return transport;
    }

    private static async Task<IPAddress> ResolveIPv4Async(string host, CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await System.Net.Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new ProxyException(ProxyFailure.HostResolutionFailed, $"Could not resolve '{host}' for SOCKS4: {ex.Message}", innerException: ex);
        }

        return addresses.Length > 0
            ? addresses[0]
            : throw new ProxyException(ProxyFailure.HostResolutionFailed, $"'{host}' has no IPv4 address for SOCKS4.");
    }
}
