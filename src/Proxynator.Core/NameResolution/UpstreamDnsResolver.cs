using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Proxynator.Core.Net;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// Resolves names by sending DNS queries straight to the upstream servers. Used while fake-IP DNS is active: going
/// through the system resolver would return Proxynator's own fake answers.
/// </summary>
public sealed class UpstreamDnsResolver(IReadOnlyList<IPEndPoint> servers, TimeSpan? timeout = null) : IHostResolver
{
    private readonly TimeSpan timeout = timeout ?? TimeSpan.FromSeconds(2);

    /// <summary>The DNS servers queried, in order.</summary>
    public IReadOnlyList<IPEndPoint> Servers { get; } = servers;

    /// <summary>The DNS servers configured on the machine's active interfaces, excluding <paramref name="exclude"/>.</summary>
    public static IReadOnlyList<IPEndPoint> DiscoverSystemServers(AddressRange? exclude = null)
    {
        var result = new List<IPEndPoint>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var address in networkInterface.GetIPProperties().DnsAddresses)
            {
                var endpoint = new IPEndPoint(address.Normalize(), 53);
                if (!address.IsIPv6SiteLocal && exclude?.Contains(address) != true && !result.Contains(endpoint))
                {
                    result.Add(endpoint);
                }
            }
        }

        return result;
    }

    /// <inheritdoc />
    public async ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        foreach (var type in new[] { DnsWire.TypeA, DnsWire.TypeAaaa })
        {
            foreach (var server in Servers)
            {
                var (answered, addresses) = await QueryAsync(server, host, type, cancellationToken).ConfigureAwait(false);
                if (addresses.Count > 0)
                {
                    return [.. addresses];
                }

                if (answered)
                {
                    break; // an authoritative "no such record" from this server; try the next type
                }
            }
        }

        throw new SocketException((int)SocketError.HostNotFound);
    }

    private async Task<(bool Answered, List<IPAddress> Addresses)> QueryAsync(IPEndPoint server, string host, ushort type, CancellationToken cancellationToken)
    {
        var id = (ushort)Random.Shared.Next(ushort.MaxValue);
        byte[] query;
        try
        {
            query = DnsWire.BuildQuery(id, host, type);
        }
        catch (ArgumentException)
        {
            return (true, []);
        }

        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var buffer = new byte[4096];
        try
        {
            await socket.ConnectAsync(server, deadline.Token).ConfigureAwait(false);
            await socket.SendAsync(query, deadline.Token).ConfigureAwait(false);
            while (true)
            {
                var length = await socket.ReceiveAsync(buffer, deadline.Token).ConfigureAwait(false);
                if (DnsWire.TryParseAddresses(buffer.AsSpan(0, length), id, out var addresses, out _))
                {
                    return (true, addresses);
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (false, []); // timed out: try the next server
        }
        catch (SocketException)
        {
            return (false, []);
        }
    }
}
