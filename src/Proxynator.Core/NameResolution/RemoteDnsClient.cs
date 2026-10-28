using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Proxies;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// Sends DNS queries for remote domains to <see cref="DnsSettings.RemoteServer"/> as DNS over TCP through its proxy
/// route. This is how the SRV lookups of Active Directory tools (<c>_ldap._tcp.dc._msdcs.corp.local</c>,
/// <c>_kerberos._tcp.corp.local</c>) reach a domain controller behind a pivot; their A lookups get fake addresses.
/// With <see cref="RemoteDnsServer.ResolveNames"/>, the relay also resolves those names here (<see cref="ResolveAsync"/>).
/// Successful answers are kept in <paramref name="cache"/> for <see cref="DnsSettings.CacheSeconds"/>: a connection
/// storm must not become a DNS storm through a slow tunnel.
/// </summary>
public sealed partial class RemoteDnsClient(ProxyRouteDialer dialer, ILogger logger, DnsCache? cache = null)
{
    private const int MaxResponse = 65535;
    private const byte ResponseCodeMask = 0x0F;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly DnsCache cache = cache ?? new DnsCache();

    /// <summary>The cache answers are kept in.</summary>
    public DnsCache Cache => cache;

    /// <summary>
    /// Whether <paramref name="query"/> goes to the remote server: remote DNS mode, a remote server is configured, the
    /// name is a remote domain, and the query type is not one the fake responder answers (A, AAAA, SVCB, HTTPS).
    /// </summary>
    public static bool Handles(ActiveConfiguration active, ReadOnlySpan<byte> query)
    {
        ArgumentNullException.ThrowIfNull(active);
        var dns = active.Settings.Dns;
        return dns.Mode == DnsMode.Remote && dns.RemoteServer is not null &&
               DnsWire.TryParseQuery(query, out var question) && question.Class == DnsWire.ClassIn &&
               question.Type is not (DnsWire.TypeA or DnsWire.TypeAaaa or DnsWire.TypeSvcb or DnsWire.TypeHttps) &&
               active.ShouldFakeResolve(question.Name);
    }

    /// <summary>
    /// Asks the remote server; returns its response, or a SERVFAIL response when it cannot be reached. Answers with
    /// response code NOERROR or NXDOMAIN come from the cache while they are fresh (with the query's ID).
    /// </summary>
    public async Task<byte[]> QueryAsync(ActiveConfiguration active, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(active);
        var server = active.Settings.Dns.RemoteServer ?? throw new InvalidOperationException("No remote DNS server is configured.");
        var lifetime = DnsCache.Lifetime(active.Settings.Dns);
        string? key = null;
        if (DnsWire.TryParseQuery(query.Span, out var question))
        {
            key = $"remote-query {ServerKey(server)} {question.Type}/{question.Class} {Normalize(question.Name)}";
            if (cache.TryGet<byte[]>(key, lifetime, out var cached))
            {
                var answer = cached.ToArray();
                query.Span[..2].CopyTo(answer); // the ID of this query
                return answer;
            }
        }

        var response = await ExchangeAsync(active, server, query, cancellationToken).ConfigureAwait(false);
        if (key is not null && response.Length > 12 && (response[3] & ResponseCodeMask) is 0 or 3)
        {
            cache.Set(key, response.ToArray(), lifetime);
        }

        return response;
    }

    private async Task<byte[]> ExchangeAsync(ActiveConfiguration active, RemoteDnsServer server, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        var target = TargetEndpoint.FromAddress(IPAddress.Parse(server.Address), server.Port);
        try
        {
            var route = active.Routes[server.Via];
            var stream = await dialer.ConnectAsync(route, target, Timeout, cancellationToken).ConfigureAwait(false);
            await using var owned = stream.ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(Timeout);

            var request = new byte[2 + query.Length];
            BinaryPrimitives.WriteUInt16BigEndian(request, (ushort)query.Length);
            query.CopyTo(request.AsMemory(2));
            await stream.WriteAsync(request, timeout.Token).ConfigureAwait(false);

            var header = new byte[2];
            await stream.ReadExactlyAsync(header, timeout.Token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt16BigEndian(header);
            var response = new byte[length];
            await stream.ReadExactlyAsync(response, timeout.Token).ConfigureAwait(false);
            return response.Length <= MaxResponse ? response : ServerFailure(query.Span);
        }
        catch (Exception ex) when (ex is ProxyException or IOException or System.Net.Sockets.SocketException ||
                                   (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            Log.Failed(logger, target.ToString(), server.Via, ex.Message);
            return ServerFailure(query.Span);
        }
    }

    /// <summary>
    /// The IPv4 address of <paramref name="name"/> according to the remote server (an A query through its route), or
    /// <see langword="null"/> when it has none or cannot be reached. Addresses are cached (failures are not).
    /// </summary>
    public async Task<IPAddress?> ResolveAsync(ActiveConfiguration active, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(active);
        ArgumentException.ThrowIfNullOrEmpty(name);
        var server = active.Settings.Dns.RemoteServer ?? throw new InvalidOperationException("No remote DNS server is configured.");
        var lifetime = DnsCache.Lifetime(active.Settings.Dns);
        var key = $"remote-address {ServerKey(server)} {Normalize(name)}";
        if (cache.TryGet<IPAddress>(key, lifetime, out var cached))
        {
            return cached;
        }

        var id = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        // Not through QueryAsync's cache: an empty answer must not stick; only addresses are cached here.
        var response = await ExchangeAsync(active, server, DnsWire.BuildQuery(id, name, DnsWire.TypeA), cancellationToken).ConfigureAwait(false);
        if (!DnsWire.TryParseAddresses(response, id, out var addresses, out var responseCode) ||
            addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) is not { } address)
        {
            Log.NoAddress(logger, name, $"{server.Address}:{server.Port}", server.Via, responseCode);
            return null;
        }

        cache.Set(key, address, lifetime);
        return address;
    }

    private static string ServerKey(RemoteDnsServer server) => $"{server.Address}:{server.Port} via {server.Via}";

    private static string Normalize(string name) => name.TrimEnd('.').ToUpperInvariant();

    /// <summary>A SERVFAIL response to <paramref name="query"/> (same ID and question).</summary>
    internal static byte[] ServerFailure(ReadOnlySpan<byte> query)
    {
        if (!DnsWire.TryParseQuery(query, out var question))
        {
            return [];
        }

        var response = query[..question.End].ToArray();
        response[2] = (byte)(0x80 | (query[2] & 0x01)); // QR, RD echoed
        response[3] = 0x82; // RA, RCODE 2 (SERVFAIL)
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4), 1); // QDCOUNT
        response.AsSpan(6, 6).Clear(); // ANCOUNT, NSCOUNT, ARCOUNT
        return response;
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1310, Level = LogLevel.Warning, Message = "The remote DNS server {Server} via '{Via}' did not answer: {Reason}")]
        public static partial void Failed(ILogger logger, string server, string via, string reason);

        [LoggerMessage(EventId = 1311, Level = LogLevel.Warning, Message = "The remote DNS server {Server} via '{Via}' has no IPv4 address for {Name} (response code {ResponseCode})")]
        public static partial void NoAddress(ILogger logger, string name, string server, string via, int responseCode);
    }
}
