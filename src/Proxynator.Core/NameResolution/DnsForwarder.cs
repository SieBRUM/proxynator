using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// A local DNS server for captured programs in <see cref="DnsMode.Remote"/>: names in <c>remoteDomains</c> get fake
/// answers from the <see cref="FakeIpPool"/>, everything else is forwarded to the service's own DNS servers. Used
/// by backends that can redirect the DNS queries of chosen processes only (Linux eBPF), which makes remote DNS
/// per process instead of machine-wide. Other lookups of remote domains (SRV, ...) go to
/// <see cref="DnsSettings.RemoteServer"/> through its proxy when one is configured.
/// </summary>
public sealed partial class DnsForwarder : IAsyncDisposable
{
    private const int MaxDatagram = 4096;
    private static readonly TimeSpan UpstreamTimeout = TimeSpan.FromSeconds(3);

    private readonly ConfigurationStore configuration;
    private readonly FakeDnsResponder responder;
    private readonly IReadOnlyList<IPEndPoint> upstream;
    private readonly ILogger logger;
    private readonly RemoteDnsClient remoteDns;
    private readonly CancellationTokenSource shutdown = new();
    private readonly List<Socket> listeners = [];
    private readonly List<Task> loops = [];

    /// <summary>Creates the forwarder.</summary>
    /// <param name="configuration">The configuration store (DNS mode, remote domains, remote server).</param>
    /// <param name="fakeIps">The fake-IP pool.</param>
    /// <param name="upstream">The service's own DNS servers, for names that are not faked.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="connector">Opens connections to proxies, for <see cref="DnsSettings.RemoteServer"/>.</param>
    public DnsForwarder(ConfigurationStore configuration, FakeIpPool fakeIps, IReadOnlyList<IPEndPoint> upstream, ILogger logger, Net.ITcpConnector? connector = null)
    {
        this.configuration = configuration;
        responder = new FakeDnsResponder(fakeIps);
        this.upstream = upstream;
        this.logger = logger;
        remoteDns = new RemoteDnsClient(new Proxies.ProxyRouteDialer(connector ?? Net.TcpConnector.Default), logger);
    }

    /// <summary>The bound endpoints (actual ports).</summary>
    public IReadOnlyList<IPEndPoint> LocalEndpoints { get; private set; } = [];

    /// <summary>Binds the listeners and starts answering.</summary>
    public void Start(IEnumerable<IPEndPoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var bound = new List<IPEndPoint>();
        foreach (var endpoint in endpoints)
        {
            var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.Bind(endpoint);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                Log.BindFailed(logger, endpoint, ex.Message);
                continue;
            }

            listeners.Add(socket);
            bound.Add((IPEndPoint)socket.LocalEndPoint!);
            loops.Add(ServeAsync(socket, shutdown.Token));
        }

        LocalEndpoints = bound;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await shutdown.CancelAsync().ConfigureAwait(false);
        foreach (var listener in listeners)
        {
            listener.Dispose();
        }

        await Task.WhenAll(loops).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        shutdown.Dispose();
    }

    private async Task ServeAsync(Socket listener, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxDatagram];
        EndPoint any = listener.AddressFamily == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await listener.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
            {
                continue;
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }

            var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            var client = (IPEndPoint)received.RemoteEndPoint;
            var active = configuration.Current;
            var answer = active.Settings.Dns.Mode == DnsMode.Remote ? responder.TryAnswer(query, active.ShouldFakeResolve) : null;
            if (answer is not null)
            {
                await ReplyAsync(listener, answer, client, cancellationToken).ConfigureAwait(false);
                continue;
            }

            _ = active.Settings.Dns.Mode == DnsMode.Remote && RemoteDnsClient.Handles(active, query)
                ? AnswerRemotelyAsync(listener, active, query, client, cancellationToken)
                : ForwardAsync(listener, query, client, cancellationToken);
        }
    }

    private async Task ForwardAsync(Socket listener, byte[] query, IPEndPoint client, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxDatagram];
        foreach (var server in upstream)
        {
            using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(UpstreamTimeout);
            try
            {
                await socket.ConnectAsync(server, timeout.Token).ConfigureAwait(false);
                await socket.SendAsync(query, timeout.Token).ConfigureAwait(false);
                var length = await socket.ReceiveAsync(buffer, timeout.Token).ConfigureAwait(false);
                await ReplyAsync(listener, buffer.AsMemory(0, length), client, cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (ex is SocketException || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // Try the next server.
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
        }

        Log.ForwardFailed(logger, upstream.Count);
    }

    private async Task AnswerRemotelyAsync(Socket listener, ActiveConfiguration active, byte[] query, IPEndPoint client, CancellationToken cancellationToken)
    {
        var answer = await remoteDns.QueryAsync(active, query, cancellationToken).ConfigureAwait(false);
        await ReplyAsync(listener, answer, client, cancellationToken).ConfigureAwait(false);
    }

    private static async Task ReplyAsync(Socket listener, ReadOnlyMemory<byte> answer, IPEndPoint client, CancellationToken cancellationToken)
    {
        try
        {
            await listener.SendToAsync(answer, SocketFlags.None, client, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // The client is gone or the service is stopping.
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1300, Level = LogLevel.Warning, Message = "The DNS forwarder cannot listen on {Endpoint}: {Reason}")]
        public static partial void BindFailed(ILogger logger, IPEndPoint endpoint, string reason);

        [LoggerMessage(EventId = 1301, Level = LogLevel.Debug, Message = "A DNS query could not be forwarded ({Servers} server(s) tried)")]
        public static partial void ForwardFailed(ILogger logger, int servers);
    }
}
