using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Proxies;
using Proxynator.Core.Rules;

namespace Proxynator.Core.Relay;

/// <summary>
/// The UDP counterpart of <see cref="RelayServer"/>. Capture backends redirect UDP flows to it the same way (the
/// datagram's source is the key in its <see cref="IOriginalDestinationTable"/>). Each flow becomes a session that
/// sends datagrams directly, through a SOCKS5 UDP association, to the fake-IP DNS responder, or nowhere (blocked),
/// and returns replies to the client. Idle sessions expire.
/// </summary>
public sealed partial class UdpRelayServer : IAsyncDisposable
{
    private const int MaxDatagram = 65_535;
    private const int QueueLength = 256;
    private const int SioUdpConnectionReset = -1744830452;
    // Longer than the capture NAT's UDP idle timeouts, so a NAT entry never outlives its session.
    private static readonly TimeSpan SessionIdleTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan DnsSessionIdleTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(5);

    private readonly ConfigurationStore configuration;
    private readonly IOriginalDestinationTable destinations;
    private readonly IProcessInfoProvider processes;
    private readonly ConnectionTracker tracker;
    private readonly ILogger logger;
    private readonly FakeIpPool? fakeIps;
    private readonly IHostResolver resolver;
    private readonly ITcpConnector connector;
    private readonly RemoteDnsClient remoteDns;
    private readonly TimeProvider time;
    private readonly ConcurrentDictionary<IPEndPoint, UdpSession> sessions = new();
    private readonly CancellationTokenSource shutdown = new();
    private readonly List<Socket> sockets = [];
    private readonly List<Task> receiveLoops = [];
    private ITimer? sweeper;

    /// <summary>Creates the UDP relay.</summary>
    public UdpRelayServer(
        ConfigurationStore configuration,
        IOriginalDestinationTable destinations,
        IProcessInfoProvider processes,
        ConnectionTracker tracker,
        ILogger<UdpRelayServer> logger,
        FakeIpPool? fakeIps = null,
        IHostResolver? resolver = null,
        ITcpConnector? connector = null,
        TimeProvider? timeProvider = null)
    {
        this.configuration = configuration;
        this.destinations = destinations;
        this.processes = processes;
        this.tracker = tracker;
        this.logger = logger;
        this.fakeIps = fakeIps;
        this.resolver = resolver ?? SystemHostResolver.Instance;
        this.connector = connector ?? TcpConnector.Default;
        remoteDns = new RemoteDnsClient(new ProxyRouteDialer(this.connector), logger);
        time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The bound endpoints (with actual ports).</summary>
    public IReadOnlyList<IPEndPoint> LocalEndpoints { get; private set; } = [];

    /// <summary>The number of active sessions.</summary>
    public int SessionCount => sessions.Count;

    /// <summary>The destination port treated as DNS in remote mode. Overridable for tests (port 53 needs privileges).</summary>
    internal int DnsPort { get; init; } = 53;

    /// <summary>Binds the sockets and starts relaying. <see cref="IPAddress.IPv6Any"/> binds dual-mode.</summary>
    public void Start(IEnumerable<IPEndPoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var bound = new List<IPEndPoint>();
        foreach (var endpoint in endpoints)
        {
            var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            sockets.Add(socket);
            if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = endpoint.Address.Equals(IPAddress.IPv6Any);
            }

            if (OperatingSystem.IsWindows())
            {
                // Otherwise an ICMP "port unreachable" for one client makes the next ReceiveFrom fail.
                socket.IOControl(SioUdpConnectionReset, [0, 0, 0, 0], null);
            }

            socket.Bind(endpoint);
            bound.Add((IPEndPoint)socket.LocalEndPoint!);
        }

        LocalEndpoints = bound;
        foreach (var socket in sockets)
        {
            Log.Listening(logger, (IPEndPoint)socket.LocalEndPoint!);
            receiveLoops.Add(ReceiveLoopAsync(socket, shutdown.Token));
        }

        sweeper = time.CreateTimer(_ => SweepIdleSessions(), null, SweepInterval, SweepInterval);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (shutdown.IsCancellationRequested)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        if (sweeper is not null)
        {
            await sweeper.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var socket in sockets)
        {
            socket.Dispose();
        }

        await Task.WhenAll(receiveLoops).ConfigureAwait(false);
        foreach (var key in sessions.Keys)
        {
            if (sessions.TryRemove(key, out var session))
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }

        shutdown.Dispose();
    }

    /// <summary>Closes sessions idle for longer than their timeout. Exposed for tests.</summary>
    internal void SweepIdleSessions()
    {
        var now = time.GetUtcNow();
        foreach (var (key, session) in sessions)
        {
            if (now - session.LastActivity > session.IdleTimeout && sessions.TryRemove(key, out _))
            {
                _ = session.DisposeAsync().AsTask();
            }
        }
    }

    private async Task ReceiveLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxDatagram];
        EndPoint any = socket.AddressFamily == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
        while (!cancellationToken.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                continue; // e.g. ICMP errors reported on the socket
            }

            var client = ((IPEndPoint)result.RemoteEndPoint).Normalize();
            var datagram = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
            if (!sessions.TryGetValue(client, out var session))
            {
                if (!destinations.TryTake(client, out var original))
                {
                    Log.UnknownClient(logger, client);
                    continue;
                }

                session = CreateSession(socket, client, original);
                sessions[client] = session;
                session.Start();
            }

            session.Enqueue(datagram);
        }
    }

    private UdpSession CreateSession(Socket socket, IPEndPoint client, OriginalDestination original)
    {
        var active = configuration.Current;
        IPAddress? address = original.Destination.Address.Normalize();
        var hostname = original.Hostname;
        if (fakeIps?.Contains(address) == true)
        {
            if (hostname is null)
            {
                fakeIps.TryGetHostname(address, out hostname);
            }

            address = null;
        }

        var context = new ConnectionContext(
            processes.GetProcessInfo(original.ProcessId),
            TransportProtocol.Udp,
            address,
            hostname,
            original.Destination.Port);

        if (active.Settings.Dns.Mode == DnsMode.Remote && context.DestinationPort == DnsPort && fakeIps is not null && address is not null)
        {
            return new UdpSession(this, socket, client, context, SessionKind.Dns, route: null, tracked: null);
        }

        var decision = active.Rules.Evaluate(context);
        var (kind, route) = decision.Action switch
        {
            RuleActionType.Block => (SessionKind.Drop, null),
            RuleActionType.Direct => (SessionKind.Direct, null),
            _ when active.Settings.Udp.BlockQuic && context.DestinationPort == 443 => (SessionKind.Drop, null),
            _ when decision.Route is { Hops: [{ Type: ProxyType.Socks5 }] } => (SessionKind.Socks5, decision.Route),
            _ => decision.UdpFallback == UdpFallback.Direct ? (SessionKind.Direct, null) : (SessionKind.Drop, (ProxyRoute?)null),
        };

        var tracked = tracker.Open(context, decision);
        Log.SessionDecided(logger, tracked.Id, context.Process?.Name ?? "?", original.ProcessId, context.DestinationDisplay, decision.RuleName, kind);
        return new UdpSession(this, socket, client, context, kind, route, tracked);
    }

    private enum SessionKind
    {
        Direct,
        Socks5,
        Dns,
        Drop,
    }

    /// <summary>One redirected UDP flow.</summary>
    private sealed class UdpSession : IAsyncDisposable
    {
        private readonly UdpRelayServer relay;
        private readonly Socket relaySocket;
        private readonly IPEndPoint client;
        private readonly ConnectionContext context;
        private readonly SessionKind kind;
        private readonly ProxyRoute? route;
        private readonly TrackedConnection? tracked;
        private readonly Channel<byte[]> inbound = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(QueueLength) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
        private readonly CancellationTokenSource stop;
        private Task pump = Task.CompletedTask;
        private Socket? direct;
        private Socks5UdpAssociation? association;
        private long lastActivityTicks;
        private int disposed;

        public UdpSession(UdpRelayServer relay, Socket relaySocket, IPEndPoint client, ConnectionContext context, SessionKind kind, ProxyRoute? route, TrackedConnection? tracked)
        {
            this.relay = relay;
            this.relaySocket = relaySocket;
            this.client = client;
            this.context = context;
            this.kind = kind;
            this.route = route;
            this.tracked = tracked;
            stop = CancellationTokenSource.CreateLinkedTokenSource(relay.shutdown.Token);
            Touch();
        }

        public DateTimeOffset LastActivity => new(Interlocked.Read(ref lastActivityTicks), TimeSpan.Zero);

        public TimeSpan IdleTimeout => kind == SessionKind.Dns ? DnsSessionIdleTimeout : SessionIdleTimeout;

        public void Start() => pump = PumpAsync(stop.Token);

        public void Enqueue(byte[] datagram)
        {
            Touch();
            if (kind != SessionKind.Drop)
            {
                inbound.Writer.TryWrite(datagram);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            inbound.Writer.TryComplete();
            await stop.CancelAsync().ConfigureAwait(false);
            direct?.Dispose();
            if (association is not null)
            {
                await association.DisposeAsync().ConfigureAwait(false);
            }

            await pump.ConfigureAwait(false);
            stop.Dispose();
            if (tracked is not null)
            {
                relay.tracker.Close(tracked);
            }
        }

        private void Touch() => Interlocked.Exchange(ref lastActivityTicks, relay.time.GetUtcNow().UtcTicks);

        private async Task PumpAsync(CancellationToken cancellationToken)
        {
            try
            {
                switch (kind)
                {
                    case SessionKind.Direct:
                        direct = await OpenDirectAsync(cancellationToken).ConfigureAwait(false);
                        _ = ReceiveDirectAsync(direct, cancellationToken);
                        await foreach (var datagram in inbound.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                        {
                            await direct.SendAsync(datagram, cancellationToken).ConfigureAwait(false);
                            tracked?.AddSent(datagram.Length);
                        }

                        break;

                    case SessionKind.Socks5:
                        var timeout = TimeSpan.FromMilliseconds(relay.configuration.Current.Settings.Relay.ConnectTimeoutMs);
                        association = await Socks5UdpAssociation.CreateAsync(route!.Hops[0], relay.connector, timeout, cancellationToken).ConfigureAwait(false);
                        _ = ReceiveSocksAsync(association, cancellationToken);
                        var target = context.DestinationHost is { } host
                            ? TargetEndpoint.FromHost(host, context.DestinationPort, context.DestinationAddress)
                            : TargetEndpoint.FromAddress(context.DestinationAddress!, context.DestinationPort);
                        await foreach (var datagram in inbound.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                        {
                            await association.SendAsync(target, datagram, cancellationToken).ConfigureAwait(false);
                            tracked?.AddSent(datagram.Length);
                        }

                        break;

                    case SessionKind.Dns:
                        await ServeDnsAsync(cancellationToken).ConfigureAwait(false);
                        break;
                }
            }
            catch (ProxyException ex)
            {
                Log.SessionFailed(relay.logger, context.DestinationDisplay, ex.Message); // fail closed: datagrams are dropped
            }
            catch (Exception ex) when (ex is SocketException or IOException)
            {
                Log.SessionFailed(relay.logger, context.DestinationDisplay, ex.Message);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or ChannelClosedException)
            {
                // Session closed.
            }
        }

        private async Task<Socket> OpenDirectAsync(CancellationToken cancellationToken)
        {
            var address = context.DestinationAddress
                ?? (await relay.resolver.ResolveAsync(context.DestinationHost!, cancellationToken).ConfigureAwait(false))[0];
            var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                await socket.ConnectAsync(address, context.DestinationPort, cancellationToken).ConfigureAwait(false);
                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private async Task ServeDnsAsync(CancellationToken cancellationToken)
        {
            var responder = new FakeDnsResponder(relay.fakeIps!);
            await foreach (var query in inbound.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var active = relay.configuration.Current;
                var answer = responder.TryAnswer(query, active.ShouldFakeResolve);
                if (answer is not null)
                {
                    await ReplyAsync(answer, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                if (RemoteDnsClient.Handles(active, query))
                {
                    // SRV and other non-address lookups of remote domains: ask the DNS server behind the proxy.
                    _ = AnswerRemotelyAsync(active, query, cancellationToken);
                    continue;
                }

                // Not a name we fake: ask the real server (from the service, so it is not captured again).
                if (direct is null)
                {
                    direct = await OpenDirectAsync(cancellationToken).ConfigureAwait(false);
                    _ = ReceiveDirectAsync(direct, cancellationToken);
                }

                await direct.SendAsync(query, cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task AnswerRemotelyAsync(ActiveConfiguration active, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
        {
            try
            {
                await ReplyAsync(await relay.remoteDns.QueryAsync(active, query, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Session closed.
            }
        }

        private async Task ReceiveDirectAsync(Socket socket, CancellationToken cancellationToken)
        {
            var buffer = new byte[MaxDatagram];
            try
            {
                while (true)
                {
                    int length;
                    try
                    {
                        length = await socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        continue; // ICMP port unreachable from the destination; keep the session
                    }

                    await ReplyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Session closed.
            }
        }

        private async Task ReceiveSocksAsync(Socks5UdpAssociation socks, CancellationToken cancellationToken)
        {
            var buffer = new byte[MaxDatagram];
            try
            {
                while (true)
                {
                    var (_, payload) = await socks.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    await ReplyAsync(payload, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // Session closed.
            }
        }

        private async ValueTask ReplyAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            Touch();
            await relaySocket.SendToAsync(payload, SocketFlags.None, client, cancellationToken).ConfigureAwait(false);
            tracked?.AddReceived(payload.Length);
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 1100, Level = LogLevel.Information, Message = "UDP relay listening on {Endpoint}")]
        public static partial void Listening(ILogger logger, IPEndPoint endpoint);

        [LoggerMessage(EventId = 1101, Level = LogLevel.Debug, Message = "Dropping UDP datagram from {Client}: no original destination registered")]
        public static partial void UnknownClient(ILogger logger, IPEndPoint client);

        [LoggerMessage(EventId = 1102, Level = LogLevel.Information, Message = "#{ConnectionId} {Process} (pid {ProcessId}) -> udp {Destination}: rule '{Rule}' -> {Kind}")]
        public static partial void SessionDecided(ILogger logger, long connectionId, string process, int processId, string destination, string rule, SessionKind kind);

        [LoggerMessage(EventId = 1103, Level = LogLevel.Warning, Message = "UDP session to {Destination} failed; its datagrams are dropped: {Reason}")]
        public static partial void SessionFailed(ILogger logger, string destination, string reason);
    }
}
