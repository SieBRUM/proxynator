using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Proxies;
using Proxynator.Core.Rules;

namespace Proxynator.Core.Relay;

/// <summary>
/// The local relay that capture backends redirect connections to. For each accepted connection it looks up the
/// original destination, evaluates the rules (sniffing the hostname first when useful), connects upstream directly
/// or through the selected proxy route, and pumps data both ways. If a proxy route fails, the client connection is
/// reset; it is never silently sent direct.
/// </summary>
public sealed class RelayServer : IAsyncDisposable
{
    private readonly ConfigurationStore configuration;
    private readonly IOriginalDestinationTable destinations;
    private readonly IProcessInfoProvider processes;
    private readonly ConnectionTracker tracker;
    private readonly ITcpConnector connector;
    private readonly ProxyRouteDialer dialer;
    private readonly RemoteDnsClient remoteDns;
    private readonly ILogger logger;
    private readonly FakeIpPool? fakeIps;
    private readonly CancellationTokenSource shutdown = new();
    private readonly List<Socket> listeners = [];
    private readonly List<Task> acceptLoops = [];
    private readonly ConcurrentDictionary<Task, byte> connections = new();
    private bool started;

    /// <summary>Creates the relay.</summary>
    /// <param name="configuration">The configuration store; read once per connection.</param>
    /// <param name="destinations">The table capture backends register redirected connections in.</param>
    /// <param name="processes">Process lookup for rule matching.</param>
    /// <param name="tracker">Receives the active connections.</param>
    /// <param name="logger">Logger.</param>
    /// <param name="connector">Opens upstream TCP connections; defaults to a <see cref="TcpConnector"/> using <paramref name="resolver"/>.</param>
    /// <param name="fakeIps">The fake-IP pool, when fake-IP DNS can be active; connections to its addresses are mapped back to hostnames.</param>
    /// <param name="resolver">Resolves hostnames for direct connections; defaults to the system resolver.</param>
    /// <param name="dnsCache">Keeps the remote DNS server's answers; shared with the rest of the service.</param>
    public RelayServer(
        ConfigurationStore configuration,
        IOriginalDestinationTable destinations,
        IProcessInfoProvider processes,
        ConnectionTracker tracker,
        ILogger<RelayServer> logger,
        ITcpConnector? connector = null,
        FakeIpPool? fakeIps = null,
        IHostResolver? resolver = null,
        DnsCache? dnsCache = null)
    {
        this.configuration = configuration;
        this.destinations = destinations;
        this.processes = processes;
        this.tracker = tracker;
        this.logger = logger;
        this.fakeIps = fakeIps;
        this.connector = connector ?? new TcpConnector(resolver: resolver);
        dialer = new ProxyRouteDialer(this.connector);
        remoteDns = new RemoteDnsClient(dialer, logger, dnsCache);
    }

    /// <summary>The endpoints the relay is listening on (with actual ports when port 0 was requested).</summary>
    public IReadOnlyList<IPEndPoint> LocalEndpoints { get; private set; } = [];

    /// <summary>
    /// Binds the listeners and starts accepting connections. <see cref="IPAddress.IPv6Any"/> listens dual-mode
    /// (IPv4 and IPv6).
    /// </summary>
    public void Start(IEnumerable<IPEndPoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (started)
        {
            throw new InvalidOperationException("The relay has already been started.");
        }

        started = true;
        var bound = new List<IPEndPoint>();
        try
        {
            foreach (var endpoint in endpoints)
            {
                var listener = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                listeners.Add(listener);
                if (endpoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    // [::] also accepts IPv4 (as mapped addresses, normalized on accept); specific IPv6 addresses don't.
                    listener.DualMode = endpoint.Address.Equals(IPAddress.IPv6Any);
                }

                listener.Bind(endpoint);
                listener.Listen(512);
                bound.Add((IPEndPoint)listener.LocalEndPoint!);
            }
        }
        catch
        {
            CloseListeners();
            throw;
        }

        LocalEndpoints = bound;
        foreach (var listener in listeners)
        {
            RelayLog.Listening(logger, (IPEndPoint)listener.LocalEndPoint!);
            acceptLoops.Add(AcceptLoopAsync(listener, shutdown.Token));
        }
    }

    /// <summary>Stops accepting, aborts active connections and waits for them to finish.</summary>
    public async ValueTask DisposeAsync()
    {
        if (shutdown.IsCancellationRequested)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        CloseListeners();
        await Task.WhenAll(acceptLoops).ConfigureAwait(false);
        await Task.WhenAll(connections.Keys).ConfigureAwait(false);
        shutdown.Dispose();
    }

    private void CloseListeners()
    {
        foreach (var listener in listeners)
        {
            listener.Dispose();
        }
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                RelayLog.AcceptFailed(logger, ex);
                continue;
            }

            var task = HandleClientAsync(client, cancellationToken);
            connections.TryAdd(task, 0);
            _ = task.ContinueWith(t => connections.TryRemove(t, out _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private async Task HandleClientAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        try
        {
            await RelayAsync(clientSocket, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Shutting down.
        }
#pragma warning disable CA1031 // One misbehaving connection must never take the relay down.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            RelayLog.UnexpectedError(logger, ex);
        }
        finally
        {
            clientSocket.Dispose();
        }
    }

    private async Task RelayAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        var peer = (clientSocket.RemoteEndPoint as IPEndPoint)?.Normalize();
        if (peer is null || !destinations.TryTake(peer, out var original))
        {
            RelayLog.UnknownClient(logger, peer);
            Reset(clientSocket);
            return;
        }

        var active = configuration.Current;
        var settings = active.Settings;
        IPAddress? address = original.Destination.Address.Normalize();
        var hostname = original.Hostname;
        var hostnameIsHint = original.HostnameIsHint;
        if (fakeIps?.Contains(address) == true)
        {
            // A fake-IP DNS answer: the hostname is the real destination; the address means nothing outside this machine.
            if (hostname is null && !fakeIps.TryGetHostname(address, out hostname))
            {
                RelayLog.UnknownFakeAddress(logger, address);
                Reset(clientSocket);
                return;
            }

            address = null;
            hostnameIsHint = false;
        }

        var context = new ConnectionContext(
            processes.GetProcessInfo(original.ProcessId),
            TransportProtocol.Tcp,
            address,
            hostname,
            original.Destination.Port);
        var decision = active.Rules.Evaluate(context);

        var clientStream = new NetworkStream(clientSocket, ownsSocket: false);
        var prelude = ClientPrelude.None;
        try
        {
            // In remote mode, names that were not faked (excluded domains, hosts file entries) are sniffed as well.
            // A hostname hint from the process's lookups is checked against the sniffed name: addresses are shared.
            if (settings.Dns.Mode != DnsMode.Local && (context.DestinationHost is null || hostnameIsHint) &&
                (decision.Action == RuleActionType.Proxy || active.Rules.UsesHostCriteria))
            {
                prelude = await ClientPrelude.ReadAsync(clientStream, TimeSpan.FromMilliseconds(settings.Dns.SniffTimeoutMs), cancellationToken).ConfigureAwait(false);
                if (prelude.Hostname is { } sniffed && !string.Equals(sniffed, context.DestinationHost, StringComparison.OrdinalIgnoreCase))
                {
                    context = context with { DestinationHost = sniffed };
                    decision = active.Rules.Evaluate(context);
                }
            }

            var connection = tracker.Open(context, decision);
            try
            {
                RelayLog.Decided(
                    logger, connection.Id, context.Process?.Name ?? "?", original.ProcessId, context.DestinationDisplay,
                    decision.RuleName, decision.Action, decision.Route?.Id);

                if (decision.Action == RuleActionType.Block)
                {
                    Reset(clientSocket);
                    return;
                }

                var upstream = await ConnectUpstreamAsync(connection, active, cancellationToken).ConfigureAwait(false);
                if (upstream is null)
                {
                    Reset(clientSocket);
                    return;
                }

                await using (upstream.ConfigureAwait(false))
                {
                    await StreamPump.RunAsync(clientStream, upstream, prelude, connection, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                tracker.Close(connection);
                RelayLog.Closed(logger, connection.Id, connection.BytesSent, connection.BytesReceived);
            }
        }
        finally
        {
            prelude.Dispose();
            await clientStream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Returns the upstream stream, or <see langword="null"/> (after logging) if it could not be established.</summary>
    private async Task<Stream?> ConnectUpstreamAsync(TrackedConnection connection, ActiveConfiguration active, CancellationToken cancellationToken)
    {
        var context = connection.Context;
        var decision = connection.Decision;
        var settings = active.Settings;
        var timeout = TimeSpan.FromMilliseconds(settings.Relay.ConnectTimeoutMs);

        if (decision.Action == RuleActionType.Proxy)
        {
            var route = decision.Route!;
            var target = BuildProxyTarget(context, settings.Dns.Mode);
            if (target.Address is null && settings.Dns.RemoteServer is { ResolveNames: true } && active.ShouldFakeResolve(target.Host!))
            {
                // The proxy cannot resolve internal names: ask the target network's DNS server, through the tunnel.
                if (await remoteDns.ResolveAsync(active, target.Host!, cancellationToken).ConfigureAwait(false) is not { } resolved)
                {
                    RelayLog.ProxyFailed(logger, connection.Id, context.DestinationDisplay, route.Id,
                        $"the remote DNS server has no address for {target.Host} (remoteServer.resolveNames)");
                    return null;
                }

                target = TargetEndpoint.FromAddress(resolved, target.Port);
            }
            else if (target.Address is null && route.Hops[^1].Type == ProxyType.Socks4)
            {
                // Never resolve such a name here: it is only known on the far side, or locally it is a fake address.
                RelayLog.ProxyFailed(logger, connection.Id, context.DestinationDisplay, route.Id,
                    $"SOCKS4 cannot send the name {target.Host} to proxy '{route.Hops[^1].Id}', and only the far side can resolve it. " +
                    "Use a socks4a or socks5 proxy, or set settings.dns.remoteServer.resolveNames");
                return null;
            }

            try
            {
                return await dialer.ConnectAsync(route, target, timeout, cancellationToken).ConfigureAwait(false);
            }
            catch (ProxyException ex)
            {
                RelayLog.ProxyFailed(logger, connection.Id, context.DestinationDisplay, route.Id, ex.Message);
                return null;
            }
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            var target = context.DestinationAddress is { } address
                ? TargetEndpoint.FromAddress(address, context.DestinationPort)
                : TargetEndpoint.FromHost(context.DestinationHost!, context.DestinationPort);
            return await connector.ConnectAsync(target, timeoutSource.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or IOException ||
                                   (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            RelayLog.DirectFailed(logger, connection.Id, context.DestinationDisplay, ex is OperationCanceledException ? "timed out" : ex.Message);
            return null;
        }
    }

    /// <summary>Hostnames are passed to the proxy unless the DNS mode is <see cref="DnsMode.Local"/>.</summary>
    internal static TargetEndpoint BuildProxyTarget(ConnectionContext context, DnsMode dnsMode)
    {
        if (context.DestinationHost is { } host && (dnsMode != DnsMode.Local || context.DestinationAddress is null))
        {
            return TargetEndpoint.FromHost(host, context.DestinationPort, context.DestinationAddress);
        }

        return TargetEndpoint.FromAddress(context.DestinationAddress!, context.DestinationPort);
    }

    /// <summary>Closes the socket with a TCP RST so the client sees an immediate failure.</summary>
    private static void Reset(Socket socket)
    {
        try
        {
            socket.LingerState = new LingerOption(true, 0);
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            // Already closed.
        }

        socket.Dispose();
    }
}
