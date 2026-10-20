using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Rules;

namespace Proxynator.Core.Hooking;

/// <summary>
/// The service side of the hook registration protocol, shared by all user-mode capture backends (Windows injection,
/// Linux preload). It applies the same decisions as the kernel-level backends: connections that may need the relay
/// are registered in <see cref="CaptureContext.Destinations"/> under the endpoint the hooked socket will connect
/// from, and the hook is told to connect to the relay instead.
/// </summary>
public sealed partial class HookRequestHandler : IDisposable
{
    private readonly CaptureContext context;
    private readonly IProcessInfoProvider processes;
    private readonly ILogger logger;
    private volatile HashSet<IPEndPoint> excludedEndpoints = [];

    /// <summary>Creates the handler and starts tracking the configured proxy endpoints (never redirected).</summary>
    public HookRequestHandler(CaptureContext context, IProcessInfoProvider processes, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(context);
        this.context = context;
        this.processes = processes;
        this.logger = logger;
        context.Configuration.Changed += OnConfigurationChanged;
    }

    /// <summary>Resolves the configured proxy endpoints once; call before serving requests.</summary>
    public Task InitializeAsync(CancellationToken cancellationToken) => RefreshExclusionsAsync(context.Configuration.Current, cancellationToken);

    /// <inheritdoc />
    public void Dispose() => context.Configuration.Changed -= OnConfigurationChanged;

    /// <summary>Answers one request from the process <paramref name="processId"/> (as verified by the transport).</summary>
    public HookResponse Handle(int processId, HookRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return request switch
        {
            HookHelloRequest hello => Hello(processId, hello),
            HookConnectRequest { Protocol: TransportProtocol.Tcp } connect => ConnectTcp(processId, connect),
            HookConnectRequest connect => ConnectUdp(processId, connect),
            HookResolveRequest resolve => Resolve(processId, resolve),
            _ => throw new ArgumentException($"Unknown request {request.GetType().Name}.", nameof(request)),
        };
    }

    private HookHelloResponse Hello(int processId, HookHelloRequest hello)
    {
        Log.ProcessHooked(logger, processes.GetProcessInfo(processId)?.Name ?? "?", processId, hello.PointerBits);
        return new HookHelloResponse(context.ServiceProcessId);
    }

    private HookConnectResponse ConnectTcp(int processId, HookConnectRequest request)
    {
        var remote = request.RemoteEndpoint.Normalize();
        if (IsNeverRedirected(processId, remote))
        {
            return HookConnectResponse.Direct;
        }

        var fakeIps = context.FakeIps;
        var isFake = fakeIps?.Contains(remote.Address) == true;
        string? hostname = request.Hostname;
        if (isFake)
        {
            // Fake addresses only work through the relay; an unknown one is refused there, with a log entry.
            fakeIps!.TryGetHostname(remote.Address, out hostname);
        }

        var connection = new ConnectionContext(processes.GetProcessInfo(processId), TransportProtocol.Tcp, remote.Address, hostname, remote.Port);
        if (!isFake && !context.Configuration.Current.Rules.RequiresRelay(connection))
        {
            return HookConnectResponse.Direct;
        }

        var local = request.LocalEndpoint.Normalize();
        var relay = context.RelayEndpoints.FirstOrDefault(e => e.AddressFamily == local.AddressFamily);
        if (relay is null)
        {
            // Fail closed: the rules want the relay, but it does not listen on this address family.
            Log.NoRelayForFamily(logger, local.AddressFamily, connection.DestinationDisplay);
            return HookConnectResponse.Block;
        }

        context.Destinations.Register(local, new OriginalDestination(remote, processId, hostname, HostnameIsHint: !isFake && hostname is not null));
        Log.Redirecting(logger, connection.Process?.Name ?? "?", processId, connection.DestinationDisplay);
        return new HookConnectResponse(HookVerdict.Relay, relay);
    }

    /// <summary>
    /// UDP is not relayed in user-mode capture yet: datagrams the rules would proxy follow the rule's UDP fallback
    /// (block by default), QUIC is blocked for proxied processes, everything else goes direct.
    /// </summary>
    private HookConnectResponse ConnectUdp(int processId, HookConnectRequest request)
    {
        var remote = request.RemoteEndpoint.Normalize();
        if (IsNeverRedirected(processId, remote))
        {
            return HookConnectResponse.Direct;
        }

        var active = context.Configuration.Current;
        if (context.FakeIps?.Contains(remote.Address) == true)
        {
            Log.UdpToFakeAddress(logger, processId, remote);
            return HookConnectResponse.Block;
        }

        var connection = new ConnectionContext(processes.GetProcessInfo(processId), TransportProtocol.Udp, remote.Address, request.Hostname, remote.Port);
        var decision = active.Rules.Evaluate(connection);
        var verdict = decision.Action switch
        {
            RuleActionType.Direct => HookVerdict.Direct,
            RuleActionType.Block => HookVerdict.Block,
            _ when active.Settings.Udp.BlockQuic && remote.Port == 443 => HookVerdict.Block,
            _ => decision.UdpFallback == UdpFallback.Direct ? HookVerdict.Direct : HookVerdict.Block,
        };
        if (verdict == HookVerdict.Block)
        {
            Log.UdpBlocked(logger, connection.Process?.Name ?? "?", processId, connection.DestinationDisplay, decision.RuleName);
        }

        return verdict == HookVerdict.Block ? HookConnectResponse.Block : HookConnectResponse.Direct;
    }

    /// <summary>In remote DNS mode, names in <c>remoteDomains</c> get a fake address; only hooked processes ask.</summary>
    private HookResolveResponse Resolve(int processId, HookResolveRequest request)
    {
        var active = context.Configuration.Current;
        if (active.Settings.Dns.Mode != DnsMode.Remote || context.FakeIps is not { } fakeIps || !active.ShouldFakeResolve(request.Hostname))
        {
            return HookResolveResponse.ResolveNormally;
        }

        var address = fakeIps.GetOrAllocate(request.Hostname.TrimEnd('.'));
        Log.Faked(logger, request.Hostname, address, processId);
        return new HookResolveResponse(address);
    }

    private bool IsNeverRedirected(int processId, IPEndPoint remote)
    {
        if (processId == context.ServiceProcessId || IPAddress.IsLoopback(remote.Address) ||
            remote.Address.Equals(IPAddress.Any) || remote.Address.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        return excludedEndpoints.Contains(remote);
    }

    private void OnConfigurationChanged(object? sender, ActiveConfiguration configuration) =>
        _ = RefreshExclusionsAsync(configuration, CancellationToken.None);

    private async Task RefreshExclusionsAsync(ActiveConfiguration configuration, CancellationToken cancellationToken)
    {
        var excluded = new HashSet<IPEndPoint>();
        foreach (var endpoint in configuration.ProxyEndpoints)
        {
            try
            {
                var addresses = endpoint.Address is { } address
                    ? [address]
                    : await Dns.GetHostAddressesAsync(endpoint.Host!, cancellationToken).ConfigureAwait(false);
                foreach (var resolved in addresses)
                {
                    excluded.Add(new IPEndPoint(resolved.Normalize(), endpoint.Port));
                }
            }
            catch (SocketException ex)
            {
                Log.ProxyResolutionFailed(logger, endpoint.ToString(), ex.Message);
            }
        }

        excludedEndpoints = excluded;
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 4000, Level = LogLevel.Information, Message = "Hooked process {Process} (pid {ProcessId}, {Bits}-bit) connected")]
        public static partial void ProcessHooked(ILogger logger, string process, int processId, int bits);

        [LoggerMessage(EventId = 4001, Level = LogLevel.Debug, Message = "Redirecting TCP {Process} (pid {ProcessId}) -> {Destination}")]
        public static partial void Redirecting(ILogger logger, string process, int processId, string destination);

        [LoggerMessage(EventId = 4002, Level = LogLevel.Warning, Message = "Refusing a connection to {Destination}: the relay does not listen on {Family}")]
        public static partial void NoRelayForFamily(ILogger logger, AddressFamily family, string destination);

        [LoggerMessage(EventId = 4003, Level = LogLevel.Information, Message = "Blocked UDP from {Process} (pid {ProcessId}) to {Destination} (rule '{Rule}'; UDP is not relayed in injection mode)")]
        public static partial void UdpBlocked(ILogger logger, string process, int processId, string destination, string rule);

        [LoggerMessage(EventId = 4004, Level = LogLevel.Warning, Message = "Blocked UDP from pid {ProcessId} to the fake address {Destination}")]
        public static partial void UdpToFakeAddress(ILogger logger, int processId, IPEndPoint destination);

        [LoggerMessage(EventId = 4005, Level = LogLevel.Debug, Message = "Answered {Hostname} with fake address {Address} for pid {ProcessId}")]
        public static partial void Faked(ILogger logger, string hostname, IPAddress address, int processId);

        [LoggerMessage(EventId = 4006, Level = LogLevel.Warning, Message = "Could not resolve proxy {Endpoint} for the exclusion list: {Reason}")]
        public static partial void ProxyResolutionFailed(ILogger logger, string endpoint, string reason);
    }
}
