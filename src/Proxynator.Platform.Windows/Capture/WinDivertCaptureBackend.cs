using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Rules;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// Kernel-level capture with WinDivert. Two handles are used:
/// <list type="bullet">
/// <item>a sniffing SOCKET-layer handle that learns which process opened each outbound TCP connection;</item>
/// <item>a NETWORK-layer handle that diverts outbound TCP, redirects new connections that need the relay with the
/// <see cref="ReflectNat"/>, and drops connections from the network to the relay port.</item>
/// </list>
/// Closing the handles (on stop, or when the process dies) immediately restores normal packet flow.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WinDivertCaptureBackend : ICaptureBackend
{
    private const short Priority = 0;

    private readonly IProcessInfoProvider processes;
    private readonly ILogger logger;
    private readonly WindowsFirewall firewall;
    private readonly SocketOwnerCache owners = new();
    private CaptureContext? context;
    private ReflectNat? nat;
    private WinDivertHandle? networkHandle;
    private WinDivertHandle? socketHandle;
    private Thread? networkThread;
    private Thread? socketThread;
    private volatile HashSet<(UInt128 Address, int Port)> excludedEndpoints = [];
    private int ownProcessId;

    /// <summary>Creates the backend.</summary>
    public WinDivertCaptureBackend(IProcessInfoProvider processes, ILogger<WinDivertCaptureBackend> logger)
    {
        this.processes = processes;
        this.logger = logger;
        firewall = new WindowsFirewall(logger);
    }

    /// <inheritdoc />
    public CaptureMode Mode => CaptureMode.WinDivert;

    /// <inheritdoc />
    /// <remarks>Reflected packets arrive on the client's own interface address, so the relay listens on all addresses.</remarks>
    public IReadOnlyList<IPEndPoint> RelayListenEndpoints =>
        [Socket.OSSupportsIPv6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0)];

    /// <summary>The number of connections currently redirected.</summary>
    public int RedirectedConnections => nat?.Count ?? 0;

    /// <inheritdoc />
    public async Task StartAsync(CaptureContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (this.context is not null)
        {
            throw new InvalidOperationException("The capture backend has already been started.");
        }

        this.context = context;
        ownProcessId = context.ServiceProcessId;
        var relayPort = context.RelayEndpoints[0].Port;
        var udpRelayPort = context.UdpDestinations is not null && context.UdpRelayEndpoints.Count > 0 ? context.UdpRelayEndpoints[0].Port : 0;
        nat = new ReflectNat(relayPort, udpRelayPort);

        await RefreshExclusionsAsync(context.Configuration.Current, cancellationToken).ConfigureAwait(false);
        context.Configuration.Changed += OnConfigurationChanged;
        if (context.Configuration.Current.Settings.Capture.ProxyLoopback)
        {
            Log.LoopbackNotSupported(logger);
        }

        firewall.AllowRelayPorts(relayPort, udpRelayPort);
        FlushDnsCache();

        socketHandle = Open("(tcp or udp) and (event == CONNECT or event == CLOSE)", WinDivertLayer.Socket, WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);
        var networkFilter = udpRelayPort == 0
            ? string.Create(CultureInfo.InvariantCulture, $"tcp and ((outbound and !loopback) or (inbound and !loopback and tcp.DstPort == {relayPort}))")
            : string.Create(
                CultureInfo.InvariantCulture,
                $"(tcp or udp) and ((outbound and !loopback) or (inbound and !loopback and ((tcp and tcp.DstPort == {relayPort}) or (udp and udp.DstPort == {udpRelayPort}))))");
        try
        {
            networkHandle = Open(networkFilter, WinDivertLayer.Network, WinDivertFlags.None);
        }
        catch
        {
            socketHandle.Dispose();
            throw;
        }

        socketThread = new Thread(SocketLoop) { IsBackground = true, Name = "Proxynator WinDivert socket events" };
        networkThread = new Thread(NetworkLoop) { IsBackground = true, Name = "Proxynator WinDivert packets" };
        socketThread.Start();
        networkThread.Start();
        Log.Started(logger, relayPort, udpRelayPort);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (context is not null)
        {
            context.Configuration.Changed -= OnConfigurationChanged;
        }

        foreach (var handle in new[] { networkHandle, socketHandle })
        {
            if (handle is { IsInvalid: false, IsClosed: false })
            {
                WinDivertNative.Shutdown(handle, WinDivertShutdown.Both);
            }
        }

        networkThread?.Join(TimeSpan.FromSeconds(5));
        socketThread?.Join(TimeSpan.FromSeconds(5));
        networkHandle?.Dispose();
        socketHandle?.Dispose();
        networkHandle = null;
        socketHandle = null;
        if (context is not null)
        {
            firewall.RemoveRelayRule();
            FlushDnsCache(); // no fake-IP answers may outlive the service
            Log.Stopped(logger);
            context = null;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None).ConfigureAwait(false);

    private static void FlushDnsCache()
    {
        try
        {
            DnsApi.FlushResolverCache();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Not available; nothing to flush.
        }
    }

    /// <summary>Checks a WinDivert filter for syntax errors without opening a handle.</summary>
    internal static unsafe string? ValidateFilter(string filter, WinDivertLayer layer)
    {
        byte* error = null;
        uint position = 0;
        return WinDivertNative.CompileFilter(filter, layer, null, 0, &error, &position)
            ? null
            : $"{Marshal.PtrToStringUTF8((nint)error)} at position {position}";
    }

    private static WinDivertHandle Open(string filter, WinDivertLayer layer, WinDivertFlags flags)
    {
        WinDivertHandle handle;
        try
        {
            handle = WinDivertNative.Open(filter, layer, Priority, flags);
        }
        catch (DllNotFoundException ex)
        {
            throw new InvalidOperationException("WinDivert.dll was not found next to the application. Rebuild on Windows or with -p:IncludeWinDivert=true.", ex);
        }

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new InvalidOperationException($"WinDivertOpen({layer}) failed: {DescribeOpenError(error)}");
        }

        return handle;
    }

    private static string DescribeOpenError(int error) => error switch
    {
        2 => "the WinDivert64.sys driver file was not found next to WinDivert.dll (error 2)",
        5 => "access denied; run as Administrator (error 5)",
        87 => "invalid filter or parameter (error 87)",
        577 => "the driver signature could not be verified; check Secure Boot / driver signing policy (error 577)",
        654 => "an incompatible WinDivert driver version is already loaded; reboot or stop other WinDivert users (error 654)",
        1060 => "the WinDivert driver service is missing; it may have been removed by another program (error 1060)",
        1275 => "the driver was blocked from loading, e.g. by security software or HVCI (error 1275)",
        1753 => "the Base Filtering Engine service is not running (error 1753)",
        _ => $"Win32 error {error}",
    };

    private void OnConfigurationChanged(object? sender, ActiveConfiguration configuration) =>
        _ = RefreshExclusionsAsync(configuration, CancellationToken.None);

    /// <summary>Resolves configured proxy endpoints; connections to them are never redirected.</summary>
    private async Task RefreshExclusionsAsync(ActiveConfiguration configuration, CancellationToken cancellationToken)
    {
        var excluded = new HashSet<(UInt128, int)>();
        foreach (var endpoint in configuration.ProxyEndpoints)
        {
            IPAddress[] addresses;
            try
            {
                addresses = endpoint.Address is { } address
                    ? [address]
                    : await System.Net.Dns.GetHostAddressesAsync(endpoint.Host!, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                Log.ProxyResolutionFailed(logger, endpoint.ToString(), ex.Message);
                continue;
            }

            foreach (var address in addresses)
            {
                excluded.Add((AddressKey.FromIPAddress(address.Normalize()), endpoint.Port));
            }
        }

        excludedEndpoints = excluded;
    }

    private unsafe void SocketLoop()
    {
        var handle = socketHandle!;
        WinDivertAddress address;
        while (true)
        {
            if (!WinDivertNative.Recv(handle, null, 0, null, &address))
            {
                if (IsShutdownError(Marshal.GetLastPInvokeError()))
                {
                    return;
                }

                continue;
            }

            var socket = address.Socket;
            var protocol = socket.Protocol == 17 ? TransportProtocol.Udp : TransportProtocol.Tcp;
            var remote = socket.RemoteAddr.ToUInt128();
            if (address.Event == WinDivertEvent.SocketConnect)
            {
                owners.Add(protocol, socket.LocalPort, remote, socket.RemotePort, (int)socket.ProcessId);
            }
            else if (address.Event == WinDivertEvent.SocketClose)
            {
                owners.Remove(protocol, socket.LocalPort, remote, socket.RemotePort);
            }
        }
    }

    private unsafe void NetworkLoop()
    {
        var handle = networkHandle!;
        var natTable = nat!;
        var buffer = GC.AllocateArray<byte>(WinDivertNative.MaxPacketSize, pinned: true);
        Func<ConnectionAttempt, bool> decide = ShouldRedirect;
        fixed (byte* packet = buffer)
        {
            WinDivertAddress address;
            uint length;
            while (true)
            {
                if (!WinDivertNative.Recv(handle, packet, (uint)buffer.Length, &length, &address))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (IsShutdownError(error))
                    {
                        return;
                    }

                    Log.ReceiveFailed(logger, error);
                    continue;
                }

                NatVerdict verdict;
                try
                {
                    verdict = address.Outbound ? natTable.Process(buffer.AsSpan(0, (int)length), decide) : NatVerdict.Drop;
                }
#pragma warning disable CA1031 // A bug in one packet must not stop the capture thread; fail open for that packet.
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    Log.PacketFailed(logger, ex);
                    verdict = NatVerdict.PassThrough;
                }

                if (verdict == NatVerdict.Drop)
                {
                    continue;
                }

                if (verdict == NatVerdict.Reflect)
                {
                    address.Outbound = false;
                    WinDivertNative.CalcChecksums(packet, length, &address, 0);
                }

                if (!WinDivertNative.Send(handle, packet, length, null, &address))
                {
                    var error = Marshal.GetLastPInvokeError();
                    if (IsShutdownError(error))
                    {
                        return;
                    }

                    Log.SendFailed(logger, error);
                }
            }
        }
    }

    /// <summary>Called for every new outbound TCP connection or UDP flow; decides whether a relay must handle it.</summary>
    private bool ShouldRedirect(ConnectionAttempt attempt)
    {
        var current = context!;
        var isUdp = attempt.Protocol == TransportProtocol.Udp;
        if (excludedEndpoints.Contains((attempt.RemoteAddress, attempt.RemotePort)) || (isUdp && current.UdpDestinations is null))
        {
            return false;
        }

        var processId = owners.TryGet(attempt.Protocol, attempt.LocalPort, attempt.RemoteAddress, attempt.RemotePort, out var owner)
            ? owner
            : isUdp
                ? IpHelper.FindUdpOwner(attempt.IsIPv6, attempt.LocalPort)
                : IpHelper.FindTcpOwner(attempt.IsIPv6, attempt.LocalPort, attempt.RemoteAddress, attempt.RemotePort);
        if (processId == ownProcessId)
        {
            return false;
        }

        if (processId < 0)
        {
            // Unknown owner: never redirect. It could be the relay's own upstream connection, and a catch-all rule
            // would then loop it back into the relay.
            Log.UnknownOwner(logger, attempt.RemoteIPAddress, attempt.RemotePort);
            return false;
        }

        var remoteAddress = attempt.RemoteIPAddress;
        var settings = current.Configuration.Current.Settings;
        string? hostname = null;
        var isFake = current.FakeIps?.Contains(remoteAddress) == true;
        if (isFake)
        {
            // Fake addresses only work through the relay; an unknown one is refused there, with a log entry.
            current.FakeIps!.TryGetHostname(remoteAddress, out hostname);
        }

        var mustRelay = isFake || (isUdp && attempt.RemotePort == 53 && settings.Dns.Mode == DnsMode.Remote && current.FakeIps is not null);

        var connection = new ConnectionContext(
            processes.GetProcessInfo(processId),
            attempt.Protocol,
            remoteAddress,
            hostname,
            attempt.RemotePort);
        if (!mustRelay && !current.Configuration.Current.Rules.RequiresRelay(connection))
        {
            return false;
        }

        // The relay will see the reflected flow as coming from B:pa (original destination address, client port).
        (isUdp ? current.UdpDestinations! : current.Destinations).Register(
            new IPEndPoint(remoteAddress, attempt.LocalPort),
            new OriginalDestination(new IPEndPoint(remoteAddress, attempt.RemotePort), processId, hostname));
        Log.Redirecting(logger, attempt.Protocol, connection.Process?.Name ?? "?", processId, connection.DestinationDisplay);
        return true;
    }

    private static bool IsShutdownError(int error) =>
        error is WinDivertNative.ErrorNoData or WinDivertNative.ErrorOperationAborted or WinDivertNative.ErrorInvalidHandle;

    private static partial class Log
    {
        [LoggerMessage(EventId = 2000, Level = LogLevel.Information, Message = "WinDivert capture started; TCP relay port {RelayPort}, UDP relay port {UdpRelayPort}")]
        public static partial void Started(ILogger logger, int relayPort, int udpRelayPort);

        [LoggerMessage(EventId = 2001, Level = LogLevel.Information, Message = "WinDivert capture stopped; normal networking restored")]
        public static partial void Stopped(ILogger logger);

        [LoggerMessage(EventId = 2002, Level = LogLevel.Debug, Message = "Redirecting {Protocol} {Process} (pid {ProcessId}) -> {Destination}")]
        public static partial void Redirecting(ILogger logger, TransportProtocol protocol, string process, int processId, string destination);

        [LoggerMessage(EventId = 2003, Level = LogLevel.Warning, Message = "WinDivertRecv failed with Win32 error {Error}")]
        public static partial void ReceiveFailed(ILogger logger, int error);

        [LoggerMessage(EventId = 2004, Level = LogLevel.Warning, Message = "WinDivertSend failed with Win32 error {Error}")]
        public static partial void SendFailed(ILogger logger, int error);

        [LoggerMessage(EventId = 2005, Level = LogLevel.Error, Message = "Processing a packet failed; it was passed through unchanged")]
        public static partial void PacketFailed(ILogger logger, Exception exception);

        [LoggerMessage(EventId = 2006, Level = LogLevel.Warning, Message = "Could not resolve proxy {Endpoint} for the capture exclusion list: {Reason}")]
        public static partial void ProxyResolutionFailed(ILogger logger, string endpoint, string reason);

        [LoggerMessage(EventId = 2008, Level = LogLevel.Debug, Message = "Not redirecting a connection to {Address}:{Port}: its owning process could not be determined")]
        public static partial void UnknownOwner(ILogger logger, IPAddress address, int port);

        [LoggerMessage(EventId = 2007, Level = LogLevel.Warning, Message = "settings.capture.proxyLoopback is not supported by the windivert backend yet; loopback connections are not redirected")]
        public static partial void LoopbackNotSupported(ILogger logger);
    }
}
