using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Rules;
using Proxynator.Platform.Linux.Interop;
using Proxynator.Platform.Linux.Processes;

namespace Proxynator.Platform.Linux.Capture;

/// <summary>
/// Kernel-level capture with eBPF programs on the root cgroup (native/linux/bpf/proxynator.bpf.c). The service
/// classifies processes (may any non-direct rule apply?) into a BPF map; connect() of candidates, and of processes
/// not classified yet, is rewritten to the relay, which looks the original destination up here by the client's
/// source port. The links belong to this process: when it exits, the kernel removes the programs.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class BpfCaptureBackend : ICaptureBackend, IOriginalDestinationSource
{
    private const ushort AfInet = 2;

    private static readonly string[] CgroupPrograms =
    [
        "proxynator_sockops", "proxynator_recvmsg4", "proxynator_recvmsg6", "proxynator_sendmsg4", "proxynator_sendmsg6",
        "proxynator_connect4", "proxynator_connect6",
    ];

    private static readonly string[] TracingPrograms = ["proxynator_fork", "proxynator_exit", "proxynator_exec"];

    private readonly LinuxProcessInfoProvider processes;
    private readonly ILogger logger;
    private readonly ILoggerFactory loggerFactory;
    private readonly List<nint> links = [];
    private CaptureContext? context;
    private nint bpfObject;
    private BpfMap<uint, BpfConfig> configMap;
    private BpfMap<uint, uint> decisions;
    private BpfMap<uint, Origin> ports;
    private BpfMap<EndpointKey, byte> excluded;
    private nint ringBuffer;
    private GCHandle self;
    private Thread? eventThread;
    private volatile bool stopping;
    private DnsForwarder? dnsForwarder;
    private long redirected;

    /// <summary>Creates the backend.</summary>
    public BpfCaptureBackend(LinuxProcessInfoProvider processes, ILoggerFactory loggerFactory)
    {
        this.processes = processes;
        this.loggerFactory = loggerFactory;
        logger = loggerFactory.CreateLogger<BpfCaptureBackend>();
    }

    /// <inheritdoc />
    public CaptureMode Mode => CaptureMode.Ebpf;

    /// <inheritdoc />
    /// <remarks>Rewritten connections go to loopback, in the socket's address family.</remarks>
    public IReadOnlyList<IPEndPoint> RelayListenEndpoints =>
        Socket.OSSupportsIPv6
            ? [new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)]
            : [new IPEndPoint(IPAddress.Loopback, 0)];

    /// <inheritdoc />
    public string Activity => string.Create(CultureInfo.InvariantCulture, $"{Interlocked.Read(ref redirected)} redirected connection(s)");

    /// <inheritdoc />
    public async Task StartAsync(CaptureContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (this.context is not null)
        {
            throw new InvalidOperationException("The capture backend has already been started.");
        }

        var objectPath = NativeFiles.PathOf(NativeFiles.BpfObject);
        if (!File.Exists(objectPath))
        {
            throw new InvalidOperationException($"{objectPath} is missing. Build it with build/build-native.sh (see README).");
        }

        if (LibBpf.TryLoad() is { } libbpfError)
        {
            throw new InvalidOperationException($"libbpf is not installed (apt install libbpf1, or libbpf0 on Ubuntu 22.04): {libbpfError}");
        }

        var cgroup = CgroupFinder.FindCgroup2Mount() ?? throw new InvalidOperationException("No cgroup v2 hierarchy is mounted; the ebpf capture mode needs one.");
        if (!File.Exists("/sys/kernel/btf/vmlinux"))
        {
            throw new InvalidOperationException("The kernel has no BTF (/sys/kernel/btf/vmlinux); the ebpf capture mode needs it. Use the preload mode instead.");
        }

        this.context = context;
        if (context.Configuration.Current.Settings.Capture.ProxyLoopback)
        {
            Log.LoopbackNotSupported(logger);
        }

        try
        {
            Load(objectPath);
            dnsForwarder = new DnsForwarder(context.Configuration, context.FakeIps ?? throw new InvalidOperationException("The fake-IP pool is missing."),
                context.DnsServers, loggerFactory.CreateLogger<DnsForwarder>());
            dnsForwarder.Start(RelayListenEndpoints);
            WriteConfig(context);
            await RefreshExclusionsAsync(context.Configuration.Current, cancellationToken).ConfigureAwait(false);
            ClassifyRunningProcesses();
            context.Destinations.ExternalSource = this;
            StartEvents();
            Attach(cgroup);
        }
        catch
        {
            await StopAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        context.Configuration.Changed += OnConfigurationChanged;
        var relays = string.Join(", ", context.RelayEndpoints);
        Log.Started(logger, cgroup, relays);
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (stopping)
        {
            return;
        }

        stopping = true;
        if (context is not null)
        {
            context.Configuration.Changed -= OnConfigurationChanged;
        }

        // Links first: from here on the kernel no longer redirects anything.
        foreach (var link in links)
        {
            _ = LibBpf.bpf_link__destroy(link);
        }

        var wasAttached = links.Count > 0;
        links.Clear();
        eventThread?.Join();
        if (ringBuffer != 0)
        {
            LibBpf.ring_buffer__free(ringBuffer);
            ringBuffer = 0;
        }

        if (self.IsAllocated)
        {
            self.Free();
        }

        if (bpfObject != 0)
        {
            LibBpf.bpf_object__close(bpfObject);
            bpfObject = 0;
        }

        if (context?.Destinations.ExternalSource == this)
        {
            context.Destinations.ExternalSource = null;
        }

        if (dnsForwarder is not null)
        {
            await dnsForwarder.DisposeAsync().ConfigureAwait(false);
            dnsForwarder = null;
        }

        if (wasAttached)
        {
            Log.Stopped(logger);
        }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));

    /// <inheritdoc />
    public bool TryTake(IPEndPoint clientEndpoint, [NotNullWhen(true)] out OriginalDestination? destination)
    {
        destination = null;
        if (!ports.IsValid || !IPAddress.IsLoopback(clientEndpoint.Address))
        {
            return false;
        }

        var key = (uint)clientEndpoint.Port;
        if (!ports.TryGet(key, out var origin))
        {
            return false;
        }

        ports.Delete(key);
        destination = new OriginalDestination(new IPEndPoint(origin.ToAddress(), BinaryPrimitives.ReverseEndianness(origin.Port)), (int)origin.Tgid);
        Interlocked.Increment(ref redirected);

        // A process the service had not classified yet came through the relay first: classify it now, so its
        // further connections take the fast path.
        Classify((int)origin.Tgid, onlyIfUnknown: true);
        return true;
    }

    private void Load(string objectPath)
    {
        // Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK; newer ones (and libbpf 1.x) do not need this.
        var unlimited = new Libc.RLimit { Current = ulong.MaxValue, Maximum = ulong.MaxValue };
        _ = Libc.setrlimit(Libc.RlimitMemlock, in unlimited);

        bpfObject = LibBpf.bpf_object__open_file(objectPath, 0);
        if (LibBpf.IsError(bpfObject))
        {
            bpfObject = 0;
            throw new InvalidOperationException($"Cannot open {objectPath} (error {Marshal.GetLastPInvokeError()}).");
        }

        var error = LibBpf.bpf_object__load(bpfObject);
        if (error != 0)
        {
            throw new InvalidOperationException($"The kernel rejected the eBPF programs (error {-error}). Run proxynatord --verbose for details, or use the preload mode.");
        }

        configMap = new BpfMap<uint, BpfConfig>(MapFd("config"));
        decisions = new BpfMap<uint, uint>(MapFd("decisions"));
        ports = new BpfMap<uint, Origin>(MapFd("ports"));
        excluded = new BpfMap<EndpointKey, byte>(MapFd("excluded"));
    }

    private int MapFd(string name)
    {
        var fd = LibBpf.bpf_object__find_map_fd_by_name(bpfObject, name);
        return fd >= 0 ? fd : throw new InvalidOperationException($"The eBPF object has no map '{name}'.");
    }

    private void Attach(string cgroupPath)
    {
        foreach (var name in TracingPrograms)
        {
            links.Add(Check(LibBpf.bpf_program__attach(Program(name)), name));
        }

        var cgroupFd = Libc.open(cgroupPath, Libc.ORdOnly | Libc.ODirectory | Libc.OCloexec);
        if (cgroupFd < 0)
        {
            throw new InvalidOperationException($"Cannot open {cgroupPath} (errno {Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            foreach (var name in CgroupPrograms)
            {
                links.Add(Check(LibBpf.bpf_program__attach_cgroup(Program(name), cgroupFd), name));
            }
        }
        finally
        {
            Libc.close(cgroupFd);
        }

        nint Program(string name)
        {
            var program = LibBpf.bpf_object__find_program_by_name(bpfObject, name);
            return program != 0 ? program : throw new InvalidOperationException($"The eBPF object has no program '{name}'.");
        }

        static nint Check(nint link, string name) =>
            LibBpf.IsError(link) ? throw new InvalidOperationException($"Cannot attach the eBPF program {name}.") : link;
    }

    private void WriteConfig(CaptureContext context)
    {
        ushort PortOf(IReadOnlyList<IPEndPoint> endpoints, AddressFamily family) =>
            endpoints.FirstOrDefault(e => e.AddressFamily == family) is { } endpoint ? BinaryPrimitives.ReverseEndianness((ushort)endpoint.Port) : (ushort)0;

        var dns = dnsForwarder!.LocalEndpoints;
        var config = new BpfConfig
        {
            ServiceTgid = (uint)context.ServiceProcessId,
            Relay4Port = PortOf(context.RelayEndpoints, AddressFamily.InterNetwork),
            Relay6Port = PortOf(context.RelayEndpoints, AddressFamily.InterNetworkV6),
            Dns4Port = PortOf(dns, AddressFamily.InterNetwork),
            Dns6Port = PortOf(dns, AddressFamily.InterNetworkV6),
        };
        if (config.Relay4Port == 0)
        {
            throw new InvalidOperationException("The relay does not listen on 127.0.0.1.");
        }

        configMap.Update(0, config);
    }

    private void StartEvents()
    {
        self = GCHandle.Alloc(this);
        ringBuffer = EventCallback.Open(MapFd("events"), GCHandle.ToIntPtr(self));
        if (LibBpf.IsError(ringBuffer))
        {
            ringBuffer = 0;
            throw new InvalidOperationException("Cannot open the eBPF event ring buffer.");
        }

        eventThread = new Thread(() =>
        {
            while (!stopping)
            {
                _ = LibBpf.ring_buffer__poll(ringBuffer, 200);
            }
        })
        {
            IsBackground = true,
            Name = "Proxynator eBPF events",
        };
        eventThread.Start();
    }

    /// <summary>Called on the event thread for every exec(): the process has a new program, classify it again.</summary>
    internal void OnProcessExec(int processId) => Classify(processId, onlyIfUnknown: false);

    private void ClassifyRunningProcesses()
    {
        foreach (var pid in processes.RunningProcessIds())
        {
            Classify(pid, onlyIfUnknown: false);
        }
    }

    /// <summary>Writes the process's classification (and UDP/DNS policy) to the decisions map.</summary>
    private void Classify(int processId, bool onlyIfUnknown)
    {
        if (!decisions.IsValid || context is null)
        {
            return;
        }

        var key = (uint)processId;
        if (onlyIfUnknown && decisions.TryGet(key, out _))
        {
            return;
        }

        var isService = processId == context.ServiceProcessId;
        decisions.Update(key, ProcessClassifier.Decide(context.Configuration.Current, isService ? null : processes.GetProcessInfo(processId), isService));
    }

    private void OnConfigurationChanged(object? sender, ActiveConfiguration configuration) => _ = Task.Run(async () =>
    {
        try
        {
            await RefreshExclusionsAsync(configuration, CancellationToken.None).ConfigureAwait(false);
            ClassifyRunningProcesses();
        }
#pragma warning disable CA1031 // Background refresh: log, keep capturing with the previous classification.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Log.RefreshFailed(logger, ex);
        }
    });

    /// <summary>Connections to the configured proxies are never redirected.</summary>
    private async Task RefreshExclusionsAsync(ActiveConfiguration configuration, CancellationToken cancellationToken)
    {
        var keys = new List<EndpointKey>();
        foreach (var endpoint in configuration.ProxyEndpoints)
        {
            try
            {
                var addresses = endpoint.Address is { } address ? [address] : await Dns.GetHostAddressesAsync(endpoint.Host!, cancellationToken).ConfigureAwait(false);
                keys.AddRange(addresses.Select(a => EndpointKey.Create(a, endpoint.Port)));
            }
            catch (SocketException ex)
            {
                Log.ProxyResolutionFailed(logger, endpoint.ToString(), ex.Message);
            }
        }

        // Clear, then fill: the map is small (one entry per proxy address).
        foreach (var key in excluded.Keys())
        {
            excluded.Delete(key);
        }

        foreach (var key in keys)
        {
            excluded.Update(key, 1);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BpfConfig
    {
        public uint ServiceTgid;
        public ushort Relay4Port;
        public ushort Relay6Port;
        public ushort Dns4Port;
        public ushort Dns6Port;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct Origin
    {
        public uint Tgid;
        public ushort Family;
        public ushort Port;
        public fixed byte Address[16];

        public IPAddress ToAddress()
        {
            fixed (byte* bytes = Address)
            {
                return new IPAddress(new ReadOnlySpan<byte>(bytes, 16)).Normalize();
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct EndpointKey
    {
        public fixed byte Address[16];
        public ushort Port;
        public ushort Padding;

        public static EndpointKey Create(IPAddress address, int port)
        {
            var key = new EndpointKey { Port = BinaryPrimitives.ReverseEndianness((ushort)port) };
            var mapped = address.AddressFamily == AddressFamily.InterNetwork ? address.MapToIPv6() : address;
            mapped.TryWriteBytes(new Span<byte>(key.Address, 16), out _);
            return key;
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 2200, Level = LogLevel.Information, Message = "eBPF capture started on cgroup {Cgroup}; relay on {Relay}")]
        public static partial void Started(ILogger logger, string cgroup, string relay);

        [LoggerMessage(EventId = 2201, Level = LogLevel.Information, Message = "eBPF capture stopped; the programs are detached")]
        public static partial void Stopped(ILogger logger);

        [LoggerMessage(EventId = 2202, Level = LogLevel.Warning, Message = "Could not resolve proxy {Endpoint} for the exclusion list: {Reason}")]
        public static partial void ProxyResolutionFailed(ILogger logger, string endpoint, string reason);

        [LoggerMessage(EventId = 2203, Level = LogLevel.Error, Message = "Re-classifying processes after a configuration change failed")]
        public static partial void RefreshFailed(ILogger logger, Exception exception);

        [LoggerMessage(EventId = 2204, Level = LogLevel.Warning, Message = "settings.capture.proxyLoopback is not supported by the ebpf backend yet; loopback connections are not redirected")]
        public static partial void LoopbackNotSupported(ILogger logger);
    }
}
