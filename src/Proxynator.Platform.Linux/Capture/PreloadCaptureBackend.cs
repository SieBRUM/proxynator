using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Hooking;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Platform.Linux.Interop;

namespace Proxynator.Platform.Linux.Capture;

/// <summary>
/// User-mode capture: programs started with <c>proxynator run</c> carry the preload library
/// (native/linux/preload), which asks this backend over the Unix socket <see cref="CaptureContext.HookEndpoint"/>
/// before every connect, exactly like the Windows injection hook. Only those programs (and their children, which
/// inherit <c>LD_PRELOAD</c>) are affected.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class PreloadCaptureBackend : ICaptureBackend
{
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly IProcessInfoProvider processes;
    private readonly ILogger logger;
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentDictionary<Task, int> sessions = new();
    private HookRequestHandler? handler;
    private Socket? listener;
    private Task? acceptLoop;
    private string? socketPath;

    /// <summary>Creates the backend.</summary>
    public PreloadCaptureBackend(IProcessInfoProvider processes, ILogger<PreloadCaptureBackend> logger)
    {
        this.processes = processes;
        this.logger = logger;
    }

    /// <inheritdoc />
    public CaptureMode Mode => CaptureMode.Preload;

    /// <inheritdoc />
    public IReadOnlyList<IPEndPoint> RelayListenEndpoints =>
        Socket.OSSupportsIPv6
            ? [new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)]
            : [new IPEndPoint(IPAddress.Loopback, 0)];

    /// <inheritdoc />
    public string Activity => string.Create(CultureInfo.InvariantCulture, $"{sessions.Values.Distinct().Count()} hooked process(es)");

    /// <inheritdoc />
    public async Task StartAsync(CaptureContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (handler is not null)
        {
            throw new InvalidOperationException("The capture backend has already been started.");
        }

        socketPath = context.HookEndpoint ?? throw new InvalidOperationException("The preload capture mode needs a hook endpoint.");
        var library = NativeFiles.PathOf(NativeFiles.PreloadLibrary);
        if (!File.Exists(library))
        {
            throw new InvalidOperationException($"{library} is missing. Build it with build/build-native.sh (see README).");
        }

        handler = new HookRequestHandler(context, processes, logger);
        await handler.InitializeAsync(cancellationToken).ConfigureAwait(false);

        if (Path.GetDirectoryName(Path.GetFullPath(socketPath)) is { } directory)
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(socketPath))
        {
            File.Delete(socketPath); // stale socket from a previous run
        }

        listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(128);

        // Hooked programs run as any user. Callers are identified by SO_PEERCRED, never by what they claim.
        File.SetUnixFileMode(socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                                         UnixFileMode.OtherRead | UnixFileMode.OtherWrite);
        acceptLoop = Task.Run(() => AcceptLoopAsync(shutdown.Token), CancellationToken.None);
        Log.Started(logger, socketPath);
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (shutdown.IsCancellationRequested)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        listener?.Dispose();
        if (acceptLoop is not null)
        {
            await acceptLoop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }

        await Task.WhenAll(sessions.Keys).WaitAsync(StopTimeout, cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        handler?.Dispose();
        if (socketPath is not null && File.Exists(socketPath))
        {
            File.Delete(socketPath);
            Log.Stopped(logger);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        shutdown.Dispose();
    }

    /// <summary>The PID of the process on the other end of a Unix socket.</summary>
    internal static int PeerProcessId(Socket socket)
    {
        Span<byte> buffer = stackalloc byte[Marshal.SizeOf<Libc.UCred>()];
        var length = socket.GetRawSocketOption(Libc.SolSocket, Libc.SoPeerCred, buffer);
        return length >= sizeof(int) ? MemoryMarshal.Read<Libc.UCred>(buffer).ProcessId : 0;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener!.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                Log.AcceptFailed(logger, ex.Message);
                continue;
            }

            var processId = PeerProcessId(client);
            if (processId <= 0)
            {
                client.Dispose();
                continue;
            }

            var session = ServeAsync(client, processId, cancellationToken);
            sessions[session] = processId;
            _ = session.ContinueWith(completed => sessions.TryRemove(completed, out _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private async Task ServeAsync(Socket client, int processId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        using (client)
        {
            await using var stream = new NetworkStream(client, ownsSocket: false);
            try
            {
                await HookSession.RunAsync(stream, processId, handler!, logger, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException)
            {
                // The process exited or the service is stopping.
            }
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 2300, Level = LogLevel.Information, Message = "Preload capture started; hooks register on {Socket}")]
        public static partial void Started(ILogger logger, string socket);

        [LoggerMessage(EventId = 2301, Level = LogLevel.Information, Message = "Preload capture stopped; hooked processes now refuse new connections")]
        public static partial void Stopped(ILogger logger);

        [LoggerMessage(EventId = 2302, Level = LogLevel.Warning, Message = "Accepting a hook connection failed: {Reason}")]
        public static partial void AcceptFailed(ILogger logger, string reason);
    }
}
