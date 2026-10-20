using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Hooking;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Platform.Windows.Injection;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// User-mode capture: processes started with <c>proxynator run</c> or attached with <c>proxynator attach</c> (and
/// their children) carry the hook DLL, which asks this backend over the named pipe <see cref="CaptureContext.HookEndpoint"/>
/// before every connect. Only those processes are affected; nothing is installed system-wide, so stopping the service
/// leaves the host untouched (hooked processes then fail closed).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class InjectionCaptureBackend : ICaptureBackend
{
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(5);

    private readonly IProcessInfoProvider processes;
    private readonly ILogger logger;
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentDictionary<Task, int> sessions = new();
    private HookRequestHandler? handler;
    private NamedPipeServerStream? firstInstance;
    private Task? acceptLoop;
    private string? pipeName;

    /// <summary>Creates the backend.</summary>
    public InjectionCaptureBackend(IProcessInfoProvider processes, ILogger<InjectionCaptureBackend> logger)
    {
        this.processes = processes;
        this.logger = logger;
    }

    /// <inheritdoc />
    public CaptureMode Mode => CaptureMode.Injection;

    /// <inheritdoc />
    /// <remarks>Hooked sockets connect to the relay over loopback only, from the same address family.</remarks>
    public IReadOnlyList<IPEndPoint> RelayListenEndpoints =>
        Socket.OSSupportsIPv6
            ? [new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)]
            : [new IPEndPoint(IPAddress.Loopback, 0)];

    /// <summary>The number of hooked processes currently connected.</summary>
    public int HookedProcesses => sessions.Values.Distinct().Count();

    /// <inheritdoc />
    public string Activity => string.Create(CultureInfo.InvariantCulture, $"{HookedProcesses} hooked process(es)");

    /// <inheritdoc />
    public async Task StartAsync(CaptureContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (handler is not null)
        {
            throw new InvalidOperationException("The capture backend has already been started.");
        }

        pipeName = context.HookEndpoint ?? throw new InvalidOperationException("The injection capture mode needs a hook endpoint.");
        var missing = HookLibrary.Missing();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"The hook DLLs are missing in {HookLibrary.Directory}: {string.Join(", ", missing)}. Build them with build/build-native.ps1 (see README).");
        }

        if (context.Configuration.Current.Settings.Capture.ProxyLoopback)
        {
            Log.LoopbackNotSupported(logger);
        }

        handler = new HookRequestHandler(context, processes, logger);
        await handler.InitializeAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // The first instance must not exist yet: otherwise another process owns the name and would answer the hooks.
            firstInstance = CreateInstance(first: true);
        }
        catch (IOException ex)
        {
            handler.Dispose();
            handler = null;
            throw new InvalidOperationException($"Cannot create the hook pipe {HookLibrary.PipePath(pipeName)} (is another proxynatord running?): {ex.Message}", ex);
        }

        acceptLoop = Task.Run(() => AcceptLoopAsync(shutdown.Token), CancellationToken.None);
        var pipePath = HookLibrary.PipePath(pipeName);
        var relays = string.Join(", ", context.RelayEndpoints);
        Log.Started(logger, pipePath, relays);
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (shutdown.IsCancellationRequested)
        {
            return;
        }

        await shutdown.CancelAsync().ConfigureAwait(false);
        if (acceptLoop is not null)
        {
            await acceptLoop.ConfigureAwait(false);
        }

        await Task.WhenAll(sessions.Keys).WaitAsync(StopTimeout, cancellationToken).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        handler?.Dispose();
        if (pipeName is not null)
        {
            Log.Stopped(logger);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        shutdown.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        var next = firstInstance;
        firstInstance = null;
        while (!cancellationToken.IsCancellationRequested)
        {
            var server = next ?? CreateInstance(first: false);
            next = null;
            try
            {
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch (IOException ex)
            {
                Log.AcceptFailed(logger, ex.Message);
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            if (!PipeNative.GetNamedPipeClientProcessId(server.SafePipeHandle, out var clientProcessId))
            {
                await server.DisposeAsync().ConfigureAwait(false);
                continue;
            }

            var session = ServeAsync(server, (int)clientProcessId, cancellationToken);
            sessions[session] = (int)clientProcessId;
            _ = session.ContinueWith(completed => sessions.TryRemove(completed, out _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream server, int processId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        await using (server.ConfigureAwait(false))
        {
            try
            {
                await HookSession.RunAsync(server, processId, handler!, logger, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // The process exited or the service is stopping.
            }

            Log.SessionEnded(logger, processes.GetProcessInfo(processId)?.Name ?? "?", processId);
        }
    }

    private NamedPipeServerStream CreateInstance(bool first) =>
        NamedPipeServerStreamAcl.Create(
            pipeName!,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
            inBufferSize: 0,
            outBufferSize: 0,
            CreatePipeSecurity());

    /// <summary>
    /// Hooked processes run as any user, including AppContainer processes, so all authenticated users and app packages
    /// may connect (but not create instances). The service identifies callers by the pipe client PID, never by what
    /// they claim.
    /// </summary>
    private static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                     identity.User!,
                 })
        {
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                     new SecurityIdentifier("S-1-15-2-1"), // ALL APPLICATION PACKAGES
                 })
        {
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }

        return security;
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 2100, Level = LogLevel.Information, Message = "Injection capture started; hooks register on {Pipe}, relay on {Relay}")]
        public static partial void Started(ILogger logger, string pipe, string relay);

        [LoggerMessage(EventId = 2101, Level = LogLevel.Information, Message = "Injection capture stopped; hooked processes now refuse new connections")]
        public static partial void Stopped(ILogger logger);

        [LoggerMessage(EventId = 2102, Level = LogLevel.Warning, Message = "Accepting a hook connection failed: {Reason}")]
        public static partial void AcceptFailed(ILogger logger, string reason);

        [LoggerMessage(EventId = 2103, Level = LogLevel.Debug, Message = "Hooked process {Process} (pid {ProcessId}) disconnected")]
        public static partial void SessionEnded(ILogger logger, string process, int processId);

        [LoggerMessage(EventId = 2104, Level = LogLevel.Warning, Message = "settings.capture.proxyLoopback is not supported by the injection backend yet; loopback connections are not redirected")]
        public static partial void LoopbackNotSupported(ILogger logger);
    }
}
