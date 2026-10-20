using System.Net;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Relay;

namespace Proxynator.Service;

/// <summary>
/// Owns the running pieces: configuration store, relay, capture backend and connection tracker. Started and stopped
/// by the host; used by the control API.
/// </summary>
internal sealed partial class ProxynatorEngine(ServiceOptions options, IPlatformModule platform, ILoggerFactory loggerFactory) : IHostedService, IDisposable
{
    private static readonly TimeSpan ProxyProbeTimeout = TimeSpan.FromSeconds(3);

    private readonly ILogger logger = loggerFactory.CreateLogger<ProxynatorEngine>();
    private readonly SemaphoreSlim applyLock = new(1, 1);
    private ICaptureBackend? capture;

    public ServiceOptions Options => options;

    public IPlatformModule Platform => platform;

    public DateTimeOffset StartedAt { get; private set; }

    public PrivilegeCheckResult Privileges { get; private set; } = new(false, "Not checked yet.");

    public ConfigurationStore Configuration { get; private set; } = null!;

    public OriginalDestinationTable Destinations { get; } = new();

    public ConnectionTracker Tracker { get; } = new();

    public RelayServer? Relay { get; private set; }

    /// <summary>The capture mode in effect (resolved from <see cref="CaptureMode.Auto"/>), or null with --no-capture.</summary>
    public CaptureMode? CaptureMode { get; private set; }

    public CaptureState CaptureState { get; private set; } = CaptureState.Stopped;

    public string CaptureDetail { get; private set; } = string.Empty;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        StartedAt = DateTimeOffset.UtcNow;
        Privileges = platform.PrivilegeChecker.Check();
        if (!Privileges.IsSufficient)
        {
            if (!options.NoCapture)
            {
                throw new ServiceStartupException(ServiceStartupException.InsufficientPrivileges, Privileges.Description);
            }

            Log.UnprivilegedWithoutCapture(logger, Privileges.Description);
        }

        Configuration = new ConfigurationStore(await LoadInitialConfigurationAsync(cancellationToken).ConfigureAwait(false));

        if (options.NoCapture)
        {
            CaptureState = CaptureState.Disabled;
            CaptureDetail = "Capture disabled with --no-capture.";
        }
        else
        {
            CreateCaptureBackend();
        }

        Relay = new RelayServer(Configuration, Destinations, platform.ProcessInfo, Tracker, loggerFactory.CreateLogger<RelayServer>());
        Relay.Start(capture?.RelayListenEndpoints ?? [new IPEndPoint(IPAddress.Loopback, 0)]);

        if (capture is not null)
        {
            await StartCaptureAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // Capture first, so no new connections are redirected to a relay that is going away.
        if (capture is not null)
        {
            await capture.DisposeAsync().ConfigureAwait(false);
            capture = null;
        }

        CaptureState = CaptureState.Stopped;
        if (Relay is not null)
        {
            await Relay.DisposeAsync().ConfigureAwait(false);
        }
    }

    public void Dispose() => applyLock.Dispose();

    /// <summary>Validates, applies and optionally saves a configuration. Never partially applies.</summary>
    public async Task<ConfigApplyResult> ApplyConfigAsync(string json, bool persist, CancellationToken cancellationToken)
    {
        var loaded = ConfigLoader.Parse(json);
        if (!loaded.Success)
        {
            return new ConfigApplyResult(false, loaded.Errors);
        }

        await applyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var errors = Configuration.TryApply(loaded.Config);
            if (errors.Count > 0)
            {
                return new ConfigApplyResult(false, errors);
            }

            Log.ConfigurationApplied(logger, loaded.Config.Rules.Count, loaded.Config.Proxies.Count);
            var restartReason = RestartReason(loaded.Config);
            if (!persist)
            {
                return new ConfigApplyResult(true, [], RestartRequiredReason: restartReason);
            }

            try
            {
                await ConfigFile.SaveAsync(options.ConfigPath, json, cancellationToken).ConfigureAwait(false);
                return new ConfigApplyResult(true, [], Persisted: true, RestartRequiredReason: restartReason);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Log.SaveFailed(logger, options.ConfigPath, ex.Message);
                return new ConfigApplyResult(true, [], PersistError: ex.Message, RestartRequiredReason: restartReason);
            }
        }
        finally
        {
            applyLock.Release();
        }
    }

    /// <summary>Platform checks plus service-level checks (configuration, capture, relay, proxy reachability).</summary>
    public async Task<IReadOnlyList<DiagnosticResult>> RunDiagnosticsAsync(CancellationToken cancellationToken)
    {
        var results = new List<DiagnosticResult>(platform.RunDiagnostics());
        var active = Configuration.Current;

        results.Add(new DiagnosticResult(
            "Configuration",
            DiagnosticStatus.Ok,
            $"{options.ConfigPath}{(File.Exists(options.ConfigPath) ? string.Empty : " (not saved yet)")}: {active.Rules.Count} active rule(s), {active.Config.Proxies.Count} prox(ies), {active.Config.Chains.Count} chain(s)."));

        results.Add(CaptureState switch
        {
            CaptureState.Running => new DiagnosticResult("Capture", DiagnosticStatus.Ok, $"{CaptureMode} capture is running."),
            CaptureState.Disabled => new DiagnosticResult("Capture", DiagnosticStatus.Warning, CaptureDetail),
            _ => new DiagnosticResult("Capture", DiagnosticStatus.Error, CaptureDetail),
        });

        results.Add(Relay is { LocalEndpoints.Count: > 0 }
            ? new DiagnosticResult("Relay", DiagnosticStatus.Ok, $"Listening on {string.Join(", ", Relay.LocalEndpoints)}.")
            : new DiagnosticResult("Relay", DiagnosticStatus.Error, "The relay is not listening."));

        if (active.Config.Rules.Count == 0)
        {
            results.Add(new DiagnosticResult("Rules", DiagnosticStatus.Warning, "No rules are configured, so all traffic goes direct. Load a configuration with 'proxynator config load <file>'."));
        }

        var probes = active.Config.Proxies.Select(proxy => ProbeProxyAsync(proxy, cancellationToken));
        results.AddRange(await Task.WhenAll(probes).ConfigureAwait(false));
        return results;
    }

    private static async Task<DiagnosticResult> ProbeProxyAsync(ProxyDefinition proxy, CancellationToken cancellationToken)
    {
        var name = $"Proxy '{proxy.Id}'";
        var endpoint = TargetEndpoint.FromHost(proxy.Host, proxy.Port);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(ProxyProbeTimeout);
        try
        {
            await using var stream = (await TcpConnector.Default.ConnectAsync(endpoint, timeout.Token).ConfigureAwait(false)).ConfigureAwait(false);
            return new DiagnosticResult(name, DiagnosticStatus.Ok, $"{proxy.Type.ToString().ToLowerInvariant()} proxy at {endpoint} is accepting connections.");
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException ||
                                   (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            var reason = ex is OperationCanceledException ? "timed out" : ex.Message;
            return new DiagnosticResult(name, DiagnosticStatus.Error, $"Cannot connect to {endpoint}: {reason}. Connections routed through it will be refused.");
        }
    }

    private async Task<ProxynatorConfig> LoadInitialConfigurationAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(options.ConfigPath))
        {
            Log.NoConfiguration(logger, options.ConfigPath);
            return new ProxynatorConfig { Version = ConfigVersion.Current };
        }

        var loaded = await ConfigLoader.LoadFileAsync(options.ConfigPath, cancellationToken).ConfigureAwait(false);
        if (!loaded.Success)
        {
            throw new ServiceStartupException(
                ServiceStartupException.InvalidConfiguration,
                $"The configuration file {options.ConfigPath} is invalid:{Environment.NewLine}  " + string.Join(Environment.NewLine + "  ", loaded.Errors));
        }

        Log.ConfigurationLoaded(logger, options.ConfigPath, loaded.Config.Rules.Count, loaded.Config.Proxies.Count);
        return loaded.Config;
    }

    private void CreateCaptureBackend()
    {
        var configured = Configuration.Current.Settings.Capture.Mode;
        var mode = configured == Core.Configuration.CaptureMode.Auto ? platform.DefaultCaptureMode : configured;
        CaptureMode = mode;
        try
        {
            capture = platform.CreateCaptureBackend(mode, loggerFactory);
        }
        catch (NotSupportedException ex)
        {
            Fail(ex.Message);
        }
    }

    private async Task StartCaptureAsync(CancellationToken cancellationToken)
    {
        try
        {
            await capture!.StartAsync(
                new CaptureContext(Configuration, Destinations, Relay!.LocalEndpoints, Environment.ProcessId),
                cancellationToken).ConfigureAwait(false);
            CaptureState = CaptureState.Running;
            CaptureDetail = $"{CaptureMode} capture is running.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            await capture!.DisposeAsync().ConfigureAwait(false);
            capture = null;
            Fail(ex.Message);
        }
    }

    private void Fail(string reason)
    {
        CaptureState = CaptureState.Failed;
        CaptureDetail = reason;
        Log.CaptureFailed(logger, reason);
    }

    private string? RestartReason(ProxynatorConfig config)
    {
        if (options.NoCapture || CaptureMode is null)
        {
            return null;
        }

        var requested = config.Settings.Capture.Mode == Core.Configuration.CaptureMode.Auto ? platform.DefaultCaptureMode : config.Settings.Capture.Mode;
        return requested != CaptureMode
            ? $"The capture mode changed from '{CaptureMode}' to '{requested}'; restart proxynatord to switch."
            : null;
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 3000, Level = LogLevel.Information, Message = "Loaded {Path}: {Rules} rule(s), {Proxies} prox(ies)")]
        public static partial void ConfigurationLoaded(ILogger logger, string path, int rules, int proxies);

        [LoggerMessage(EventId = 3001, Level = LogLevel.Warning, Message = "No configuration at {Path}; starting with no rules (all traffic direct). Use 'proxynator config load <file>'.")]
        public static partial void NoConfiguration(ILogger logger, string path);

        [LoggerMessage(EventId = 3002, Level = LogLevel.Error, Message = "Traffic capture is NOT active: {Reason}")]
        public static partial void CaptureFailed(ILogger logger, string reason);

        [LoggerMessage(EventId = 3003, Level = LogLevel.Information, Message = "Applied new configuration: {Rules} rule(s), {Proxies} prox(ies)")]
        public static partial void ConfigurationApplied(ILogger logger, int rules, int proxies);

        [LoggerMessage(EventId = 3004, Level = LogLevel.Error, Message = "The configuration was applied but could not be saved to {Path}: {Reason}")]
        public static partial void SaveFailed(ILogger logger, string path, string reason);

        [LoggerMessage(EventId = 3005, Level = LogLevel.Warning, Message = "Running without required privileges ({Reason}); allowed because capture is disabled")]
        public static partial void UnprivilegedWithoutCapture(ILogger logger, string reason);
    }
}
