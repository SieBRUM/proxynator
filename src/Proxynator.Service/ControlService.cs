using System.Globalization;
using System.Reflection;
using System.Threading.Channels;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Proxynator.Core.Configuration;
using Proxynator.Core.Relay;
using Proxynator.Ipc.V1;
using CorePlatform = Proxynator.Core.Platform;

namespace Proxynator.Service;

/// <summary>The <c>proxynator.v1.Control</c> gRPC service.</summary>
internal sealed class ControlService(ProxynatorEngine engine) : Control.ControlBase
{
    private static readonly string Version =
        typeof(ControlService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    public override Task<GetStatusResponse> GetStatus(GetStatusRequest request, ServerCallContext context)
    {
        var active = engine.Configuration.Current;
        var response = new GetStatusResponse
        {
            Version = Version,
            Platform = engine.Platform.Name,
            StartedAt = Timestamp.FromDateTimeOffset(engine.StartedAt),
            Capture = new CaptureStatus
            {
                Mode = engine.CaptureMode?.ToString().ToLowerInvariant() ?? "none",
                State = engine.CaptureState switch
                {
                    CaptureState.Disabled => Ipc.V1.CaptureState.Disabled,
                    CaptureState.Running => Ipc.V1.CaptureState.Running,
                    CaptureState.Failed => Ipc.V1.CaptureState.Failed,
                    _ => Ipc.V1.CaptureState.Stopped,
                },
                Detail = engine.CaptureDetail,
                Activity = engine.CaptureActivity ?? string.Empty,
            },
            ConfigPath = engine.Options.ConfigPath,
            RuleCount = active.Rules.Count,
            ActiveConnections = engine.Tracker.GetActive().Count,
            Privileged = engine.Privileges.IsSufficient,
            ProcessId = Environment.ProcessId,
        };
        response.RelayEndpoints.AddRange(engine.Relay?.LocalEndpoints.Select(e => e.ToString()) ?? []);
        response.UdpRelayEndpoints.AddRange(engine.UdpRelay?.LocalEndpoints.Select(e => e.ToString()) ?? []);
        response.DnsMode = active.Settings.Dns.Mode.ToString().ToLowerInvariant();
        response.FakeIpCount = engine.FakeIps.Count;
        response.DnsCacheEntries = engine.DnsCache.Count;
        response.DnsCacheSeconds = active.Settings.Dns.CacheSeconds;
        return Task.FromResult(response);
    }

    public override Task<GetConfigResponse> GetConfig(GetConfigRequest request, ServerCallContext context) =>
        Task.FromResult(new GetConfigResponse
        {
            Json = ConfigLoader.Serialize(engine.Configuration.Current.Config),
            Path = engine.Options.ConfigPath,
        });

    public override async Task<ApplyConfigResponse> ApplyConfig(ApplyConfigRequest request, ServerCallContext context)
    {
        var result = await engine.ApplyConfigAsync(request.Json, request.Persist, context.CancellationToken).ConfigureAwait(false);
        var response = new ApplyConfigResponse
        {
            Applied = result.Applied,
            Persisted = result.Persisted,
            PersistError = result.PersistError ?? string.Empty,
            RestartRequiredReason = result.RestartRequiredReason ?? string.Empty,
        };
        response.Errors.AddRange(result.Errors.Select(e => new Ipc.V1.ConfigError { Path = e.Path, Message = e.Message }));
        return response;
    }

    public override Task<ListRulesResponse> ListRules(ListRulesRequest request, ServerCallContext context)
    {
        var active = engine.Configuration.Current;
        var response = new ListRulesResponse();
        foreach (var rule in active.Config.Rules)
        {
            var summary = new RuleSummary
            {
                Name = rule.Name,
                Enabled = rule.Enabled,
                Match = DescribeMatch(rule.Match),
                Action = rule.Action.Type.ToString().ToLowerInvariant(),
                Target = rule.Action.Target ?? string.Empty,
            };
            if (rule.Action.Target is { } target && active.Routes.TryGetValue(target, out var route))
            {
                summary.Route.AddRange(route.Hops.Select(h => h.Id));
            }

            response.Rules.Add(summary);
        }

        return Task.FromResult(response);
    }

    public override Task<ListConnectionsResponse> ListConnections(ListConnectionsRequest request, ServerCallContext context)
    {
        var response = new ListConnectionsResponse();
        response.Connections.AddRange(engine.Tracker.GetActive().Select(ToMessage));
        return Task.FromResult(response);
    }

    public override async Task WatchConnections(WatchConnectionsRequest request, IServerStreamWriter<ConnectionEvent> responseStream, ServerCallContext context)
    {
        var events = Channel.CreateBounded<ConnectionEvent>(new BoundedChannelOptions(1024) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
        void Opened(object? sender, TrackedConnection connection) =>
            events.Writer.TryWrite(new ConnectionEvent { Kind = ConnectionEvent.Types.Kind.Opened, Connection = ToMessage(connection) });
        void Closed(object? sender, TrackedConnection connection) =>
            events.Writer.TryWrite(new ConnectionEvent { Kind = ConnectionEvent.Types.Kind.Closed, Connection = ToMessage(connection) });

        engine.Tracker.Opened += Opened;
        engine.Tracker.Closed += Closed;
        using var watcher = engine.AddConnectionWatcher();
        try
        {
            await foreach (var connectionEvent in events.Reader.ReadAllAsync(context.CancellationToken).ConfigureAwait(false))
            {
                await responseStream.WriteAsync(connectionEvent, context.CancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested)
        {
            // The client stopped watching.
        }
        finally
        {
            engine.Tracker.Opened -= Opened;
            engine.Tracker.Closed -= Closed;
        }
    }

    public override async Task<RunDiagnosticsResponse> RunDiagnostics(RunDiagnosticsRequest request, ServerCallContext context)
    {
        var results = await engine.RunDiagnosticsAsync(context.CancellationToken).ConfigureAwait(false);
        var response = new RunDiagnosticsResponse();
        response.Results.AddRange(results.Select(r => new DiagnosticResult
        {
            Name = r.Name,
            Detail = r.Detail,
            Status = r.Status switch
            {
                CorePlatform.DiagnosticStatus.Ok => Ipc.V1.DiagnosticStatus.Ok,
                CorePlatform.DiagnosticStatus.Warning => Ipc.V1.DiagnosticStatus.Warning,
                _ => Ipc.V1.DiagnosticStatus.Error,
            },
        }));
        return response;
    }

    public override Task<ClearDnsCacheResponse> ClearDnsCache(ClearDnsCacheRequest request, ServerCallContext context)
    {
        var (cleared, systemCleared, systemDetail) = engine.ClearDnsCache(request.IncludeSystem);
        return Task.FromResult(new ClearDnsCacheResponse
        {
            ClearedEntries = cleared,
            SystemCacheCleared = systemCleared,
            SystemCacheDetail = systemDetail,
        });
    }

    internal static string DescribeMatch(RuleMatch match)
    {
        var parts = new List<string>();
        if (match.Processes.Count > 0)
        {
            parts.Add($"processes={string.Join(',', match.Processes)}{(match.IncludeChildren ? " (+children)" : string.Empty)}");
        }

        if (match.Hosts.Count > 0)
        {
            parts.Add($"hosts={string.Join(',', match.Hosts)}");
        }

        if (match.Addresses.Count > 0)
        {
            parts.Add($"addresses={string.Join(',', match.Addresses)}");
        }

        if (match.Ports.Count > 0)
        {
            parts.Add($"ports={string.Join(',', match.Ports)}");
        }

        if (match.Protocols.Count > 0)
        {
            parts.Add($"protocols={string.Join(',', match.Protocols.Select(p => p.ToString().ToLowerInvariant()))}");
        }

        return parts.Count == 0 ? "any" : string.Join("; ", parts);
    }

    private static Connection ToMessage(TrackedConnection connection) => new()
    {
        Id = connection.Id,
        StartedAt = Timestamp.FromDateTimeOffset(connection.StartedAt),
        ProcessId = connection.Context.Process?.ProcessId ?? 0,
        ProcessName = connection.Context.Process?.Name ?? string.Empty,
        ProcessPath = connection.Context.Process?.ExecutablePath ?? string.Empty,
        Destination = connection.Context.DestinationDisplay,
        Rule = connection.Decision.RuleName,
        Action = connection.Decision.Action.ToString().ToLowerInvariant(),
        Route = connection.Decision.Route?.Id ?? string.Empty,
        BytesSent = connection.BytesSent,
        BytesReceived = connection.BytesReceived,
        Protocol = connection.Context.Protocol.ToString().ToLowerInvariant(),
    };
}
