using System.Globalization;
using Grpc.Core;
using Proxynator.Client;
using Proxynator.Core.Configuration;
using Proxynator.Ipc;
using Proxynator.Ipc.V1;

namespace Proxynator.Cli;

/// <summary>Implementations of the CLI commands. Output goes to <c>output</c>/<c>error</c> so tests can capture it.</summary>
internal sealed class Commands(string endpoint, TextWriter output, TextWriter error)
{
    public async Task<int> StatusAsync(CancellationToken cancellationToken) => await CallAsync(async client =>
    {
        var status = await client.GetStatusAsync(new GetStatusRequest(), cancellationToken: cancellationToken);
        var uptime = DateTimeOffset.UtcNow - status.StartedAt.ToDateTimeOffset();
        output.WriteLine($"proxynatord {status.Version} on {status.Platform} (pid {status.ProcessId}), up {DisplayFormat.Duration(uptime)}");
        var activity = status.Capture.Activity.Length > 0 ? $" ({status.Capture.Activity})" : string.Empty;
        output.WriteLine($"Capture:      {status.Capture.Mode} - {DescribeState(status.Capture.State)}{activity}");
        if (status.Capture.State is CaptureState.Failed or CaptureState.Disabled)
        {
            output.WriteLine($"              {status.Capture.Detail}");
        }

        output.WriteLine($"Relay:        TCP {string.Join(", ", status.RelayEndpoints)}; UDP {string.Join(", ", status.UdpRelayEndpoints)}");
        output.WriteLine($"DNS mode:     {status.DnsMode}{(status.DnsMode == "remote" ? $" ({status.FakeIpCount} name(s) on fake addresses)" : string.Empty)}");
        output.WriteLine($"Config:       {status.ConfigPath} ({status.RuleCount} active rule(s))");
        output.WriteLine($"Connections:  {status.ActiveConnections} active");
        output.WriteLine($"Privileged:   {(status.Privileged ? "yes" : "no")}");
        return status.Capture.State == CaptureState.Failed ? ExitCodes.Failure : ExitCodes.Success;
    }).ConfigureAwait(false);

    public async Task<int> ValidateConfigAsync(string path, CancellationToken cancellationToken)
    {
        var result = await ConfigLoader.LoadFileAsync(path, cancellationToken).ConfigureAwait(false);
        if (!result.Success)
        {
            WriteErrors(path, result.Errors.Select(e => (e.Path, e.Message)));
            return ExitCodes.Failure;
        }

        var config = result.Config;
        output.WriteLine($"{path} is valid: {config.Proxies.Count} prox(ies), {config.Chains.Count} chain(s), {config.Rules.Count} rule(s).");
        return ExitCodes.Success;
    }

    public async Task<int> LoadConfigAsync(string path, bool save, CancellationToken cancellationToken)
    {
        string json;
        try
        {
            json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"Cannot read {path}: {ex.Message}");
            return ExitCodes.Failure;
        }

        return await CallAsync(async client =>
        {
            var response = await client.ApplyConfigAsync(new ApplyConfigRequest { Json = json, Persist = save }, cancellationToken: cancellationToken);
            if (!response.Applied)
            {
                WriteErrors(path, response.Errors.Select(e => (e.Path, e.Message)));
                error.WriteLine("The configuration was NOT applied; the previous configuration is still active.");
                return ExitCodes.Failure;
            }

            output.WriteLine("Configuration applied. New connections use it; existing connections are not affected.");
            if (response.Persisted)
            {
                output.WriteLine("Saved as the service configuration.");
            }
            else if (response.PersistError.Length > 0)
            {
                error.WriteLine($"Warning: could not save it as the service configuration: {response.PersistError}");
            }

            if (response.RestartRequiredReason.Length > 0)
            {
                error.WriteLine($"Note: {response.RestartRequiredReason}");
            }

            return response.PersistError.Length > 0 ? ExitCodes.Failure : ExitCodes.Success;
        }).ConfigureAwait(false);
    }

    public async Task<int> ShowConfigAsync(CancellationToken cancellationToken) => await CallAsync(async client =>
    {
        var response = await client.GetConfigAsync(new GetConfigRequest(), cancellationToken: cancellationToken);
        output.WriteLine(response.Json);
        return ExitCodes.Success;
    }).ConfigureAwait(false);

    public async Task<int> ListRulesAsync(CancellationToken cancellationToken) => await CallAsync(async client =>
    {
        var response = await client.ListRulesAsync(new ListRulesRequest(), cancellationToken: cancellationToken);
        if (response.Rules.Count == 0)
        {
            output.WriteLine("No rules configured: all traffic goes direct.");
            return ExitCodes.Success;
        }

        var rows = response.Rules.Select((rule, index) => (IReadOnlyList<string>)
        [
            (index + 1).ToString(CultureInfo.InvariantCulture),
            rule.Name + (rule.Enabled ? string.Empty : " (disabled)"),
            rule.Match,
            rule.Action == "proxy" ? $"proxy via {string.Join(" -> ", rule.Route)}" : rule.Action,
        ]);
        Format.Table(output, ["#", "RULE", "MATCH", "ACTION"], rows);
        output.WriteLine("Rules are evaluated top to bottom; the first match wins. Unmatched traffic goes direct.");
        return ExitCodes.Success;
    }).ConfigureAwait(false);

    public async Task<int> ConnectionsAsync(bool follow, CancellationToken cancellationToken) => await CallAsync(async client =>
    {
        var response = await client.ListConnectionsAsync(new ListConnectionsRequest(), cancellationToken: cancellationToken);
        if (response.Connections.Count == 0)
        {
            output.WriteLine("No active relayed connections.");
        }
        else
        {
            var now = DateTimeOffset.UtcNow;
            var rows = response.Connections.Select(c => (IReadOnlyList<string>)
            [
                c.Id.ToString(CultureInfo.InvariantCulture),
                c.Protocol,
                DescribeProcess(c),
                c.Destination,
                c.Rule,
                c.Action == "proxy" ? c.Route : c.Action,
                DisplayFormat.Bytes(c.BytesSent),
                DisplayFormat.Bytes(c.BytesReceived),
                DisplayFormat.Duration(now - c.StartedAt.ToDateTimeOffset()),
            ]);
            Format.Table(output, ["ID", "PROTO", "PROCESS", "DESTINATION", "RULE", "VIA", "SENT", "RECEIVED", "AGE"], rows);
        }

        if (!follow)
        {
            return ExitCodes.Success;
        }

        output.WriteLine("Watching for connections (Ctrl+C to stop)...");
        using var call = client.WatchConnections(new WatchConnectionsRequest(), cancellationToken: cancellationToken);
        try
        {
            await foreach (var connectionEvent in call.ResponseStream.ReadAllAsync(cancellationToken))
            {
                var c = connectionEvent.Connection;
                output.WriteLine(connectionEvent.Kind == ConnectionEvent.Types.Kind.Opened
                    ? $"+ #{c.Id} {c.Protocol} {DescribeProcess(c)} -> {c.Destination}  [{c.Rule}] {(c.Action == "proxy" ? "via " + c.Route : c.Action)}"
                    : $"- #{c.Id} {c.Destination} closed: {DisplayFormat.Bytes(c.BytesSent)} sent, {DisplayFormat.Bytes(c.BytesReceived)} received");
            }
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Cancelled || cancellationToken.IsCancellationRequested)
        {
            // Ctrl+C
        }

        return ExitCodes.Success;
    }).ConfigureAwait(false);

    public async Task<int> DoctorAsync(CancellationToken cancellationToken)
    {
        var exitCode = await CallAsync(async client =>
        {
            Write(DiagnosticStatus.Ok, "Service", $"proxynatord is reachable at {IpcEndpoint.Describe(endpoint)}.");
            var response = await client.RunDiagnosticsAsync(new RunDiagnosticsRequest(), cancellationToken: cancellationToken);
            foreach (var result in response.Results)
            {
                Write(result.Status, result.Name, result.Detail);
            }

            return response.Results.Any(r => r.Status == DiagnosticStatus.Error) ? ExitCodes.Failure : ExitCodes.Success;
        }).ConfigureAwait(false);
        return exitCode;

        void Write(DiagnosticStatus status, string name, string detail)
        {
            var label = status switch
            {
                DiagnosticStatus.Ok => "[ OK ]",
                DiagnosticStatus.Warning => "[WARN]",
                _ => "[FAIL]",
            };
            output.WriteLine($"{label} {name}: {detail}");
        }
    }

    private async Task<int> CallAsync(Func<Control.ControlClient, Task<int>> action)
    {
        using var channel = ControlClientFactory.CreateChannel(endpoint);
        try
        {
            return await action(ControlClientFactory.CreateClient(channel)).ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unavailable)
        {
            foreach (var line in ServiceHints.Unreachable(endpoint))
            {
                error.WriteLine(line);
            }

            return ExitCodes.ServiceUnreachable;
        }
        catch (RpcException ex)
        {
            error.WriteLine($"proxynatord returned an error: {ex.Status.Detail} ({ex.StatusCode})");
            return ExitCodes.Failure;
        }
    }

    private void WriteErrors(string source, IEnumerable<(string Path, string Message)> errors)
    {
        error.WriteLine($"{source} is invalid:");
        foreach (var (path, message) in errors)
        {
            error.WriteLine($"  {path}: {message}");
        }
    }

    private static string DescribeProcess(Connection connection) =>
        connection.ProcessName.Length > 0 ? $"{connection.ProcessName} ({connection.ProcessId})" : $"pid {connection.ProcessId}";

    private static string DescribeState(CaptureState state) => state switch
    {
        CaptureState.Running => "running",
        CaptureState.Disabled => "disabled",
        CaptureState.Failed => "FAILED (traffic is not being redirected)",
        CaptureState.Stopped => "stopped",
        _ => "unknown",
    };
}
