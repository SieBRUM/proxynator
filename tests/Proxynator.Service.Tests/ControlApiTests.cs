using System.Net;
using System.Net.Sockets;
using Grpc.Core;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Ipc.V1;
using Proxynator.Core.Tests.Support;
using IpcCaptureState = Proxynator.Ipc.V1.CaptureState;

namespace Proxynator.Service.Tests;

public class ControlApiTests
{
    private static string SampleConfig => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", "config.json"));

    [Fact]
    public async Task Status_reports_service_state()
    {
        await using var service = await TestService.StartAsync();

        var status = await service.Client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token());

        Assert.Equal(IpcCaptureState.Disabled, status.Capture.State);
        Assert.Equal("none", status.Capture.Mode);
        Assert.Equal("Test", status.Platform);
        Assert.Equal(service.ConfigPath, status.ConfigPath);
        Assert.Equal(0, status.RuleCount);
        Assert.Single(status.RelayEndpoints);
        Assert.Equal(Environment.ProcessId, status.ProcessId);
    }

    [Fact]
    public async Task Invalid_config_is_rejected_and_nothing_changes()
    {
        await using var service = await TestService.StartAsync();

        var response = await service.Client.ApplyConfigAsync(
            new ApplyConfigRequest { Json = """{ "version": 1, "rules": [ { "name": "r", "action": { "type": "proxy", "target": "x" } } ] }""", Persist = true },
            cancellationToken: TestTimeout.Token());

        Assert.False(response.Applied);
        Assert.Equal("$.rules[0].action.target", Assert.Single(response.Errors).Path);
        Assert.False(File.Exists(service.ConfigPath));
        Assert.Empty((await service.Client.ListRulesAsync(new ListRulesRequest(), cancellationToken: TestTimeout.Token())).Rules);
    }

    [Fact]
    public async Task Valid_config_is_applied_saved_and_listed()
    {
        await using var service = await TestService.StartAsync();

        var response = await service.Client.ApplyConfigAsync(new ApplyConfigRequest { Json = SampleConfig, Persist = true }, cancellationToken: TestTimeout.Token());

        Assert.True(response.Applied);
        Assert.True(response.Persisted);
        Assert.Equal(SampleConfig, await File.ReadAllTextAsync(service.ConfigPath));

        var rules = (await service.Client.ListRulesAsync(new ListRulesRequest(), cancellationToken: TestTimeout.Token())).Rules;
        Assert.Equal(["test via SOCKS5", "test3 web traffic via Burp", "curl via chain", "default"], rules.Select(r => r.Name));
        Assert.Equal(["pivot", "burp"], rules[2].Route);
        Assert.Equal("processes=test3.exe; ports=80,443", rules[1].Match);
        Assert.Equal("direct", rules[3].Action);

        var config = await service.Client.GetConfigAsync(new GetConfigRequest(), cancellationToken: TestTimeout.Token());
        Assert.Contains("\"pivot-then-burp\"", config.Json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Saved_config_is_loaded_on_start()
    {
        await using var service = await TestService.StartAsync(initialConfigJson: SampleConfig);

        var status = await service.Client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token());

        Assert.Equal(4, status.RuleCount);
    }

    [Fact]
    public async Task Relayed_connections_are_listed_and_streamed()
    {
        var ct = TestTimeout.Token();
        var platform = new TestPlatformModule();
        platform.Processes[4242] = new ProcessInfo(4242, "app.exe", @"C:\app.exe");
        await using var service = await TestService.StartAsync(platform);
        await using var echo = new EchoServer();
        using var watch = service.Client.WatchConnections(new WatchConnectionsRequest(), cancellationToken: ct);
        await Task.Delay(200, ct); // let the watch subscribe

        // Simulate a capture backend: register the client endpoint, then connect to the relay.
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Engine.Destinations.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(echo.Endpoint, 4242));
        await client.ConnectAsync(service.Engine.Relay!.LocalEndpoints[0], ct);
        await client.SendAsync("ping"u8.ToArray(), ct);
        Assert.Equal("ping", await client.ReceiveStringAsync(4, ct));

        var listed = Assert.Single((await service.Client.ListConnectionsAsync(new ListConnectionsRequest(), cancellationToken: ct)).Connections);
        Assert.Equal(("app.exe", 4242, "direct"), (listed.ProcessName, listed.ProcessId, listed.Action));
        Assert.Equal(echo.Endpoint.ToString(), listed.Destination);

        client.Shutdown(SocketShutdown.Send);
        Assert.True(await client.IsClosedByPeerAsync(ct));

        Assert.True(await watch.ResponseStream.MoveNext(ct));
        Assert.Equal(ConnectionEvent.Types.Kind.Opened, watch.ResponseStream.Current.Kind);
        Assert.True(await watch.ResponseStream.MoveNext(ct));
        var closed = watch.ResponseStream.Current;
        Assert.Equal(ConnectionEvent.Types.Kind.Closed, closed.Kind);
        Assert.Equal((4, 4), (closed.Connection.BytesSent, closed.Connection.BytesReceived));
    }

    [Fact]
    public async Task Diagnostics_include_platform_relay_and_proxy_checks()
    {
        await using var service = await TestService.StartAsync();
        await service.Client.ApplyConfigAsync(
            new ApplyConfigRequest { Json = """{ "version": 1, "proxies": [ { "id": "down", "type": "socks5", "host": "127.0.0.1", "port": 1 } ] }""" },
            cancellationToken: TestTimeout.Token());

        var results = (await service.Client.RunDiagnosticsAsync(new RunDiagnosticsRequest(), cancellationToken: TestTimeout.Token())).Results;

        Assert.Contains(results, r => r.Name == "Test platform" && r.Status == DiagnosticStatus.Ok);
        Assert.Contains(results, r => r.Name == "Relay" && r.Status == DiagnosticStatus.Ok);
        Assert.Contains(results, r => r.Name == "Capture" && r.Status == DiagnosticStatus.Warning);
        Assert.Contains(results, r => r.Name == "Proxy 'down'" && r.Status == DiagnosticStatus.Error);
    }

    [Fact]
    public async Task Remote_dns_mode_is_reported_by_status_and_diagnostics()
    {
        await using var service = await TestService.StartAsync(initialConfigJson: """{ "version": 1, "settings": { "dns": { "mode": "remote" } } }""");

        var status = await service.Client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token());
        var results = (await service.Client.RunDiagnosticsAsync(new RunDiagnosticsRequest(), cancellationToken: TestTimeout.Token())).Results;

        Assert.Equal("remote", status.DnsMode);
        Assert.Contains(results, r => r.Name == "Remote DNS");
    }

    [Fact]
    public async Task Service_refuses_to_start_without_privileges_when_capturing()
    {
        var ex = await Assert.ThrowsAsync<ServiceStartupException>(() =>
            TestService.StartAsync(new TestPlatformModule { Privileged = false, Backend = new FakeCaptureBackend() }, noCapture: false));

        Assert.Equal(ServiceStartupException.InsufficientPrivileges, ex.ExitCode);
    }

    [Fact]
    public async Task Invalid_config_file_stops_startup()
    {
        var ex = await Assert.ThrowsAsync<ServiceStartupException>(() =>
            TestService.StartAsync(initialConfigJson: """{ "version": 1, "rules": [ { "name": "r", "action": { "type": "block", "target": "x" } } ] }"""));

        Assert.Equal(ServiceStartupException.InvalidConfiguration, ex.ExitCode);
    }

    [Fact]
    public async Task Unsupported_capture_is_reported_as_failed_but_the_service_stays_up()
    {
        await using var service = await TestService.StartAsync(new TestPlatformModule(), noCapture: false);

        var status = await service.Client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token());

        Assert.Equal(IpcCaptureState.Failed, status.Capture.State);
        Assert.Contains("not supported", status.Capture.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Capture_backend_gets_the_relay_endpoints_and_is_stopped_on_shutdown()
    {
        var backend = new FakeCaptureBackend();
        var service = await TestService.StartAsync(new TestPlatformModule { Backend = backend }, noCapture: false);

        var status = await service.Client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token());
        Assert.Equal(IpcCaptureState.Running, status.Capture.State);
        Assert.Equal("windivert", status.Capture.Mode);
        Assert.Equal(service.Engine.Relay!.LocalEndpoints, backend.Context!.RelayEndpoints);
        Assert.Equal(Environment.ProcessId, backend.Context.ServiceProcessId);
        Assert.NotEqual(0, backend.Context.RelayEndpoints[0].Port);
        Assert.Equal(service.Engine.UdpRelay!.LocalEndpoints, backend.Context.UdpRelayEndpoints);
        Assert.Same(service.Engine.UdpDestinations, backend.Context.UdpDestinations);
        Assert.Same(service.Engine.FakeIps, backend.Context.FakeIps);
        Assert.Single(status.UdpRelayEndpoints);
        Assert.Equal("sniff", status.DnsMode);

        await service.DisposeAsync();
        Assert.True(backend.Stopped);
    }

    [Fact]
    public async Task Unreachable_service_reports_unavailable()
    {
        var directory = Directory.CreateTempSubdirectory("pn-").FullName;
        using var channel = Proxynator.Ipc.ControlClientFactory.CreateChannel(TestService.NewEndpoint(directory));
        var client = Proxynator.Ipc.ControlClientFactory.CreateClient(channel);

        var ex = await Assert.ThrowsAsync<RpcException>(async () => await client.GetStatusAsync(new GetStatusRequest(), cancellationToken: TestTimeout.Token()));

        Assert.Equal(StatusCode.Unavailable, ex.StatusCode);
    }
}
