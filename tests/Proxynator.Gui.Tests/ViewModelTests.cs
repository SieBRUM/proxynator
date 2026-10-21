using System.Net;
using System.Net.Sockets;
using Avalonia.Headless.XUnit;
using Proxynator.Core.Configuration;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;
using Proxynator.Gui.Services;
using Proxynator.Gui.ViewModels;
using Proxynator.Ipc.V1;
using Proxynator.Service.Tests;

namespace Proxynator.Gui.Tests;

/// <summary>The GUI's view models against a real in-process proxynatord.</summary>
public class ViewModelTests
{
    [AvaloniaFact]
    public async Task The_overview_shows_status_and_active_rules()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var overview = gui.ViewModel.Overview;

        await overview.RefreshAsync();

        Assert.True(gui.ViewModel.State.IsConnected);
        Assert.StartsWith("none: disabled", overview.Capture, StringComparison.Ordinal);
        Assert.Contains("--no-capture", overview.CaptureDetail, StringComparison.Ordinal);
        Assert.Contains("(4 active rule(s))", overview.Config, StringComparison.Ordinal);
        Assert.Equal(["test via SOCKS5", "test3 web traffic via Burp", "curl via chain", "default"], overview.Rules.Select(r => r.Name));
        Assert.Equal("proxy via pivot → burp", overview.Rules[2].Action);
    }

    [AvaloniaFact]
    public async Task An_unreachable_service_is_explained()
    {
        var endpoint = OperatingSystem.IsWindows() ? $"proxynator-missing-{Guid.NewGuid():N}" : Path.Combine(Path.GetTempPath(), $"pn-missing-{Guid.NewGuid():N}.sock");
        using var viewModel = new MainWindowViewModel(new ServiceConnection(endpoint), new FakeFileDialogs());

        await viewModel.TickAsync();

        Assert.False(viewModel.State.IsConnected);
        Assert.Contains("Cannot reach proxynatord", viewModel.State.Headline, StringComparison.Ordinal);
        Assert.NotEmpty(viewModel.State.Hint);
    }

    [AvaloniaFact]
    public async Task Rules_edited_in_the_gui_are_applied_and_saved()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var rules = gui.ViewModel.Rules;
        Assert.True(gui.Workspace.IsLoaded);
        Assert.False(gui.Workspace.IsDirty);

        rules.SelectedRule = gui.Workspace.Rules[^1];
        rules.AddCommand.Execute(null);
        var rule = rules.SelectedRule!;
        rule.Name = "nxc via pivot";
        rule.Processes = "nxc, python*";
        rule.IncludeChildren = true;
        rule.Ports = "389, 636";
        rule.Udp = false;
        rule.Target = "pivot";

        Assert.True(gui.Workspace.IsDirty);
        Assert.Empty(gui.Workspace.Problems);
        Assert.Equal(3, gui.Workspace.Rules.IndexOf(rule)); // above the catch-all
        Assert.Equal("nxc, python* (+children); port 389, 636; tcp → proxy via pivot", rule.Summary);

        Assert.True(await gui.Workspace.ApplyAsync(persist: true));

        Assert.False(gui.Workspace.IsDirty);
        Assert.StartsWith("Applied and saved.", gui.Workspace.StatusMessage, StringComparison.Ordinal);
        var applied = gui.Service.Engine.Configuration.Current.Config.Rules[3];
        Assert.Equal("nxc via pivot", applied.Name);
        Assert.Equal(["nxc", "python*"], applied.Match.Processes);
        Assert.Equal([Core.Net.TransportProtocol.Tcp], applied.Match.Protocols);
        Assert.Equal("pivot", applied.Action.Target);
        var saved = await ConfigLoader.LoadFileAsync(gui.Service.ConfigPath, TestTimeout.Token());
        Assert.Equal("nxc via pivot", saved.Config!.Rules[3].Name);

        // Untouched parts survive the round trip through the editor.
        Assert.Equal("pass", saved.Config.Proxies.Single(p => p.Id == "pivot").Auth!.Password);
        Assert.Equal(CaptureMode.WinDivert, saved.Config.Settings.Capture.Mode);
    }

    [AvaloniaFact]
    public async Task Invalid_edits_are_reported_in_words_and_never_applied()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var before = gui.Service.Engine.Configuration.Current;

        gui.Workspace.Proxies[0].Port = "five thousand";
        gui.Workspace.Rules[1].Target = "nowhere";
        gui.Workspace.Rules[2].Tcp = false;
        gui.Workspace.Rules[2].Udp = false;

        Assert.Contains("Proxy 'socks-local' (port): Enter a port number.", gui.Workspace.Problems);
        Assert.Contains(gui.Workspace.Problems, p => p.StartsWith("Rule 'test3 web traffic via Burp' (action.target):", StringComparison.Ordinal));
        Assert.Contains("Rule 'curl via chain' (match.protocols): Select TCP, UDP or both.", gui.Workspace.Problems);
        Assert.Equal("3 problems", gui.Workspace.ProblemSummary);

        Assert.False(await gui.Workspace.ApplyAsync(persist: false));
        Assert.Same(before, gui.Service.Engine.Configuration.Current);

        await gui.Workspace.DiscardAsync();
        Assert.False(gui.Workspace.IsDirty);
        Assert.Empty(gui.Workspace.Problems);
        Assert.Equal("5000", gui.Workspace.Proxies[0].Port);
    }

    [AvaloniaFact]
    public async Task Proxies_and_chains_are_edited_and_rule_targets_follow()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var proxies = gui.ViewModel.Proxies;
        Assert.Equal(["socks-local", "burp", "pivot", "pivot-then-burp"], gui.Workspace.TargetIds);

        proxies.AddBurpCommand.Execute(null);
        Assert.Equal("burp2", proxies.SelectedProxy!.Id);
        proxies.SelectedProxy.Id = "burp-dc";
        proxies.SelectedProxy.Username = "u";
        proxies.SelectedProxy.Password = "p";
        proxies.AddChainCommand.Execute(null);
        proxies.SelectedChain!.Hops = "pivot, burp-dc";

        Assert.Contains("burp-dc", gui.Workspace.TargetIds);
        Assert.Contains(proxies.SelectedChain.Id, gui.Workspace.TargetIds);
        Assert.Equal("pivot → burp-dc", proxies.SelectedChain.Summary);
        Assert.Empty(gui.Workspace.Problems);
        Assert.True(await gui.Workspace.ApplyAsync(persist: false));

        var config = gui.Service.Engine.Configuration.Current.Config;
        var burp = config.Proxies.Single(p => p.Id == "burp-dc");
        Assert.Equal((ProxyType.Http, "127.0.0.1", 8080, "u", "p"), (burp.Type, burp.Host, burp.Port, burp.Auth!.Username, burp.Auth.Password));
        Assert.Equal(["pivot", "burp-dc"], config.Chains.Single(c => c.Id == "chain").Hops);

        // Deleting a proxy a rule uses is caught before it reaches the service.
        proxies.SelectedProxy = gui.Workspace.Proxies.Single(p => p.Id == "socks-local");
        proxies.DeleteProxyCommand.Execute(null);
        Assert.Contains(gui.Workspace.Problems, p => p.StartsWith("Rule 'test via SOCKS5'", StringComparison.Ordinal));
    }

    [AvaloniaFact]
    public async Task Testing_a_proxy_reports_whether_it_accepts_connections()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        await using var echo = new EchoServer();
        var proxies = gui.ViewModel.Proxies;
        proxies.SelectedProxy = gui.Workspace.Proxies[0];
        proxies.SelectedProxy.Port = echo.Endpoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);

        await proxies.TestProxyCommand.ExecuteAsync(null);
        Assert.StartsWith("Reachable", proxies.SelectedProxy.TestResult, StringComparison.Ordinal);

        using var unused = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        unused.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        proxies.SelectedProxy.Port = ((IPEndPoint)unused.LocalEndPoint!).Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        await proxies.TestProxyCommand.ExecuteAsync(null);
        Assert.StartsWith("Not reachable", proxies.SelectedProxy.TestResult, StringComparison.Ordinal);
    }

    [AvaloniaFact]
    public async Task Settings_are_edited_and_applied()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var settings = gui.Workspace.Settings;

        settings.DnsMode = DnsMode.Remote;
        settings.RemoteDomains = "*.corp.local, corp.local";
        settings.UseRemoteServer = true;
        settings.RemoteServerAddress = "10.0.0.10";
        settings.RemoteServerVia = "pivot";
        settings.CaptureMode = CaptureMode.Injection;
        settings.SniffTimeoutMs = "soon";
        Assert.Contains("settings.dns.sniffTimeoutMs: Enter a whole number.", gui.Workspace.Problems);
        settings.SniffTimeoutMs = "300";

        Assert.True(await gui.Workspace.ApplyAsync(persist: false));

        Assert.StartsWith("Applied until the service restarts", gui.Workspace.StatusMessage, StringComparison.Ordinal);
        var dns = gui.Service.Engine.Configuration.Current.Config.Settings.Dns;
        Assert.Equal((DnsMode.Remote, 300), (dns.Mode, dns.SniffTimeoutMs));
        Assert.Equal(["*.corp.local", "corp.local"], dns.RemoteDomains);
        Assert.Equal(("10.0.0.10", 53, "pivot"), (dns.RemoteServer!.Address, dns.RemoteServer.Port, dns.RemoteServer.Via));
    }

    [AvaloniaFact]
    public async Task Json_round_trips_through_the_working_copy_and_files()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var json = gui.ViewModel.Json;
        await json.ActivateAsync();
        Assert.Contains("\"pivot-then-burp\"", json.Text, StringComparison.Ordinal);
        Assert.False(json.IsModified);

        json.Text = """{ "version": 1, "proxies": [ { "id": "p", "type": "socks5", "host": "127.0.0.1", "port": 9050 } ], "rules": [ { "name": "all", "action": { "type": "proxy", "target": "p" } } ] }""";
        Assert.True(json.IsModified);
        json.ValidateCommand.Execute(null);
        Assert.Equal("Valid: 1 prox(ies), 0 chain(s), 1 rule(s).", Assert.Single(json.Messages));
        json.UseTextCommand.Execute(null);
        Assert.True(gui.Workspace.IsDirty);
        Assert.Equal("all", Assert.Single(gui.Workspace.Rules).Name);
        Assert.False(json.IsModified);

        json.Text = """{ "version": 1, "rules": [ { "name": "x", "action": { "type": "proxy", "target": "missing" } } ] }""";
        json.UseTextCommand.Execute(null);
        Assert.Equal("Not taken over: the JSON is invalid.", json.Messages[0]);
        Assert.Equal("all", Assert.Single(gui.Workspace.Rules).Name);

        var directory = Directory.CreateTempSubdirectory("pn-gui-").FullName;
        try
        {
            json.ResetCommand.Execute(null);
            gui.Dialogs.SavePath = Path.Combine(directory, "saved.json");
            await json.SaveCommand.ExecuteAsync(null);
            Assert.True((await ConfigLoader.LoadFileAsync(gui.Dialogs.SavePath, TestTimeout.Token())).Success);

            gui.Dialogs.OpenPath = Path.Combine(AppContext.BaseDirectory, "samples", "config.json");
            await json.OpenCommand.ExecuteAsync(null);
            Assert.True(json.IsModified);
            Assert.Contains("test3.exe", json.Text, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [AvaloniaFact]
    public async Task Changes_made_elsewhere_are_picked_up_unless_the_user_is_editing()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        await gui.Service.Client.ApplyConfigAsync(new ApplyConfigRequest { Json = """{ "version": 1, "rules": [ { "name": "from the cli", "action": { "type": "block" } } ] }""" }, cancellationToken: TestTimeout.Token());

        await gui.ViewModel.TickAsync();
        Assert.Equal("from the cli", Assert.Single(gui.Workspace.Rules).Name);

        gui.Workspace.Rules[0].Name = "being edited";
        await gui.Service.Client.ApplyConfigAsync(new ApplyConfigRequest { Json = """{ "version": 1 }""" }, cancellationToken: TestTimeout.Token());
        await gui.ViewModel.TickAsync();
        Assert.Equal("being edited", Assert.Single(gui.Workspace.Rules).Name);
    }

    [AvaloniaFact]
    public async Task Connections_appear_live_and_stay_listed_when_closed()
    {
        var platform = new TestPlatformModule();
        platform.Processes[4242] = new ProcessInfo(4242, "app.exe", @"C:\app.exe");
        await using var gui = await GuiHarness.StartAsync(platform: platform);
        await using var echo = new EchoServer();
        var connections = gui.ViewModel.Connections;
        connections.Start();
        await Wait.UntilAsync(() => connections.IsWatching && gui.Service.Engine.ConnectionWatchers > 0, "the connection watch");

        var ct = TestTimeout.Token();
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        gui.Service.Engine.Destinations.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(echo.Endpoint, 4242));
        await client.ConnectAsync(gui.Service.Engine.Relay!.LocalEndpoints[0], ct);
        await client.SendAsync("ping"u8.ToArray(), ct);
        Assert.Equal("ping", await client.ReceiveStringAsync(4, ct));

        await Wait.UntilAsync(() => connections.Rows.Count == 1, "the opened connection");
        var row = connections.Rows[0];
        Assert.Equal(("app.exe", 4242, "tcp", "direct", "open"), (row.Process, row.ProcessId, row.Protocol, row.Via, row.State));
        Assert.Equal(echo.Endpoint.ToString(), row.Destination);

        client.Shutdown(SocketShutdown.Send);
        Assert.True(await client.IsClosedByPeerAsync(ct));
        await Wait.UntilAsync(() => !row.IsOpen, "the closed connection");
        Assert.Equal(("4 B", "4 B"), (row.Sent, row.Received));
        Assert.Equal("0 open, 1 closed (newest first)", connections.Summary);

        connections.Filter = "nothing like it";
        Assert.Empty(connections.View.Cast<object>());
        connections.Filter = "APP.EXE";
        Assert.Single(connections.View.Cast<object>());
        connections.ShowClosed = false;
        Assert.Empty(connections.View.Cast<object>());

        connections.ClearClosedCommand.Execute(null);
        Assert.Empty(connections.Rows);
    }

    [AvaloniaFact]
    public async Task Diagnostics_list_the_service_and_platform_checks()
    {
        await using var gui = await GuiHarness.StartAsync();
        var diagnostics = gui.ViewModel.Diagnostics;

        await diagnostics.RunCommand.ExecuteAsync(null);

        Assert.Equal("Service", diagnostics.Results[0].Name);
        Assert.Contains(diagnostics.Results, r => r is { Name: "Test platform", IsOk: true });
        Assert.False(diagnostics.IsRunning);
    }

    [AvaloniaFact]
    public async Task Launching_explains_when_the_service_does_not_accept_hooked_programs()
    {
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig);
        var launch = gui.ViewModel.Launch;
        await launch.ActivateAsync();

        Assert.Contains("without capture", launch.ModeAdvice, StringComparison.Ordinal);
        Assert.Contains("not accepting hooked processes", launch.NotReady, StringComparison.Ordinal);
        Assert.False(launch.LaunchCommand.CanExecute(null));

        launch.Program = "curl";
        launch.Arguments = "-v https://example.com";
        launch.LaunchCommand.Execute(null);

        Assert.True(launch.MessageIsError);
        Assert.Contains("not accepting hooked processes", launch.Message, StringComparison.Ordinal);
        Assert.Empty(launch.Launched);
    }
}
