using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Proxynator.Client;
using Proxynator.Core.Tests.Support;
using Proxynator.Platform.Windows.Injection;

namespace Proxynator.IntegrationTests;

/// <summary>
/// The injection capture mode with real programs: processes started (or attached to) the way <c>proxynator run</c>
/// and <c>proxynator attach</c> do it, 64-bit and 32-bit, their child processes, Python (connect) and .NET (ConnectEx).
/// The hook log of each test is written to the test output.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")] // every test skips (or fails, in CI) elsewhere before using Windows APIs
public sealed class InjectionCaptureTests : IAsyncLifetime
{
    private const string Target = "example.com";
    private const string InternalName = "intranet.proxynator.test";

    private static readonly string System32 = Environment.SystemDirectory;
    private static readonly string SysWow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    private readonly string directory = Directory.CreateTempSubdirectory("pn-inj-").FullName;
    private readonly string? previousHookLog = Environment.GetEnvironmentVariable("PROXYNATOR_HOOK_LOG");
    private readonly FakeLdapServer ldap = new();
    private FakeProxyServer proxy = null!;
    private IPAddress targetAddress = null!;

    private string HookLog => Path.Combine(directory, "hook.log");

    public async ValueTask InitializeAsync()
    {
        targetAddress = (await System.Net.Dns.GetHostAddressesAsync(Target)).First(a => a.AddressFamily == AddressFamily.InterNetwork);
        proxy = new FakeProxyServer(FakeProxyKind.Socks5)
        {
            // Names only the proxy can resolve (remote DNS) go to the target as well.
            Resolve = request => request.Port == 389 ? ldap.Endpoint : new IPEndPoint(
                request.Address ?? (request.Host is Target or InternalName
                    ? targetAddress
                    : System.Net.Dns.GetHostAddresses(request.Host!).First(a => a.AddressFamily == AddressFamily.InterNetwork)),
                request.Port),
        };

        // Inherited by the started programs and their children.
        Environment.SetEnvironmentVariable("PROXYNATOR_HOOK_LOG", HookLog);
    }

    public async ValueTask DisposeAsync()
    {
        Environment.SetEnvironmentVariable("PROXYNATOR_HOOK_LOG", previousHookLog);
        await proxy.DisposeAsync();
        await ldap.DisposeAsync();
        if (File.Exists(HookLog))
        {
            Console.WriteLine("Hook log:");
            Console.WriteLine(await File.ReadAllTextAsync(HookLog));
        }

        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            // A program may still hold the log file.
        }
    }

    [Fact]
    public async Task A_64_bit_program_is_routed_through_the_proxy()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());

        var exitCode = await RunHookedAsync(service, Path.Combine(System32, "curl.exe"), CurlArguments($"http://{Target}/"));

        Assert.Equal(0, exitCode);
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Target, 80), (request.Host, request.Port));
    }

    [Fact]
    public async Task A_batch_file_started_like_the_gui_and_cli_do_is_routed_through_the_proxy()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());
        await File.WriteAllTextAsync(Path.Combine(directory, "fetch.cmd"), $"@\"{Path.Combine(System32, "curl.exe")}\" {string.Join(' ', CurlArguments($"http://{Target}/"))}\r\n");

        // Found in the working directory through PATHEXT, run by a hooked cmd.exe, which hooks curl.
        using var program = new ProgramLauncher(service.Endpoint).Start("fetch", [], directory);
        var exitCode = await program.WaitForExitAsync(TestTimeout.Token(60));

        Assert.Equal(0, exitCode);
        Assert.Equal("fetch.cmd", program.Name);
        Assert.Contains(proxy.Requests, r => (r.Host, r.Port) == (Target, 80));
    }

    [Fact]
    public async Task A_32_bit_program_is_routed_through_the_proxy()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());

        var exitCode = await RunHookedAsync(service, Path.Combine(SysWow64, "curl.exe"), CurlArguments($"https://{Target}/"));

        Assert.Equal(0, exitCode);
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Target, 443), (request.Host, request.Port));
    }

    [Fact]
    public async Task Child_processes_are_hooked_across_bitness()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());

        // 64-bit cmd.exe starts a 32-bit and a 64-bit curl.exe.
        var cmd = Path.Combine(System32, "cmd.exe");
        var commands = $"{Join(Path.Combine(SysWow64, "curl.exe"), CurlArguments($"http://{Target}/"))} && {Join(Path.Combine(System32, "curl.exe"), CurlArguments($"https://{Target}/"))}";
        var exitCode = await RunHookedAsync(service, cmd, $"\"{cmd}\" /d /s /c \"{commands}\"");

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host == Target && r.Port == 80);
        Assert.Contains(proxy.Requests, r => r.Host == Target && r.Port == 443);
    }

    [Fact]
    public async Task Programs_without_a_matching_rule_go_direct()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(Config("""{ "processes": ["some-other-app.exe"] }"""));

        var exitCode = await RunHookedAsync(service, Path.Combine(System32, "curl.exe"), CurlArguments($"http://{Target}/"));

        Assert.Equal(0, exitCode);
        Assert.Empty(proxy.Requests);
    }

    [Fact]
    public async Task Hooked_programs_fail_closed_when_the_service_is_gone()
    {
        Requirements.ElevatedWindowsWithHooks();

        using var process = HookInjector.Start(
            Path.Combine(System32, "curl.exe"), Join(Path.Combine(System32, "curl.exe"), CurlArguments($"http://{Target}/")), null,
            $"proxynator-it-missing-{Guid.NewGuid():N}");
        var exitCode = await process.WaitForExitAsync(TestTimeout.Token(60));

        Assert.NotEqual(0, exitCode); // refused, never sent direct
        Assert.Empty(proxy.Requests);
    }

    [Fact]
    public async Task Remote_dns_is_per_process_and_resolves_names_only_the_proxy_knows()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig(dnsMode: "remote", remoteDomains: "\"*.proxynator.test\", \"example.com\""));

        // The name does not exist in public DNS: only the proxy (the fake one maps it to example.com) can reach it.
        var exitCode = await RunHookedAsync(service, Path.Combine(System32, "curl.exe"), ["-4", "-sS", "--max-time", "20", "-o", "NUL", $"http://{InternalName}/"]);

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host == InternalName && r.Port == 80);

        // Unlike the windivert mode, the rest of the machine (here: the test process) still gets real answers.
        var addresses = await System.Net.Dns.GetHostAddressesAsync(Target);
        Assert.DoesNotContain(addresses, a => a.ToString().StartsWith("198.18.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Ldap_from_a_hooked_program_goes_through_the_proxy()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());

        // curl.exe's ldap:// uses WinLDAP (wldap32), so this is Windows' own LDAP client inside the hooked process.
        var exitCode = await RunHookedAsync(service, Path.Combine(System32, "curl.exe"), ["-sS", "--max-time", "20", .. FakeLdapServer.CurlCredentials, "-o", Path.Combine(directory, "ldap.txt"), "ldap://203.0.113.10:389/dc=corp,dc=local?cn?sub?(objectClass=*)"]);

        Assert.Equal(0, exitCode);
        Assert.Contains(FakeLdapServer.EntryDn, await File.ReadAllTextAsync(Path.Combine(directory, "ldap.txt")), StringComparison.Ordinal);
        Assert.Contains(proxy.Requests, r => Equals(r.Address, IPAddress.Parse("203.0.113.10")) && r.Port == 389);
    }

    [Fact]
    public async Task Dotnet_programs_using_ConnectEx_are_routed_through_the_proxy()
    {
        Requirements.ElevatedWindowsWithHooks();
        var pwsh = FindOnPath("pwsh.exe");
        Assert.SkipWhen(pwsh is null, "PowerShell 7 (pwsh.exe) is not installed.");
        await using var service = await StartAsync(ProxyAllConfig());

        var exitCode = await RunHookedAsync(service, pwsh!, ["-NoProfile", "-NonInteractive", "-Command", $"Invoke-WebRequest -UseBasicParsing http://{Target}/ | Out-Null"]);

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host == Target && r.Port == 80);
    }

    /// <summary>pipx-style: pip.exe (console-script launcher) -> venv python.exe -> base python.exe, all hooked.</summary>
    [Fact]
    public async Task Python_console_scripts_and_their_interpreters_are_hooked()
    {
        Requirements.ElevatedWindowsWithHooks();
        var venv = Path.Combine(directory, "venv");
        var (venvExit, _, venvError) = await Tool.RunAsync("python", ["-m", "venv", venv], timeoutSeconds: 120);
        Assert.True(venvExit == 0, $"python -m venv failed: {venvError}");
        await using var service = await StartAsync(ProxyAllConfig());

        var pip = Path.Combine(venv, "Scripts", "pip.exe");
        var exitCode = await RunHookedAsync(
            service, pip, ["download", "--no-deps", "--no-cache-dir", "--disable-pip-version-check", "-d", Path.Combine(directory, "dl"), "six"], timeoutSeconds: 120);

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host is "pypi.org" or "files.pythonhosted.org" && r.Port == 443);
    }

    [Fact]
    public async Task Attaching_to_a_running_64_bit_program_routes_its_new_connections()
    {
        Requirements.ElevatedWindowsWithHooks();
        await using var service = await StartAsync(ProxyAllConfig());

        // Waits for a marker file, so the request is made only after the hook is in.
        var marker = Path.Combine(directory, "attached");
        var script = $"import os,time,urllib.request\nwhile not os.path.exists(r'{marker}'): time.sleep(0.2)\nurllib.request.urlopen('http://{Target}/', timeout=20).read()";
        var exitCode = await AttachAndRunAsync(service, "python", ["-c", script], marker);

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host == Target && r.Port == 80);
    }

    [Fact]
    public async Task Attaching_to_a_running_32_bit_program_routes_its_new_connections()
    {
        Requirements.ElevatedWindowsWithHooks();
        var powershell32 = Path.Combine(SysWow64, "WindowsPowerShell", "v1.0", "powershell.exe");
        Assert.SkipUnless(File.Exists(powershell32), "32-bit Windows PowerShell is not installed.");
        await using var service = await StartAsync(ProxyAllConfig());

        var marker = Path.Combine(directory, "attached");
        var script = $"while (-not (Test-Path '{marker}')) {{ Start-Sleep -Milliseconds 200 }}; Invoke-WebRequest -UseBasicParsing http://{Target}/ | Out-Null";
        var exitCode = await AttachAndRunAsync(service, powershell32, ["-NoProfile", "-NonInteractive", "-Command", script], marker);

        Assert.Equal(0, exitCode);
        Assert.Contains(proxy.Requests, r => r.Host == Target && r.Port == 80);
    }

    private static string[] CurlArguments(string url) => ["-4", "-sS", "-f", "--max-time", "20", "-o", "NUL", url];

    private static string Join(string program, IEnumerable<string> arguments) => WindowsCommandLine.Join([program, .. arguments]);

    private static string? FindOnPath(string file) =>
        (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(d => Path.Combine(d.Trim('"'), file))
            .FirstOrDefault(File.Exists);

    private static Task<int> RunHookedAsync(IntegrationService service, string program, string[] arguments, int timeoutSeconds = 60) =>
        RunHookedAsync(service, program, Join(program, arguments), timeoutSeconds);

    /// <summary>Starts the program the way <c>proxynator run</c> does and returns its exit code.</summary>
    private static async Task<int> RunHookedAsync(IntegrationService service, string program, string commandLine, int timeoutSeconds = 60)
    {
        using var process = HookInjector.Start(program, commandLine, null, service.HookPipe);
        return await process.WaitForExitAsync(TestTimeout.Token(timeoutSeconds));
    }

    private static async Task<int> AttachAndRunAsync(IntegrationService service, string program, string[] arguments, string marker)
    {
        var start = new ProcessStartInfo(program) { UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        try
        {
            // Let the runtime start up before attaching (attach works at any time; this mirrors real use).
            await Task.Delay(TimeSpan.FromSeconds(2));
            HookInjector.Attach(process.Id, service.HookPipe);
            await File.WriteAllTextAsync(marker, "attached");
            await process.WaitForExitAsync(TestTimeout.Token(60));
            return process.ExitCode;
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
    }

    private string ProxyAllConfig(string dnsMode = "sniff", string remoteDomains = "\"example.com\"") => Config("{}", dnsMode, remoteDomains);

    private string Config(string match, string dnsMode = "sniff", string remoteDomains = "\"example.com\"") => $$"""
        {
          "version": 1,
          "settings": {
            "capture": { "mode": "injection" },
            "dns": { "mode": "{{dnsMode}}", "remoteDomains": [{{remoteDomains}}] },
            "udp": { "blockQuic": true }
          },
          "proxies": [ { "id": "socks", "type": "socks5", "host": "127.0.0.1", "port": {{proxy.Endpoint.Port}} } ],
          "rules": [ { "name": "hooked programs", "match": {{match}}, "action": { "type": "proxy", "target": "socks", "udp": "direct" } } ]
        }
        """;

    private Task<IntegrationService> StartAsync(string configJson) => IntegrationService.StartAsync(directory, configJson);
}
