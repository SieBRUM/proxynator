using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using Proxynator.Core.Tests.Support;
using Proxynator.Ipc;
using Proxynator.Platform.Linux.Preload;

namespace Proxynator.IntegrationTests;

/// <summary>
/// Real programs (curl, sh, python3) through the Linux capture modes: the eBPF programs in the kernel and the
/// preload library. The destination is a local HTTP server on a non-loopback address; names under
/// <c>proxynator.test</c> exist only for the fake SOCKS5 proxy, which maps them to it.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("linux")] // every test skips elsewhere before using Linux APIs
public sealed class LinuxCaptureTests : IAsyncLifetime
{
    private const string Name = "web.proxynator.test";

    private readonly string directory = Directory.CreateTempSubdirectory("pn-linux-").FullName;
    private readonly string? previousHookLog = Environment.GetEnvironmentVariable("PROXYNATOR_HOOK_LOG");
    private HttpTarget target = null!;
    private FakeLdapServer ldap = null!;
    private FakeProxyServer proxy = null!;

    private string HookLog => Path.Combine(directory, "hook.log");

    public ValueTask InitializeAsync()
    {
        target = new HttpTarget();
        ldap = new FakeLdapServer();
        proxy = new FakeProxyServer(FakeProxyKind.Socks5)
        {
            // LDAP goes to the fake directory server; everything else to the HTTP target.
            Resolve = request => request.Port == 389 ? ldap.Endpoint
                : request.Address is { } address ? new IPEndPoint(address, request.Port) : target.Endpoint,
        };
        Environment.SetEnvironmentVariable("PROXYNATOR_HOOK_LOG", HookLog);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        Environment.SetEnvironmentVariable("PROXYNATOR_HOOK_LOG", previousHookLog);
        await proxy.DisposeAsync();
        await ldap.DisposeAsync();
        await target.DisposeAsync();
        if (File.Exists(HookLog))
        {
            Console.WriteLine("Hook log:");
            Console.WriteLine(await File.ReadAllTextAsync(HookLog));
        }

        Directory.Delete(directory, recursive: true);
    }

    // ---- ebpf ------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Ebpf_routes_a_matching_program_through_the_proxy_with_the_sniffed_hostname()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""");

        var (exitCode, _, error) = await CurlAsync(target.Url(), "-H", $"Host: {Name}");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Name, target.Endpoint.Port), (request.Host, request.Port));
    }

    [Fact]
    public async Task Ebpf_leaves_other_programs_alone()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["some-other-program"] }""");

        var (exitCode, _, error) = await CurlAsync(target.Url());

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.Empty(proxy.Requests);
        Assert.Equal(1, target.Requests);
    }

    [Fact]
    public async Task Ebpf_block_rules_refuse_the_connection()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""", action: """{ "type": "block" }""");

        var (exitCode, _, _) = await CurlAsync(target.Url());

        Assert.NotEqual(0, exitCode);
        Assert.Equal(0, target.Requests);
    }

    [Fact]
    public async Task Ebpf_fails_closed_when_the_proxy_is_down()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""", action: """{ "type": "proxy", "target": "down" }""");

        var (exitCode, _, _) = await CurlAsync(target.Url());

        Assert.NotEqual(0, exitCode); // never silently sent direct
        Assert.Equal(0, target.Requests);
    }

    [Fact]
    public async Task Ebpf_networking_is_restored_after_the_service_stops()
    {
        Requirements.RootLinux();
        var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""", action: """{ "type": "block" }""");
        await service.DisposeAsync();

        var (exitCode, _, error) = await CurlAsync(target.Url());

        Assert.True(exitCode == 0, $"curl failed after stopping the service ({exitCode}): {error}");
    }

    /// <summary>A shebang script (like pipx's nxc) is named after the script; what it starts is its child.</summary>
    [Fact]
    public async Task Ebpf_matches_scripts_by_name_and_their_children()
    {
        Requirements.RootLinux();
        var script = WriteScript("pn-launcher", $"#!/bin/sh\ncurl -sS -f --max-time 20 -o /dev/null -H 'Host: {Name}' {target.Url()}\n");
        await using var service = await StartAsync("ebpf", """{ "processes": ["pn-launcher"], "includeChildren": true }""");

        var (exitCode, _, error) = await Tool.RunAsync(script, []);

        Assert.True(exitCode == 0, $"the script failed ({exitCode}): {error}");
        Assert.Contains(proxy.Requests, r => r.Host == Name);
    }

    [Fact]
    public async Task Ebpf_python_scripts_are_matched_by_script_name()
    {
        Requirements.RootLinux();
        var script = WriteScript("pn-tool", $"#!/usr/bin/env python3\nimport urllib.request\nurllib.request.urlopen(urllib.request.Request('{target.Url()}', headers={{'Host': '{Name}'}}), timeout=20).read()\n");
        await using var service = await StartAsync("ebpf", """{ "processes": ["pn-tool"] }""");

        var (exitCode, _, error) = await Tool.RunAsync(script, []);

        Assert.True(exitCode == 0, $"the script failed ({exitCode}): {error}");
        Assert.Contains(proxy.Requests, r => r.Host == Name);
    }

    [Fact]
    public async Task Ebpf_blocks_udp_of_proxied_programs_by_default()
    {
        Requirements.RootLinux();
        var script = WriteScript("pn-udp", $"#!/usr/bin/env python3\nimport socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ntry:\n    s.sendto(b'x', ('{target.Address}', 9))\n    print('sent')\nexcept OSError as e:\n    print('blocked', e.errno)\n");
        await using var service = await StartAsync("ebpf", """{ "processes": ["pn-udp"] }""");

        var (_, output, error) = await Tool.RunAsync(script, []);

        Assert.True(output.StartsWith("blocked", StringComparison.Ordinal), $"UDP was not blocked: {output} {error}");
    }

    /// <summary>The name exists only for the proxy: the program gets a fake address, the proxy the name.</summary>
    [Fact]
    public async Task Ebpf_remote_dns_resolves_names_only_the_proxy_knows()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""", dnsMode: "remote");

        var (exitCode, output, error) = await CurlAsync($"http://intranet.proxynator.test:{target.Endpoint.Port}/");

        // (curl's own view of the peer is the relay: the kernel rewrote the destination.)
        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {output} {error}");
        Assert.Contains(proxy.Requests, r => r.Host == "intranet.proxynator.test");
    }

    /// <summary>
    /// LDAP to a domain controller behind a pivot: the name only resolves on the far side (remote DNS), the proxy gets
    /// it, and a real LDAP client (curl with OpenLDAP) completes a bind and a search.
    /// </summary>
    [Fact]
    public async Task Ebpf_ldap_reaches_a_domain_controller_by_name_through_the_proxy()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("ebpf", """{ "processes": ["curl"] }""", dnsMode: "remote");

        var (exitCode, output, error) = await LdapSearchAsync("dc01.proxynator.test");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {output} {error}");
        Assert.Contains(FakeLdapServer.EntryDn, output, StringComparison.Ordinal);
        Assert.Contains(proxy.Requests, r => r.Host == "dc01.proxynator.test" && r.Port == 389);
        Assert.Contains("search", ldap.Operations);
    }

    // ---- preload ---------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Preload_ldap_goes_through_the_proxy()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("preload", "{}");

        var (exitCode, output, error) = await RunPreloadedAsync(service, "curl", ["-sS", "--max-time", "20", .. FakeLdapServer.CurlCredentials, LdapUrl("203.0.113.10")]);

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {output} {error}");
        Assert.Contains(FakeLdapServer.EntryDn, output, StringComparison.Ordinal);
        Assert.Contains(proxy.Requests, r => Equals(r.Address, IPAddress.Parse("203.0.113.10")) && r.Port == 389);
    }

    [Fact]
    public async Task Preload_routes_a_started_program_through_the_proxy()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("preload", "{}");

        var (exitCode, _, error) = await RunPreloadedAsync(service, "curl", [.. CurlArguments, "-H", $"Host: {Name}", target.Url()]);

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Name, target.Endpoint.Port), (request.Host, request.Port));
    }

    [Fact]
    public async Task Preload_hooks_child_processes()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("preload", "{}");

        var (exitCode, _, error) = await RunPreloadedAsync(service, "sh", ["-c", $"curl {string.Join(' ', CurlArguments)} -H 'Host: {Name}' {target.Url()}"]);

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.Contains(proxy.Requests, r => r.Host == Name);
    }

    [Fact]
    public async Task Preload_remote_dns_gives_the_proxy_the_name()
    {
        Requirements.RootLinux();
        await using var service = await StartAsync("preload", "{}", dnsMode: "remote");

        var (exitCode, output, error) = await RunPreloadedAsync(
            service, "python3", ["-c", $"import urllib.request; print(urllib.request.urlopen('http://intranet.proxynator.test:{target.Endpoint.Port}/', timeout=20).read().decode())"]);

        Assert.True(exitCode == 0, $"python failed ({exitCode}): {output} {error}");
        Assert.Equal("ok", output);
        Assert.Contains(proxy.Requests, r => r.Host == "intranet.proxynator.test");
    }

    [Fact]
    public async Task Preload_programs_fail_closed_when_the_service_is_gone()
    {
        Requirements.RootLinux();
        var start = PreloadLauncher.CreateStartInfo("curl", [.. CurlArguments, target.Url()], Path.Combine(directory, "missing.sock"), null);

        var (exitCode, _, _) = await RunAsync(start);

        Assert.NotEqual(0, exitCode);
        Assert.Equal(0, target.Requests);
    }

    private static readonly string[] CurlArguments = ["-4", "-sS", "-f", "--max-time", "20", "-o", "/dev/null"];

    /// <summary>A subtree search for everything under dc=corp,dc=local, returning the cn attribute.</summary>
    private static string LdapUrl(string host) => $"ldap://{host}:389/dc=corp,dc=local?cn?sub?(objectClass=*)";

    private static Task<(int ExitCode, string Output, string Error)> LdapSearchAsync(string host) =>
        Tool.RunAsync("curl", ["-sS", "--max-time", "20", .. FakeLdapServer.CurlCredentials, LdapUrl(host)]);

    private static Task<(int ExitCode, string Output, string Error)> CurlAsync(string url, params string[] extra) =>
        Tool.RunAsync("curl", [.. CurlArguments, .. extra, url]);

    private static Task<(int ExitCode, string Output, string Error)> RunPreloadedAsync(IntegrationService service, string program, string[] arguments) =>
        RunAsync(PreloadLauncher.CreateStartInfo(program, arguments, IpcEndpoint.HookEndpoint(service.Endpoint), null));

    private static async Task<(int ExitCode, string Output, string Error)> RunAsync(ProcessStartInfo start)
    {
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(TestTimeout.Token(60));
        return (process.ExitCode, (await output).Trim(), (await error).Trim());
    }

    private string WriteScript(string name, string content)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, content);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private Task<IntegrationService> StartAsync(string mode, string match, string dnsMode = "sniff", string? action = null) =>
        IntegrationService.StartAsync(directory, $$"""
            {
              "version": 1,
              "settings": {
                "capture": { "mode": "{{mode}}" },
                "dns": { "mode": "{{dnsMode}}", "remoteDomains": ["*.proxynator.test"] }
              },
              "proxies": [
                { "id": "socks", "type": "socks5", "host": "127.0.0.1", "port": {{proxy.Endpoint.Port}} },
                { "id": "down", "type": "socks5", "host": "127.0.0.1", "port": 1 }
              ],
              "rules": [ { "name": "test rule", "match": {{match}}, "action": {{action ?? """{ "type": "proxy", "target": "socks" }"""}} } ]
            }
            """);
}
