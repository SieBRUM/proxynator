using System.Net;
using System.Net.Sockets;
using Proxynator.Core.Tests.Support;

namespace Proxynator.IntegrationTests;

/// <summary>
/// Real traffic from curl.exe through the WinDivert capture backend. Each test runs its own in-process service; the
/// integration tests never run in parallel (see AssemblyInfo.cs).
/// </summary>
[Trait("Category", "Integration")]
public sealed class WinDivertCaptureTests : IAsyncLifetime
{
    private const string Target = "example.com";

    private readonly string directory = Directory.CreateTempSubdirectory("pn-it-").FullName;
    private FakeProxyServer proxy = null!;
    private IPAddress targetAddress = null!;

    public async ValueTask InitializeAsync()
    {
        // Resolved before any test turns on fake-IP DNS, which would answer this process's lookups too.
        targetAddress = (await System.Net.Dns.GetHostAddressesAsync(Target)).First(a => a.AddressFamily == AddressFamily.InterNetwork);

        // A real SOCKS5 proxy (TCP and UDP) that resolves hostnames itself, like a remote proxy would.
        proxy = new FakeProxyServer(FakeProxyKind.Socks5)
        {
            Resolve = request => new IPEndPoint(
                request.Address ?? (request.Host == Target
                    ? targetAddress
                    : System.Net.Dns.GetHostAddresses(request.Host!).First(a => a.AddressFamily == AddressFamily.InterNetwork)),
                request.Port),
        };
    }

    public async ValueTask DisposeAsync()
    {
        await proxy.DisposeAsync();
        Directory.Delete(directory, recursive: true);
    }

    [Fact]
    public async Task Curl_http_is_routed_through_the_proxy_with_its_hostname()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("curl.exe", """{ "type": "proxy", "target": "socks" }"""));

        var (exitCode, status, error) = await Curl.RunAsync($"http://{Target}/");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.Equal("200", status);
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Target, 80), (request.Host, request.Port));
    }

    [Fact]
    public async Task Curl_https_is_routed_through_the_proxy_with_its_sni_hostname()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("curl.exe", """{ "type": "proxy", "target": "socks" }"""));

        var (exitCode, status, error) = await Curl.RunAsync($"https://{Target}/");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.Equal("200", status);
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Target, 443), (request.Host, request.Port));
    }

    [Fact]
    public async Task Unmatched_processes_go_direct()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("some-other-app.exe", """{ "type": "proxy", "target": "socks" }"""));

        var (exitCode, status, error) = await Curl.RunAsync($"http://{Target}/");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.Equal("200", status);
        Assert.Empty(proxy.Requests);
    }

    [Fact]
    public async Task Block_rules_refuse_the_connection()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("curl.exe", """{ "type": "block" }"""));

        var (exitCode, _, _) = await Curl.RunAsync($"http://{Target}/");

        Assert.NotEqual(0, exitCode);
        Assert.Empty(proxy.Requests);
    }

    [Fact]
    public async Task Unreachable_proxy_fails_closed()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("curl.exe", """{ "type": "proxy", "target": "down" }"""));

        var (exitCode, _, _) = await Curl.RunAsync($"http://{Target}/");

        Assert.NotEqual(0, exitCode); // never silently sent direct
    }

    [Fact]
    public async Task Networking_is_restored_after_the_service_stops()
    {
        Requirements.ElevatedWindows();
        var service = await StartAsync(RuleFor("curl.exe", """{ "type": "block" }"""));
        await service.DisposeAsync();

        var (exitCode, status, error) = await Curl.RunAsync($"http://{Target}/");

        Assert.True(exitCode == 0, $"curl failed after stopping the service ({exitCode}): {error}");
        Assert.Equal("200", status);
    }

    [Fact]
    public async Task Udp_dns_from_nslookup_goes_through_socks5_udp_associate()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("nslookup.exe", """{ "type": "proxy", "target": "socks" }"""));

        var (_, output, error) = await Tool.RunAsync(Path.Combine(Environment.SystemDirectory, "nslookup.exe"), [Target, "8.8.8.8"]);

        Assert.Contains(proxy.Requests, r => r.Udp && Equals(r.Address, IPAddress.Parse("8.8.8.8")) && r.Port == 53);
        Assert.True(output.Contains(targetAddress.ToString(), StringComparison.Ordinal), $"nslookup did not resolve {Target}: {output} {error}");
    }

    [Fact]
    public async Task Remote_dns_gives_curl_a_fake_address_and_the_proxy_the_hostname()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("curl.exe", """{ "type": "proxy", "target": "socks" }""", dnsMode: "remote"));

        var (exitCode, output, error) = await Curl.RunAsync($"http://{Target}/", "%{http_code} %{remote_ip}");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        var parts = output.Split(' ');
        Assert.Equal("200", parts[0]);
        Assert.StartsWith("198.18.", parts[1], StringComparison.Ordinal);
        var request = Assert.Single(proxy.Requests);
        Assert.Equal((Target, 80), (request.Host, request.Port));
    }

    [Fact]
    public async Task Remote_dns_still_works_for_processes_that_go_direct()
    {
        Requirements.ElevatedWindows();
        await using var service = await StartAsync(RuleFor("some-other-app.exe", """{ "type": "proxy", "target": "socks" }""", dnsMode: "remote"));

        var (exitCode, output, error) = await Curl.RunAsync($"http://{Target}/", "%{http_code} %{remote_ip}");

        Assert.True(exitCode == 0, $"curl failed ({exitCode}): {error}");
        Assert.StartsWith("200 198.18.", output, StringComparison.Ordinal); // fake address, real connection via the relay
        Assert.Empty(proxy.Requests);
    }

    /// <summary>
    /// The pipx situation: a console-script launcher (pip.exe, like nxc.exe or roadrecon.exe) starts the venv's
    /// python.exe, which starts the base interpreter that actually opens the connections. Matching the launcher with
    /// includeChildren must catch that traffic.
    /// </summary>
    [Fact]
    public async Task Python_console_scripts_in_a_venv_are_matched_through_their_launcher()
    {
        Requirements.ElevatedWindows();
        var venv = Path.Combine(directory, "venv");
        var (venvExit, _, venvError) = await Tool.RunAsync("python", ["-m", "venv", venv], timeoutSeconds: 120);
        Assert.True(venvExit == 0, $"python -m venv failed: {venvError}");
        var pip = Path.Combine(venv, "Scripts", "pip.exe");
        await using var service = await StartAsync(RuleFor(pip, """{ "type": "proxy", "target": "socks" }""", includeChildren: true));

        var (exitCode, output, error) = await Tool.RunAsync(
            pip, ["download", "--no-deps", "--no-cache-dir", "--disable-pip-version-check", "-d", Path.Combine(directory, "dl"), "six"], timeoutSeconds: 120);

        Assert.True(exitCode == 0, $"pip download failed ({exitCode}): {output} {error}");
        Assert.Contains(proxy.Requests, r => r.Host is "pypi.org" or "files.pythonhosted.org" && r.Port == 443);
    }

    private string RuleFor(string process, string action, string dnsMode = "sniff", bool includeChildren = false) => $$"""
        {
          "version": 1,
          "settings": {
            "capture": { "mode": "windivert" },
            "dns": { "mode": "{{dnsMode}}", "remoteDomains": ["{{Target}}"] }
          },
          "proxies": [
            { "id": "socks", "type": "socks5", "host": "127.0.0.1", "port": {{proxy.Endpoint.Port}} },
            { "id": "down", "type": "socks5", "host": "127.0.0.1", "port": 1 }
          ],
          "rules": [ { "name": "test rule", "match": { "processes": [{{System.Text.Json.JsonSerializer.Serialize(process)}}], "includeChildren": {{(includeChildren ? "true" : "false")}} }, "action": {{action}} } ]
        }
        """;

    private Task<IntegrationService> StartAsync(string configJson) => IntegrationService.StartAsync(directory, configJson);
}
