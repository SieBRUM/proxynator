using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Proxynator.Core.Tests.Support;
using Proxynator.Service;

namespace Proxynator.IntegrationTests;

/// <summary>
/// Real traffic from curl.exe through the WinDivert capture backend. Each test runs its own in-process service, so
/// the tests in this class run one after another.
/// </summary>
[Trait("Category", "Integration")]
public sealed class WinDivertCaptureTests : IAsyncLifetime
{
    private const string Target = "example.com";

    private readonly string directory = Directory.CreateTempSubdirectory("pn-it-").FullName;
    private FakeProxyServer proxy = null!;

    public ValueTask InitializeAsync()
    {
        // A real SOCKS5 proxy that resolves hostnames itself, like a remote proxy would.
        proxy = new FakeProxyServer(FakeProxyKind.Socks5)
        {
            Resolve = request => new IPEndPoint(
                request.Address ?? System.Net.Dns.GetHostAddresses(request.Host!).First(a => a.AddressFamily == AddressFamily.InterNetwork),
                request.Port),
        };
        return ValueTask.CompletedTask;
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

    private string RuleFor(string process, string action) => $$"""
        {
          "version": 1,
          "settings": { "capture": { "mode": "windivert" } },
          "proxies": [
            { "id": "socks", "type": "socks5", "host": "127.0.0.1", "port": {{proxy.Endpoint.Port}} },
            { "id": "down", "type": "socks5", "host": "127.0.0.1", "port": 1 }
          ],
          "rules": [ { "name": "test rule", "match": { "processes": ["{{process}}"] }, "action": {{action}} } ]
        }
        """;

    private async Task<RunningService> StartAsync(string configJson)
    {
        var configPath = Path.Combine(directory, "config.json");
        await File.WriteAllTextAsync(configPath, configJson);
        var options = new ServiceOptions
        {
            ConfigPath = configPath,
            Endpoint = $"proxynator-it-{Guid.NewGuid():N}",
            Verbose = true,
        };

        var app = ServiceHost.Build(options);
        await app.StartAsync(TestTimeout.Token(30));
        var engine = app.Services.GetRequiredService<ProxynatorEngine>();
        Assert.True(engine.CaptureState == CaptureState.Running, $"Capture did not start: {engine.CaptureDetail}");
        return new RunningService(app);
    }

    private sealed class RunningService(WebApplication app) : IAsyncDisposable
    {
        private bool disposed;

        public async ValueTask DisposeAsync()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            await app.StopAsync(TestTimeout.Token(30));
            await app.DisposeAsync();
        }
    }
}
