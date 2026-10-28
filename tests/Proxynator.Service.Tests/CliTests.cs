using Proxynator.Cli;
using Proxynator.Client;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Service.Tests;

/// <summary>The CLI commands against a real in-process service.</summary>
public class CliTests
{
    private static readonly string SamplePath = Path.Combine(AppContext.BaseDirectory, "samples", "config.json");

    private static (Commands Commands, StringWriter Output, StringWriter Error) Create(string endpoint)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        return (new Commands(endpoint, output, error), output, error);
    }

    [Fact]
    public async Task Load_then_list_rules_and_status()
    {
        await using var service = await TestService.StartAsync();
        var (commands, output, error) = Create(service.Endpoint);

        Assert.Equal(ExitCodes.Success, await commands.LoadConfigAsync(SamplePath, save: false, TestTimeout.Token()));
        Assert.Equal(ExitCodes.Success, await commands.ListRulesAsync(TestTimeout.Token()));
        Assert.Equal(ExitCodes.Success, await commands.StatusAsync(TestTimeout.Token()));

        var text = output.ToString();
        Assert.Contains("Configuration applied", text, StringComparison.Ordinal);
        Assert.Contains("proxy via pivot -> burp", text, StringComparison.Ordinal);
        Assert.Contains("(4 active rule(s))", text, StringComparison.Ordinal);
        Assert.Equal(string.Empty, error.ToString());
        Assert.False(File.Exists(service.ConfigPath)); // --no-save
    }

    [Fact]
    public async Task Load_reports_errors_and_fails()
    {
        await using var service = await TestService.StartAsync();
        var (commands, _, error) = Create(service.Endpoint);
        var bad = Path.Combine(Path.GetTempPath(), $"bad-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(bad, """{ "version": 1, "proxies": [ { "id": "p", "type": "socks5", "host": "h", "port": 0 } ] }""");

        try
        {
            Assert.Equal(ExitCodes.Failure, await commands.LoadConfigAsync(bad, save: true, TestTimeout.Token()));
            Assert.Contains("$.proxies[0].port", error.ToString(), StringComparison.Ordinal);
            Assert.Contains("NOT applied", error.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(bad);
        }
    }

    [Fact]
    public async Task Status_shows_the_dns_cache_and_clear_cache_empties_it()
    {
        var platform = new TestPlatformModule();
        await using var service = await TestService.StartAsync(platform, initialConfigJson: """{ "version": 1, "settings": { "dns": { "cacheSeconds": -1 } } }""");
        service.Engine.DnsCache.Set("a", "answer", null);
        service.Engine.DnsCache.Set("b", "answer", null);
        var (commands, output, error) = Create(service.Endpoint);

        Assert.Equal(ExitCodes.Success, await commands.StatusAsync(TestTimeout.Token()));
        Assert.Contains("DNS cache:    2 answer(s), kept until cleared", output.ToString(), StringComparison.Ordinal);

        Assert.Equal(ExitCodes.Success, await commands.ClearDnsCacheAsync(includeSystem: false, TestTimeout.Token()));
        Assert.Contains("Cleared 2 cached DNS answer(s)", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, service.Engine.DnsCache.Count);
        Assert.Equal(0, platform.SystemDnsCacheFlushes); // only with --system

        Assert.Equal(ExitCodes.Success, await commands.ClearDnsCacheAsync(includeSystem: true, TestTimeout.Token()));
        Assert.Contains("Cleared 0 cached DNS answer(s)", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("test: system cache cleared", output.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, platform.SystemDnsCacheFlushes);
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Clear_cache_fails_when_the_system_cache_cannot_be_cleared()
    {
        await using var service = await TestService.StartAsync(new TestPlatformModule { SystemDnsCacheClears = false });
        var (commands, _, error) = Create(service.Endpoint);

        Assert.Equal(ExitCodes.Failure, await commands.ClearDnsCacheAsync(includeSystem: true, TestTimeout.Token()));
        Assert.Contains("test: no system cache", error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validate_works_without_the_service()
    {
        var (commands, output, _) = Create("unused");

        Assert.Equal(ExitCodes.Success, await commands.ValidateConfigAsync(SamplePath, TestTimeout.Token()));
        Assert.Contains("is valid: 3 prox(ies), 1 chain(s), 4 rule(s)", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Doctor_prints_checks()
    {
        await using var service = await TestService.StartAsync();
        var (commands, output, _) = Create(service.Endpoint);

        Assert.Equal(ExitCodes.Success, await commands.DoctorAsync(TestTimeout.Token()));
        Assert.Contains("[ OK ] Service", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("[WARN] Rules", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unreachable_service_exits_with_code_2()
    {
        var directory = Directory.CreateTempSubdirectory("pn-").FullName;
        var (commands, _, error) = Create(TestService.NewEndpoint(directory));

        Assert.Equal(ExitCodes.ServiceUnreachable, await commands.StatusAsync(TestTimeout.Token()));
        Assert.Contains("Cannot reach proxynatord", error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(1023, "1023 B")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(5L * 1024 * 1024 * 1024, "5 GB")]
    public void Bytes_are_formatted(long bytes, string expected) => Assert.Equal(expected, DisplayFormat.Bytes(bytes));
}
