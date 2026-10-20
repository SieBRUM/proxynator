using Proxynator.Core.Configuration;

namespace Proxynator.Core.Tests.Configuration;

public class ConfigLoaderTests
{
    [Fact]
    public async Task Sample_config_loads()
    {
        var result = await ConfigLoader.LoadFileAsync(Path.Combine(AppContext.BaseDirectory, "samples", "config.json"));

        Assert.True(result.Success, string.Join(Environment.NewLine, result.Errors));
        Assert.Equal(3, result.Config.Proxies.Count);
        Assert.Equal(CaptureMode.WinDivert, result.Config.Settings.Capture.Mode);
        Assert.Equal(ProxyType.Http, result.Config.Proxies[1].Type);
        Assert.Equal(["pivot", "burp"], result.Config.Chains[0].Hops);
        Assert.Equal(4, result.Config.Rules.Count);
    }

    public static TheoryData<string> Samples() =>
        [.. Directory.GetFiles(Path.Combine(AppContext.BaseDirectory, "samples"), "*.json").Select(path => Path.GetFileName(path))];

    [Theory]
    [MemberData(nameof(Samples))]
    public async Task Every_sample_config_is_valid(string file)
    {
        var result = await ConfigLoader.LoadFileAsync(Path.Combine(AppContext.BaseDirectory, "samples", file));

        Assert.True(result.Success, string.Join(Environment.NewLine, result.Errors));
    }

    [Fact]
    public void Minimal_config_gets_defaults()
    {
        var result = ConfigLoader.Parse("""{ "version": 1 }""");

        Assert.True(result.Success);
        Assert.Equal(DnsMode.Sniff, result.Config.Settings.Dns.Mode);
        Assert.Equal(CaptureMode.Auto, result.Config.Settings.Capture.Mode);
        Assert.True(result.Config.Settings.Udp.BlockQuic);
        Assert.Empty(result.Config.Rules);
    }

    [Fact]
    public void Comments_and_trailing_commas_are_allowed()
    {
        var result = ConfigLoader.Parse("""
            {
              // comment
              "version": 1,
              "proxies": [ { "id": "a", "type": "socks5", "host": "127.0.0.1", "port": 1080, }, ],
            }
            """);

        Assert.True(result.Success, string.Join(Environment.NewLine, result.Errors));
    }

    [Theory]
    [InlineData("""{ }""", "$.version")]
    [InlineData("""{ "version": "1" }""", "$.version")]
    [InlineData("""{ "version": 99 }""", "$.version")]
    [InlineData("""{ "version": 0 }""", "$.version")]
    [InlineData("""[]""", "$")]
    [InlineData("""{ "version": 1, """, "$")]
    public void Invalid_documents_are_rejected(string json, string expectedPath)
    {
        var result = ConfigLoader.Parse(json);

        Assert.False(result.Success);
        Assert.Equal(expectedPath, Assert.Single(result.Errors).Path);
    }

    [Theory]
    [InlineData("""{ "version": 1, "proxeis": [] }""")]
    [InlineData("""{ "version": 1, "proxies": [ { "id": "a", "type": "socks6", "host": "h", "port": 1 } ] }""")]
    [InlineData("""{ "version": 1, "proxies": [ { "id": "a", "host": "h", "port": 1 } ] }""")]
    [InlineData("""{ "version": 1, "rules": null }""")]
    public void Schema_violations_are_rejected(string json)
    {
        var result = ConfigLoader.Parse(json);

        Assert.False(result.Success);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void Semantic_errors_are_reported_with_paths()
    {
        var result = ConfigLoader.Parse("""
            { "version": 1, "rules": [ { "name": "r", "action": { "type": "proxy", "target": "nope" } } ] }
            """);

        Assert.False(result.Success);
        Assert.Equal("$.rules[0].action.target", Assert.Single(result.Errors).Path);
    }

    [Fact]
    public async Task Serialize_round_trips()
    {
        var original = await ConfigLoader.LoadFileAsync(Path.Combine(AppContext.BaseDirectory, "samples", "config.json"));
        Assert.True(original.Success);

        var json = ConfigLoader.Serialize(original.Config);
        var reloaded = ConfigLoader.Parse(json);

        Assert.True(reloaded.Success, string.Join(Environment.NewLine, reloaded.Errors));
        Assert.Equal(json, ConfigLoader.Serialize(reloaded.Config));
        Assert.Contains("\"type\": \"socks5\"", json, StringComparison.Ordinal);
        Assert.Contains("\"mode\": \"windivert\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_file_is_reported()
    {
        var result = await ConfigLoader.LoadFileAsync(Path.Combine(AppContext.BaseDirectory, "does-not-exist.json"));

        Assert.False(result.Success);
    }

    [Fact]
    public void Auth_password_is_not_in_ToString()
    {
        var auth = new ProxyAuth { Username = "user", Password = "secret" };

        Assert.DoesNotContain("secret", auth.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", Support.Configs.Proxy("p", ProxyType.Socks5, 1, auth: auth).ToString(), StringComparison.Ordinal);
    }
}
