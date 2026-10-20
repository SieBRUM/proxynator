using Proxynator.Core.Configuration;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Configuration;

public class ConfigValidatorTests
{
    private static IReadOnlyList<string> ErrorPaths(ProxynatorConfig config) =>
        [.. ConfigValidator.Validate(config).Select(e => e.Path)];

    [Fact]
    public void Valid_config_has_no_errors()
    {
        var config = Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, 1080), Configs.Proxy("burp", ProxyType.Http, 8080)],
            Chains = [new ChainDefinition { Id = "both", Hops = ["socks", "burp"] }],
            Rules =
            [
                Configs.Rule("a", RuleActionType.Proxy, "both", new RuleMatch { Addresses = ["10.0.0.0/8", "::1"], Ports = ["443", "8000-8100"] }),
                Configs.Rule("b", RuleActionType.Block),
            ],
        };

        Assert.Empty(ConfigValidator.Validate(config));
    }

    [Fact]
    public void Duplicate_ids_are_rejected_case_insensitively()
    {
        var config = Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("burp", ProxyType.Http, 8080), Configs.Proxy("BURP", ProxyType.Http, 8081)],
            Chains = [new ChainDefinition { Id = "Burp", Hops = ["burp"] }],
        };

        Assert.Equal(["$.proxies[1].id", "$.chains[0].id"], ErrorPaths(config));
    }

    [Fact]
    public void Chains_must_reference_existing_proxies_only()
    {
        var config = Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("a", ProxyType.Socks5, 1)],
            Chains =
            [
                new ChainDefinition { Id = "c1", Hops = ["a", "missing"] },
                new ChainDefinition { Id = "c2", Hops = ["c1"] },
                new ChainDefinition { Id = "c3", Hops = [] },
            ],
        };

        Assert.Equal(["$.chains[0].hops[1]", "$.chains[1].hops[0]", "$.chains[2].hops"], ErrorPaths(config));
    }

    [Fact]
    public void Proxy_fields_are_checked()
    {
        var config = Configs.Minimal() with
        {
            Proxies =
            [
                Configs.Proxy("p1", ProxyType.Socks5, 0),
                Configs.Proxy("p2", ProxyType.Http, 80, host: "bad host"),
                Configs.Proxy("p3", ProxyType.Socks4, 1080, auth: new ProxyAuth { Username = "id", Password = "x" }),
                Configs.Proxy("p4", ProxyType.Socks5, 1080, auth: new ProxyAuth { Username = "user" }),
                Configs.Proxy("p5", ProxyType.Socks4a, 1080, auth: new ProxyAuth { Username = "id" }),
            ],
        };

        Assert.Equal(["$.proxies[0].port", "$.proxies[1].host", "$.proxies[2].auth.password", "$.proxies[3].auth.password"], ErrorPaths(config));
    }

    [Fact]
    public void Rule_actions_and_criteria_are_checked()
    {
        var config = Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("p", ProxyType.Socks5, 1080)],
            Rules =
            [
                Configs.Rule("no target", RuleActionType.Proxy),
                Configs.Rule("unknown target", RuleActionType.Proxy, "nope"),
                Configs.Rule("direct with target", RuleActionType.Direct, "p"),
                Configs.Rule("bad criteria", RuleActionType.Block, match: new RuleMatch { Addresses = ["10.0.0.0/33"], Ports = ["0", "90-80"], Processes = [""] }),
                Configs.Rule("NO TARGET", RuleActionType.Block),
            ],
        };

        Assert.Equal(
            [
                "$.rules[0].action.target",
                "$.rules[1].action.target",
                "$.rules[2].action.target",
                "$.rules[3].match.processes[0]",
                "$.rules[3].match.addresses[0]",
                "$.rules[3].match.ports[0]",
                "$.rules[3].match.ports[1]",
                "$.rules[4].name",
            ],
            ErrorPaths(config));
    }

    [Fact]
    public void Settings_are_checked()
    {
        var config = Configs.Minimal() with
        {
            Settings = new ProxynatorSettings
            {
                Dns = new DnsSettings { FakeIpRange = "198.18.0.0/30", SniffTimeoutMs = -1 },
                Relay = new RelaySettings { ConnectTimeoutMs = 1 },
            },
        };

        Assert.Equal(["$.settings.dns.fakeIpRange", "$.settings.dns.sniffTimeoutMs", "$.settings.relay.connectTimeoutMs"], ErrorPaths(config));
    }

    [Fact]
    public void Store_keeps_old_configuration_when_new_one_is_invalid()
    {
        var store = new ConfigurationStore(Configs.Minimal() with { Rules = [Configs.Rule("a", RuleActionType.Block)] });
        var before = store.Current;

        var errors = store.TryApply(Configs.Minimal() with { Rules = [Configs.Rule("b", RuleActionType.Proxy, "missing")] });

        Assert.NotEmpty(errors);
        Assert.Same(before, store.Current);
    }

    [Fact]
    public void Store_applies_valid_configuration_and_raises_event()
    {
        var store = new ConfigurationStore(Configs.Minimal());
        ActiveConfiguration? raised = null;
        store.Changed += (_, active) => raised = active;

        var errors = store.TryApply(Configs.Minimal() with { Rules = [Configs.Rule("a", RuleActionType.Block)] });

        Assert.Empty(errors);
        Assert.Same(store.Current, raised);
        Assert.Equal(1, store.Current.Rules.Count);
    }

    [Fact]
    public void Active_configuration_resolves_chains_and_proxy_endpoints()
    {
        var active = ActiveConfiguration.Create(Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("a", ProxyType.Socks5, 1080), Configs.Proxy("b", ProxyType.Http, 8080, host: "proxy.example")],
            Chains = [new ChainDefinition { Id = "ab", Hops = ["a", "B"] }],
        });

        Assert.Equal(["a", "b"], active.Routes["AB"].Hops.Select(h => h.Id));
        Assert.Equal(2, active.ProxyEndpoints.Count);
        Assert.Contains(active.ProxyEndpoints, e => e.Host == "proxy.example" && e.Port == 8080);
    }

    [Fact]
    public void A_remote_dns_server_needs_an_address_a_port_and_a_known_route()
    {
        static ProxynatorConfig With(RemoteDnsServer server) => Configs.Minimal() with
        {
            Settings = new ProxynatorSettings { Dns = new DnsSettings { RemoteServer = server } },
            Proxies = [Configs.Proxy("pivot", ProxyType.Socks5, 1080)],
        };

        Assert.Empty(ErrorPaths(With(new RemoteDnsServer { Address = "10.0.0.10", Via = "pivot" })));
        Assert.Equal(
            ["$.settings.dns.remoteServer.address", "$.settings.dns.remoteServer.port", "$.settings.dns.remoteServer.via"],
            ErrorPaths(With(new RemoteDnsServer { Address = "dc01.corp.local", Port = 0, Via = "nope" })));
    }
}
