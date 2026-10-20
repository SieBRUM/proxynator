using System.Net;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Rules;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Rules;

public class RuleEngineTests
{
    private static readonly ProcessInfo Test = new(1, "test.exe", @"C:\Apps\test.exe");
    private static readonly ProcessInfo Test3 = new(3, "test3.exe", @"C:\Apps\test3.exe");
    private static readonly ProcessInfo Other = new(9, "other.exe", @"C:\Windows\other.exe");

    private static RuleEngine Engine(params RuleDefinition[] rules) =>
        ActiveConfiguration.Create(Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, 5000), Configs.Proxy("burp", ProxyType.Http, 8080)],
            Chains = [new ChainDefinition { Id = "chain", Hops = ["socks", "burp"] }],
            Rules = rules,
        }).Rules;

    private static ConnectionContext Connection(
        ProcessInfo? process, int port = 443, string? host = null, string address = "93.184.216.34", TransportProtocol protocol = TransportProtocol.Tcp) =>
        new(process, protocol, IPAddress.Parse(address), host, port);

    [Fact]
    public void Different_processes_go_to_different_proxies()
    {
        var engine = Engine(
            Configs.Rule("test", RuleActionType.Proxy, "socks", new RuleMatch { Processes = ["test.exe"] }),
            Configs.Rule("test3", RuleActionType.Proxy, "burp", new RuleMatch { Processes = ["test3.exe"] }));

        var forTest = engine.Evaluate(Connection(Test));
        var forTest3 = engine.Evaluate(Connection(Test3));
        var forOther = engine.Evaluate(Connection(Other));

        Assert.Equal(("test", "socks"), (forTest.RuleName, forTest.Route!.Id));
        Assert.Equal(("test3", "burp"), (forTest3.RuleName, forTest3.Route!.Id));
        Assert.Same(RuleDecision.ImplicitDirect, forOther);
    }

    [Fact]
    public void First_match_wins()
    {
        var engine = Engine(
            Configs.Rule("block 25", RuleActionType.Block, match: new RuleMatch { Ports = ["25"] }),
            Configs.Rule("everything via chain", RuleActionType.Proxy, "chain"));

        Assert.Equal(RuleActionType.Block, engine.Evaluate(Connection(Test, port: 25)).Action);
        var decision = engine.Evaluate(Connection(Test, port: 443));
        Assert.Equal(["socks", "burp"], decision.Route!.Hops.Select(h => h.Id));
    }

    [Fact]
    public void Disabled_rules_are_skipped()
    {
        var engine = Engine(Configs.Rule("off", RuleActionType.Block) with { Enabled = false });

        Assert.Equal(0, engine.Count);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Test)).Action);
    }

    [Theory]
    [InlineData("TEST.EXE", true)]
    [InlineData("test*", true)]
    [InlineData("t?st.exe", true)]
    [InlineData("*.exe", true)]
    [InlineData("test", false)]
    [InlineData(@"C:\Apps\*", true)]
    [InlineData("c:/apps/test.exe", true)]
    [InlineData(@"C:\Other\test.exe", false)]
    public void Process_patterns(string pattern, bool expected)
    {
        var engine = Engine(Configs.Rule("r", RuleActionType.Block, match: new RuleMatch { Processes = [pattern] }));

        Assert.Equal(expected, engine.Evaluate(Connection(Test)).Action == RuleActionType.Block);
    }

    [Fact]
    public void Unknown_process_does_not_match_process_rules()
    {
        var engine = Engine(Configs.Rule("r", RuleActionType.Block, match: new RuleMatch { Processes = ["*"] }));

        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(null)).Action);
    }

    [Fact]
    public void Children_match_only_when_enabled()
    {
        var child = new ProcessInfo(20, "helper.exe", null) { Ancestors = [new ProcessInfo(10, "launcher.exe", null), Test] };
        var withChildren = Engine(Configs.Rule("r", RuleActionType.Block, match: new RuleMatch { Processes = ["test.exe"], IncludeChildren = true }));
        var withoutChildren = Engine(Configs.Rule("r", RuleActionType.Block, match: new RuleMatch { Processes = ["test.exe"] }));

        Assert.Equal(RuleActionType.Block, withChildren.Evaluate(Connection(child)).Action);
        Assert.Equal(RuleActionType.Direct, withoutChildren.Evaluate(Connection(child)).Action);
    }

    [Fact]
    public void Destination_criteria_are_combined_with_and()
    {
        var engine = Engine(Configs.Rule("r", RuleActionType.Block, match: new RuleMatch
        {
            Processes = ["test.exe"],
            Addresses = ["10.0.0.0/8"],
            Ports = ["80", "8000-8100"],
            Protocols = [TransportProtocol.Tcp],
        }));

        Assert.Equal(RuleActionType.Block, engine.Evaluate(Connection(Test, 8080, address: "10.1.2.3")).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Test, 443, address: "10.1.2.3")).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Test, 80, address: "11.1.2.3")).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Test, 80, address: "10.1.2.3", protocol: TransportProtocol.Udp)).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Other, 80, address: "10.1.2.3")).Action);
    }

    [Fact]
    public void Host_rules_need_a_known_hostname()
    {
        var engine = Engine(Configs.Rule("r", RuleActionType.Proxy, "burp", new RuleMatch { Hosts = ["*.example.com"] }));

        Assert.True(engine.UsesHostCriteria);
        Assert.Equal(RuleActionType.Proxy, engine.Evaluate(Connection(Other, host: "api.Example.com")).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Other, host: "example.com")).Action);
        Assert.Equal(RuleActionType.Direct, engine.Evaluate(Connection(Other, host: null)).Action);
    }

    [Fact]
    public void RequiresRelay_is_false_for_definite_direct()
    {
        var engine = Engine(
            Configs.Rule("direct for other", RuleActionType.Direct, match: new RuleMatch { Processes = ["other.exe"] }),
            Configs.Rule("test via socks", RuleActionType.Proxy, "socks", new RuleMatch { Processes = ["test.exe"] }));

        Assert.False(engine.RequiresRelay(Connection(Other)));
        Assert.True(engine.RequiresRelay(Connection(Test)));
        Assert.False(engine.RequiresRelay(Connection(Test3)));
    }

    [Fact]
    public void RequiresRelay_is_true_when_a_host_rule_might_match()
    {
        var engine = Engine(
            Configs.Rule("api via burp", RuleActionType.Proxy, "burp", new RuleMatch { Processes = ["test3.exe"], Hosts = ["api.example.com"] }),
            Configs.Rule("cdn direct", RuleActionType.Direct, match: new RuleMatch { Hosts = ["cdn.example.com"] }),
            Configs.Rule("block test3", RuleActionType.Block, match: new RuleMatch { Processes = ["test3.exe"] }));

        Assert.True(engine.RequiresRelay(Connection(Test3)));
        Assert.True(engine.RequiresRelay(Connection(Test3, host: "other.example.com")));
        Assert.False(engine.RequiresRelay(Connection(Other)));
        Assert.False(engine.RequiresRelay(Connection(Test3, host: "cdn.example.com")));
    }

    [Fact]
    public void Process_candidacy_ignores_destination_criteria()
    {
        var engine = Engine(
            Configs.Rule("direct for test", RuleActionType.Direct, match: new RuleMatch { Processes = ["test3.exe"] }),
            Configs.Rule("test web", RuleActionType.Proxy, "burp", new RuleMatch { Processes = ["test.exe"], Ports = ["443"] }),
            Configs.Rule("children", RuleActionType.Block, match: new RuleMatch { Processes = ["launcher"], IncludeChildren = true }));

        Assert.True(engine.MayRelay(Test));
        Assert.False(engine.MayRelay(Test3)); // only a direct rule applies
        Assert.False(engine.MayRelay(Other));
        Assert.True(engine.MayRelay(Other with { Ancestors = [new ProcessInfo(5, "launcher", null)] }));
        Assert.False(engine.MayRelay(null));
    }

    [Fact]
    public void Rules_without_process_criteria_make_every_process_a_candidate()
    {
        var engine = Engine(Configs.Rule("web", RuleActionType.Proxy, "burp", new RuleMatch { Ports = ["443"] }));

        Assert.True(engine.MayRelay(Other));
        Assert.True(engine.MayRelay(null));
    }

    [Theory]
    [InlineData("nxc", true)]
    [InlineData("*/.local/bin/nxc", true)]
    [InlineData("python3", true)]
    [InlineData("roadtx", false)]
    public void Scripts_run_by_an_interpreter_match_by_name_and_path(string pattern, bool matches)
    {
        var engine = Engine(Configs.Rule("tool", RuleActionType.Proxy, "socks", new RuleMatch { Processes = [pattern] }));
        var python = new ProcessInfo(7, "python3", "/usr/bin/python3.12") { ScriptPath = "/home/u/.local/bin/nxc" };

        Assert.Equal(matches, engine.Evaluate(Connection(python)).Action == RuleActionType.Proxy);
    }
}
