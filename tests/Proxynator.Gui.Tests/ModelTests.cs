using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Gui.ViewModels;

namespace Proxynator.Gui.Tests;

/// <summary>The editable items and helpers, without a service.</summary>
public class ModelTests
{
    [Theory]
    [InlineData("", new string[0])]
    [InlineData("a, b;c\nd\r\n e ", new[] { "a", "b", "c", "d", "e" })]
    [InlineData(" , ,", new string[0])]
    public void List_text_is_split_on_commas_semicolons_and_lines(string text, string[] expected) => Assert.Equal(expected, ListText.Parse(text));

    [Fact]
    public void Rules_round_trip_through_the_editor()
    {
        var rule = new RuleDefinition
        {
            Name = "r",
            Enabled = false,
            Match = new RuleMatch
            {
                Processes = ["a.exe", "b*"],
                IncludeChildren = true,
                Hosts = ["*.corp.local"],
                Addresses = ["10.0.0.0/8"],
                Ports = ["389", "3268-3269"],
                Protocols = [TransportProtocol.Udp],
            },
            Action = new RuleActionDefinition { Type = RuleActionType.Proxy, Target = "pivot", Udp = UdpFallback.Direct },
        };

        var item = RuleItem.From(rule);
        Assert.Equal((false, true), (item.Tcp, item.Udp));
        Assert.Equal("a.exe, b* (+children); *.corp.local; 10.0.0.0/8; port 389, 3268-3269; udp → proxy via pivot", item.Summary);
        Assert.Equivalent(rule, item.ToDefinition(), strict: true);
    }

    [Fact]
    public void A_rule_without_protocols_matches_both_and_direct_rules_have_no_target()
    {
        var item = RuleItem.From(new RuleDefinition { Name = "d", Action = new RuleActionDefinition { Type = RuleActionType.Direct } });
        Assert.Equal((true, true), (item.Tcp, item.Udp));
        Assert.Equal("everything → direct", item.Summary);

        item.Target = "leftover";
        var definition = item.ToDefinition();
        Assert.Empty(definition.Match.Protocols);
        Assert.Null(definition.Action.Target);
    }

    [Fact]
    public void Socks4_proxies_keep_a_user_id_but_no_password()
    {
        var item = new ProxyItem { Id = "s4", Type = ProxyType.Socks4a, Host = "h", Port = "1080", Username = "uid", Password = "ignored" };
        Assert.False(item.SupportsPassword);
        var auth = item.ToDefinition().Auth!;
        Assert.Equal(("uid", null), (auth.Username, auth.Password));

        item.Port = "80a";
        Assert.False(item.HasNumericPort);
        Assert.Equal(0, item.ToDefinition().Port);
    }

    [Fact]
    public void Settings_keep_what_the_editor_does_not_show()
    {
        var original = new ProxynatorSettings { Capture = new CaptureSettings { ProxyLoopback = true } };
        var item = SettingsItem.From(original);
        item.ConnectTimeoutMs = "3000";
        List<ConfigError> problems = [];

        var settings = item.ToSettings(original, problems);

        Assert.Empty(problems);
        Assert.True(settings.Capture.ProxyLoopback);
        Assert.False(item.RemoteServerResolveNames);
        Assert.Equal(3000, settings.Relay.ConnectTimeoutMs);
        Assert.Null(settings.Dns.RemoteServer);
    }

    [Theory]
    [InlineData(new string[0], null)]
    [InlineData(new[] { "--endpoint", "custom" }, "custom")]
    [InlineData(new[] { "--endpoint=/tmp/x.sock", "--other" }, "/tmp/x.sock")]
    public void The_endpoint_comes_from_the_command_line(string[] args, string? expected) =>
        Assert.Equal(expected ?? Ipc.IpcEndpoint.Default, GuiOptions.Parse(args).Endpoint);

    [Fact]
    public void The_remote_server_and_its_resolve_names_option_round_trip()
    {
        var original = new ProxynatorSettings
        {
            Dns = new DnsSettings { Mode = DnsMode.Remote, RemoteServer = new RemoteDnsServer { Address = "10.0.0.10", Via = "pivot", ResolveNames = true } },
        };
        List<ConfigError> problems = [];

        var item = SettingsItem.From(original);
        var settings = item.ToSettings(original, problems);

        Assert.True(item.RemoteServerResolveNames);
        Assert.Empty(problems);
        Assert.Equal(original.Dns.RemoteServer, settings.Dns.RemoteServer);
    }
}
