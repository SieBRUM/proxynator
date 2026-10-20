using Proxynator.Core.Configuration;
using Proxynator.Core.Processes;
using Proxynator.Platform.Linux.Capture;

namespace Proxynator.Platform.Linux.Tests;

/// <summary>What the eBPF programs are told about each process (ProcessClassifier).</summary>
public sealed class ClassificationTests
{
    private const uint Target = 1;
    private const uint Ignore = 2;
    private const uint BlockQuic = 4;
    private const uint BlockUdp = 8;
    private const uint DnsRedirect = 16;

    private static readonly ProcessInfo Nxc = new(10, "nxc", "/usr/bin/python3.12");
    private static readonly ProcessInfo Firefox = new(11, "firefox", "/usr/lib/firefox/firefox");

    private static ActiveConfiguration Config(UdpFallback udp = UdpFallback.Block, DnsMode dns = DnsMode.Sniff, RuleActionType action = RuleActionType.Proxy) =>
        ActiveConfiguration.Create(new ProxynatorConfig
        {
            Version = ConfigVersion.Current,
            Settings = new ProxynatorSettings { Dns = new DnsSettings { Mode = dns } },
            Proxies = [new ProxyDefinition { Id = "pivot", Type = ProxyType.Socks5, Host = "127.0.0.1", Port = 1080 }],
            Rules =
            [
                new RuleDefinition
                {
                    Name = "nxc",
                    Match = new RuleMatch { Processes = ["nxc"] },
                    Action = new RuleActionDefinition { Type = action, Target = action == RuleActionType.Proxy ? "pivot" : null, Udp = udp },
                },
            ],
        });

    [Fact]
    public void Processes_no_rule_can_apply_to_are_ignored()
    {
        Assert.Equal(Ignore, ProcessClassifier.Decide(Config(), Firefox, isService: false));
        Assert.Equal(Ignore, ProcessClassifier.Decide(Config(), null, isService: false));
    }

    [Fact]
    public void The_service_itself_is_always_ignored()
    {
        Assert.Equal(Ignore, ProcessClassifier.Decide(Config(), Nxc, isService: true));
    }

    [Fact]
    public void Proxied_processes_get_their_udp_blocked_by_default()
    {
        Assert.Equal(Target | BlockQuic | BlockUdp, ProcessClassifier.Decide(Config(), Nxc, isService: false));
    }

    [Fact]
    public void Udp_fallback_direct_still_blocks_quic()
    {
        Assert.Equal(Target | BlockQuic, ProcessClassifier.Decide(Config(UdpFallback.Direct), Nxc, isService: false));
    }

    [Fact]
    public void Remote_dns_redirects_the_dns_queries_of_candidates()
    {
        Assert.Equal(Target | BlockQuic | DnsRedirect, ProcessClassifier.Decide(Config(UdpFallback.Direct, DnsMode.Remote), Nxc, isService: false));
    }

    [Fact]
    public void Block_rules_block_all_udp()
    {
        Assert.Equal(Target | BlockQuic | BlockUdp, ProcessClassifier.Decide(Config(action: RuleActionType.Block), Nxc, isService: false));
    }
}
