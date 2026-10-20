using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;
using Proxynator.Core.Rules;

namespace Proxynator.Platform.Linux.Capture;

/// <summary>
/// What the eBPF programs are told about a process (the value of the <c>decisions</c> map; see
/// native/linux/bpf/proxynator.bpf.c). Pure code, tested on every OS.
/// </summary>
internal static class ProcessClassifier
{
    public const uint DecisionTarget = 1;
    public const uint DecisionIgnore = 2;
    public const uint DecisionUdpBlockQuic = 4;
    public const uint DecisionUdpBlock = 8;
    public const uint DecisionDnsRedirect = 16;

    internal static uint Decide(ActiveConfiguration active, ProcessInfo? process, bool isService)
    {
        if (isService || process is null || !active.Rules.MayRelay(process))
        {
            return DecisionIgnore;
        }

        var value = DecisionTarget;
        if (Blocks(active, process, 443, quic: true))
        {
            value |= DecisionUdpBlockQuic;
        }

        if (Blocks(active, process, 53, quic: false))
        {
            value |= DecisionUdpBlock;
        }

        if (active.Settings.Dns.Mode == DnsMode.Remote)
        {
            value |= DecisionDnsRedirect;
        }

        return value;
    }

    /// <summary>UDP is not relayed in this mode: what the rules say for a datagram to an unknown address on this port.</summary>
    private static bool Blocks(ActiveConfiguration active, ProcessInfo process, int port, bool quic)
    {
        var decision = active.Rules.Evaluate(new ConnectionContext(process, TransportProtocol.Udp, null, null, port));
        return decision.Action switch
        {
            RuleActionType.Block => true,
            RuleActionType.Proxy => (quic && active.Settings.Udp.BlockQuic) || decision.UdpFallback == UdpFallback.Block,
            _ => false,
        };
    }
}
