using Proxynator.Core.Processes;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Proxies;

namespace Proxynator.Core.Rules;

/// <summary>A <see cref="RuleDefinition"/> with its patterns parsed, ready for fast matching.</summary>
internal sealed class CompiledRule
{
    private readonly ProcessPattern[] processes;
    private readonly bool includeChildren;
    private readonly WildcardPattern[] hosts;
    private readonly AddressRange[] addresses;
    private readonly PortRange[] ports;
    private readonly TransportProtocol[] protocols;

    private CompiledRule(RuleDefinition definition, RuleDecision decision)
    {
        var match = definition.Match;
        Decision = decision;
        processes = [.. match.Processes.Select(p => new ProcessPattern(p))];
        includeChildren = match.IncludeChildren;
        hosts = [.. match.Hosts.Select(h => new WildcardPattern(h))];
        addresses = [.. match.Addresses.Select(a => AddressRange.TryParse(a, out var range) ? range : throw new ArgumentException($"Invalid address '{a}'."))];
        ports = [.. match.Ports.Select(p => PortRange.TryParse(p, out var range) ? range : throw new ArgumentException($"Invalid port '{p}'."))];
        protocols = [.. match.Protocols];
    }

    public RuleDecision Decision { get; }

    public bool HasHostCriteria => hosts.Length > 0;

    public static CompiledRule Compile(RuleDefinition definition, IReadOnlyDictionary<string, ProxyRoute> routes)
    {
        var action = definition.Action;
        ProxyRoute? route = null;
        if (action.Type == RuleActionType.Proxy &&
            (action.Target is null || !routes.TryGetValue(action.Target, out route)))
        {
            throw new ArgumentException($"Rule '{definition.Name}' targets unknown proxy or chain '{action.Target}'.", nameof(definition));
        }

        return new CompiledRule(definition, new RuleDecision(definition.Name, action.Type, route, action.Udp));
    }

    public bool Matches(ConnectionContext context) => MatchesExceptHost(context) && MatchesHost(context.DestinationHost);

    /// <summary>Checks every criterion except hostnames.</summary>
    public bool MatchesExceptHost(ConnectionContext context) =>
        (protocols.Length == 0 || protocols.Contains(context.Protocol)) &&
        (ports.Length == 0 || ports.Any(p => p.Contains(context.DestinationPort))) &&
        (addresses.Length == 0 || (context.DestinationAddress is { } address && addresses.Any(a => a.Contains(address)))) &&
        MatchesProcess(context);

    public bool MatchesHost(string? host) =>
        hosts.Length == 0 || (host is not null && hosts.Any(h => h.IsMatch(host)));

    private bool MatchesProcess(ConnectionContext context) => MatchesProcess(context.Process);

    /// <summary>Checks only the process criteria (name/path, children).</summary>
    public bool MatchesProcess(ProcessInfo? process)
    {
        if (processes.Length == 0)
        {
            return true;
        }

        if (process is null)
        {
            return false;
        }

        return processes.Any(p => p.IsMatch(process)) ||
               (includeChildren && process.Ancestors.Any(ancestor => processes.Any(p => p.IsMatch(ancestor))));
    }
}
