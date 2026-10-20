using Proxynator.Core.Configuration;
using Proxynator.Core.Processes;
using Proxynator.Core.Proxies;

namespace Proxynator.Core.Rules;

/// <summary>Evaluates an ordered rule list; the first matching enabled rule wins, otherwise the connection goes direct.</summary>
public sealed class RuleEngine
{
    private readonly CompiledRule[] rules;

    internal RuleEngine(IEnumerable<CompiledRule> rules)
    {
        this.rules = [.. rules];
        UsesHostCriteria = this.rules.Any(r => r.HasHostCriteria);
    }

    /// <summary>Whether any rule matches on hostnames (so hostnames are worth sniffing even for direct traffic).</summary>
    public bool UsesHostCriteria { get; }

    /// <summary>The number of enabled rules.</summary>
    public int Count => rules.Length;

    /// <summary>Compiles validated rule definitions. Disabled rules are dropped.</summary>
    /// <exception cref="ArgumentException">A definition is invalid or targets an unknown route.</exception>
    public static RuleEngine Create(IEnumerable<RuleDefinition> definitions, IReadOnlyDictionary<string, ProxyRoute> routes)
    {
        ArgumentNullException.ThrowIfNull(definitions);
        ArgumentNullException.ThrowIfNull(routes);
        return new RuleEngine(definitions.Where(d => d.Enabled).Select(d => CompiledRule.Compile(d, routes)));
    }

    /// <summary>Returns the decision for a connection.</summary>
    public RuleDecision Evaluate(ConnectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        foreach (var rule in rules)
        {
            if (rule.Matches(context))
            {
                return rule.Decision;
            }
        }

        return RuleDecision.ImplicitDirect;
    }

    /// <summary>
    /// Whether any rule with a non-direct action could apply to connections of <paramref name="process"/>, judging
    /// by process criteria only. Kernel-level backends that classify processes up front use it: when it is false,
    /// none of the process's connections need the relay.
    /// </summary>
    public bool MayRelay(ProcessInfo? process) =>
        rules.Any(rule => rule.Decision.Action != RuleActionType.Direct && rule.MatchesProcess(process));

    /// <summary>
    /// Decides whether a capture backend must hand a new connection to the relay. The hostname may still be unknown
    /// at that point: a rule that would match if its hostname criterion matched counts as a possible match, so
    /// the connection is relayed whenever a non-direct outcome is possible.
    /// </summary>
    public bool RequiresRelay(ConnectionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        foreach (var rule in rules)
        {
            if (!rule.MatchesExceptHost(context))
            {
                continue;
            }

            if (rule.HasHostCriteria && context.DestinationHost is null)
            {
                if (rule.Decision.Action != RuleActionType.Direct)
                {
                    return true;
                }

                continue;
            }

            if (rule.MatchesHost(context.DestinationHost))
            {
                return rule.Decision.Action != RuleActionType.Direct;
            }
        }

        return false;
    }
}
