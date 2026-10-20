using Proxynator.Core.Configuration;
using Proxynator.Core.Proxies;

namespace Proxynator.Core.Rules;

/// <summary>The outcome of rule evaluation for one connection.</summary>
/// <param name="RuleName">The matching rule, or <see cref="ImplicitRuleName"/>.</param>
/// <param name="Action">What to do.</param>
/// <param name="Route">The proxy route for <see cref="RuleActionType.Proxy"/>.</param>
/// <param name="UdpFallback">What to do with UDP when the route cannot carry it.</param>
public sealed record RuleDecision(string RuleName, RuleActionType Action, ProxyRoute? Route, UdpFallback UdpFallback)
{
    /// <summary>The name reported when no rule matched.</summary>
    public const string ImplicitRuleName = "(no matching rule)";

    /// <summary>The decision used when no rule matches: connect directly.</summary>
    public static RuleDecision ImplicitDirect { get; } = new(ImplicitRuleName, RuleActionType.Direct, null, UdpFallback.Direct);
}
