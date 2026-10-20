namespace Proxynator.Core.Configuration;

/// <summary>The action of a rule.</summary>
public sealed record RuleActionDefinition
{
    /// <summary>The action type.</summary>
    public required RuleActionType Type { get; init; }

    /// <summary>Proxy or chain identifier; required for <see cref="RuleActionType.Proxy"/>, not allowed otherwise.</summary>
    public string? Target { get; set; }

    /// <summary>What to do with UDP traffic when the target cannot carry UDP.</summary>
    public UdpFallback Udp { get; set; } = UdpFallback.Block;
}
