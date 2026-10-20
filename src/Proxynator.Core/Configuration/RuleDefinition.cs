namespace Proxynator.Core.Configuration;

/// <summary>A routing rule.</summary>
public sealed record RuleDefinition
{
    /// <summary>Unique, human-readable name.</summary>
    public required string Name { get; init; }

    /// <summary>Disabled rules are skipped.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Criteria; an empty match matches everything.</summary>
    public RuleMatch Match { get; set; } = new();

    /// <summary>What to do with matching connections.</summary>
    public required RuleActionDefinition Action { get; init; }
}
