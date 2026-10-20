using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>Root of the Proxynator configuration file.</summary>
/// <remarks>
/// Configuration records use <c>required ... { get; init; }</c> for mandatory values and <c>{ get; set; }</c> for
/// optional ones: the System.Text.Json source generator would overwrite the default initializers of init-only
/// properties that are missing from the JSON.
/// </remarks>
public sealed record ProxynatorConfig
{
    /// <summary>Optional JSON schema reference, ignored by Proxynator.</summary>
    [JsonPropertyName("$schema")]
    public string? Schema { get; set; }

    /// <summary>The configuration schema version (see <see cref="ConfigVersion"/>).</summary>
    public required int Version { get; init; }

    /// <summary>Global settings.</summary>
    public ProxynatorSettings Settings { get; set; } = new();

    /// <summary>Upstream proxies that rules and chains can refer to.</summary>
    public IReadOnlyList<ProxyDefinition> Proxies { get; set; } = [];

    /// <summary>Ordered sequences of proxies.</summary>
    public IReadOnlyList<ChainDefinition> Chains { get; set; } = [];

    /// <summary>Ordered rules; the first matching rule wins.</summary>
    public IReadOnlyList<RuleDefinition> Rules { get; set; } = [];
}
