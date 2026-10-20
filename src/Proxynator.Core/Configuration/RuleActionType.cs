using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>What happens to a connection matched by a rule.</summary>
public enum RuleActionType
{
    /// <summary>Send the connection through a proxy or chain.</summary>
    [JsonStringEnumMemberName("proxy")]
    Proxy,

    /// <summary>Let the connection go to its destination directly.</summary>
    [JsonStringEnumMemberName("direct")]
    Direct,

    /// <summary>Refuse the connection.</summary>
    [JsonStringEnumMemberName("block")]
    Block,
}
