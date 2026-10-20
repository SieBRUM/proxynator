using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>What to do with UDP traffic when the rule's proxy target cannot carry UDP.</summary>
public enum UdpFallback
{
    /// <summary>Drop the UDP traffic.</summary>
    [JsonStringEnumMemberName("block")]
    Block,

    /// <summary>Send the UDP traffic directly, bypassing the proxy.</summary>
    [JsonStringEnumMemberName("direct")]
    Direct,
}
