using System.Text.Json.Serialization;

namespace Proxynator.Core.Net;

/// <summary>Transport-layer protocol.</summary>
public enum TransportProtocol
{
    /// <summary>TCP.</summary>
    [JsonStringEnumMemberName("tcp")]
    Tcp,

    /// <summary>UDP.</summary>
    [JsonStringEnumMemberName("udp")]
    Udp,
}
