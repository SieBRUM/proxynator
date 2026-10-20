using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>Upstream proxy protocol.</summary>
public enum ProxyType
{
    /// <summary>SOCKS4: IPv4 destinations only, optional user ID.</summary>
    [JsonStringEnumMemberName("socks4")]
    Socks4,

    /// <summary>SOCKS4a: SOCKS4 plus hostname destinations.</summary>
    [JsonStringEnumMemberName("socks4a")]
    Socks4a,

    /// <summary>SOCKS5 with optional username/password authentication.</summary>
    [JsonStringEnumMemberName("socks5")]
    Socks5,

    /// <summary>HTTP proxy using <c>CONNECT</c> tunnelling (carries HTTPS and any other TCP traffic).</summary>
    [JsonStringEnumMemberName("http")]
    Http,
}
