using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>How destination hostnames are obtained and passed to proxies.</summary>
public enum DnsMode
{
    /// <summary>Resolve locally, but recover the hostname from TLS SNI or the HTTP <c>Host</c> header and send it to the proxy.</summary>
    [JsonStringEnumMemberName("sniff")]
    Sniff,

    /// <summary>Resolve locally and send the IP address to the proxy.</summary>
    [JsonStringEnumMemberName("local")]
    Local,

    /// <summary>Answer DNS with fake addresses and let the proxy resolve the real hostname.</summary>
    [JsonStringEnumMemberName("remote")]
    Remote,
}
