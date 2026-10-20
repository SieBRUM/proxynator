namespace Proxynator.Core.Configuration;

/// <summary>
/// A DNS server inside the target network, reached through a proxy (DNS over TCP). In <see cref="DnsMode.Remote"/>,
/// queries for <c>remoteDomains</c> that cannot be answered with a fake address (SRV, TXT, MX, ...; e.g. the
/// <c>_ldap._tcp.dc._msdcs.corp.local</c> lookups that find domain controllers) go there instead of to the local
/// DNS server, which does not know the internal domain.
/// </summary>
public sealed record RemoteDnsServer
{
    /// <summary>The server's IP address as seen from the far side of the proxy, e.g. a domain controller.</summary>
    public required string Address { get; init; }

    /// <summary>The DNS port.</summary>
    public int Port { get; set; } = 53;

    /// <summary>The proxy or chain to reach it through.</summary>
    public required string Via { get; init; }
}
