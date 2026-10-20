using System.Net;

namespace Proxynator.Core.Net;

/// <summary>Address helpers.</summary>
public static class NetExtensions
{
    /// <summary>Converts IPv4-mapped IPv6 addresses (<c>::ffff:a.b.c.d</c>) to plain IPv4.</summary>
    public static IPAddress Normalize(this IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    /// <summary>Converts an endpoint with an IPv4-mapped IPv6 address to a plain IPv4 endpoint.</summary>
    public static IPEndPoint Normalize(this IPEndPoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return endpoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endpoint.Address.MapToIPv4(), endpoint.Port) : endpoint;
    }
}
