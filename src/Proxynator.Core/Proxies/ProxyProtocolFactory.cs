using Proxynator.Core.Configuration;

namespace Proxynator.Core.Proxies;

/// <summary>Creates the <see cref="IProxyProtocol"/> for a hop.</summary>
public static class ProxyProtocolFactory
{
    /// <summary>Returns the protocol handler for <paramref name="hop"/>.</summary>
    public static IProxyProtocol Create(ProxyHop hop)
    {
        ArgumentNullException.ThrowIfNull(hop);
        return hop.Type switch
        {
            ProxyType.Socks4 => new Socks4Protocol(allowHostnames: false, hop.Credentials?.Username ?? string.Empty),
            ProxyType.Socks4a => new Socks4Protocol(allowHostnames: true, hop.Credentials?.Username ?? string.Empty),
            ProxyType.Socks5 => new Socks5Protocol(hop.Credentials),
            ProxyType.Http => new HttpConnectProtocol(hop.Credentials),
            _ => throw new ArgumentOutOfRangeException(nameof(hop), hop.Type, "Unknown proxy type."),
        };
    }
}
