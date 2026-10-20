using Proxynator.Core.Configuration;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>One proxy in a route.</summary>
public sealed record ProxyHop(string Id, ProxyType Type, TargetEndpoint Endpoint, ProxyCredentials? Credentials)
{
    /// <summary>Creates a hop from a validated configuration entry.</summary>
    public static ProxyHop FromDefinition(ProxyDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        var credentials = definition.Auth is { } auth ? new ProxyCredentials(auth.Username, auth.Password ?? string.Empty) : null;
        return new ProxyHop(definition.Id, definition.Type, TargetEndpoint.FromHost(definition.Host, definition.Port), credentials);
    }
}
