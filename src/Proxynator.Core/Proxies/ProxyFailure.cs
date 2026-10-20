namespace Proxynator.Core.Proxies;

/// <summary>Why establishing a connection through a proxy failed.</summary>
public enum ProxyFailure
{
    /// <summary>The proxy itself could not be reached.</summary>
    ConnectFailed,

    /// <summary>The proxy did not complete the handshake in time.</summary>
    Timeout,

    /// <summary>The proxy rejected the credentials, or none were offered when required.</summary>
    AuthenticationFailed,

    /// <summary>The proxy refused to connect to the target.</summary>
    Rejected,

    /// <summary>The proxy violated the protocol or closed the connection unexpectedly.</summary>
    ProtocolError,

    /// <summary>The target cannot be expressed in this proxy protocol (e.g. IPv6 over SOCKS4).</summary>
    Unsupported,

    /// <summary>The target hostname had to be resolved locally and could not be.</summary>
    HostResolutionFailed,
}
