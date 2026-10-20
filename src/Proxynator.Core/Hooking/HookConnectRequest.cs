using System.Net;
using Proxynator.Core.Net;

namespace Proxynator.Core.Hooking;

/// <summary>A socket is about to connect or send.</summary>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="LocalEndpoint">
/// The endpoint the socket will connect to the relay from (the hook binds unbound sockets first; a wildcard address is
/// reported as loopback). This is the key the relay looks the original destination up by.
/// </param>
/// <param name="RemoteEndpoint">The original destination.</param>
/// <param name="Hostname">The name the process resolved to this address, if the resolver hooks saw it.</param>
public sealed record HookConnectRequest(TransportProtocol Protocol, IPEndPoint LocalEndpoint, IPEndPoint RemoteEndpoint, string? Hostname) : HookRequest
{
    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Connect;
}
