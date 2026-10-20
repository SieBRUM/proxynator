namespace Proxynator.Core.Hooking;

/// <summary>A response to a <see cref="HookRequest"/>. See <see cref="HookProtocol"/> for the wire format.</summary>
public abstract record HookResponse
{
    /// <summary>The message type, the same as the request's.</summary>
    public abstract HookMessageType Type { get; }
}
