namespace Proxynator.Core.Hooking;

/// <summary>A request from a hooked process. See <see cref="HookProtocol"/> for the wire format.</summary>
public abstract record HookRequest
{
    /// <summary>The message type.</summary>
    public abstract HookMessageType Type { get; }
}
