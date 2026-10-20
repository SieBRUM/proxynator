namespace Proxynator.Core.Hooking;

/// <summary>The request types of the hook registration protocol (see <see cref="HookProtocol"/>).</summary>
public enum HookMessageType : byte
{
    /// <summary>Sent once after connecting: the hooked process introduces itself.</summary>
    Hello = 1,

    /// <summary>A socket is about to connect (TCP) or send (UDP): direct, relay or block?</summary>
    Connect = 2,

    /// <summary>A name is about to be resolved: should it get a fake address (remote DNS mode)?</summary>
    Resolve = 3,
}
