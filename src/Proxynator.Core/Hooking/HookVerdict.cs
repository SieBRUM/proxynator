namespace Proxynator.Core.Hooking;

/// <summary>What a hooked socket must do with a connection attempt.</summary>
public enum HookVerdict : byte
{
    /// <summary>Connect to the original destination, untouched.</summary>
    Direct = 0,

    /// <summary>Connect to the relay endpoint in the response instead; the original destination is registered.</summary>
    Relay = 1,

    /// <summary>Fail the call (TCP: connection refused; UDP: network unreachable).</summary>
    Block = 2,
}
