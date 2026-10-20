namespace Proxynator.Core.Hooking;

/// <summary>The first message of a session.</summary>
/// <param name="PointerBits">32 or 64: the bitness of the hooked process.</param>
public sealed record HookHelloRequest(int PointerBits) : HookRequest
{
    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Hello;
}
