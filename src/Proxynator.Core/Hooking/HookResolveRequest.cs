namespace Proxynator.Core.Hooking;

/// <summary>A name is about to be resolved by the process.</summary>
/// <param name="Hostname">The name.</param>
public sealed record HookResolveRequest(string Hostname) : HookRequest
{
    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Resolve;
}
