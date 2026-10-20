namespace Proxynator.Core.Hooking;

/// <summary>Accepts a session.</summary>
/// <param name="ServiceProcessId">The service's PID (for the hook's diagnostics).</param>
public sealed record HookHelloResponse(int ServiceProcessId) : HookResponse
{
    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Hello;
}
