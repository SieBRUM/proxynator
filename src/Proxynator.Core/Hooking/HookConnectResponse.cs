using System.Net;

namespace Proxynator.Core.Hooking;

/// <summary>The decision for a <see cref="HookConnectRequest"/>.</summary>
/// <param name="Verdict">What to do.</param>
/// <param name="RelayEndpoint">Where to connect instead, for <see cref="HookVerdict.Relay"/>.</param>
public sealed record HookConnectResponse(HookVerdict Verdict, IPEndPoint? RelayEndpoint = null) : HookResponse
{
    /// <summary>Connect directly.</summary>
    public static HookConnectResponse Direct { get; } = new(HookVerdict.Direct);

    /// <summary>Fail the call.</summary>
    public static HookConnectResponse Block { get; } = new(HookVerdict.Block);

    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Connect;
}
