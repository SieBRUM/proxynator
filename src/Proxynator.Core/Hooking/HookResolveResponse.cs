using System.Net;

namespace Proxynator.Core.Hooking;

/// <summary>The answer to a <see cref="HookResolveRequest"/>.</summary>
/// <param name="FakeAddress">The fake IPv4 address to return instead of resolving, or null to resolve normally.</param>
public sealed record HookResolveResponse(IPAddress? FakeAddress) : HookResponse
{
    /// <summary>Resolve the name normally.</summary>
    public static HookResolveResponse ResolveNormally { get; } = new((IPAddress?)null);

    /// <inheritdoc />
    public override HookMessageType Type => HookMessageType.Resolve;
}
