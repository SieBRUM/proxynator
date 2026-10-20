namespace Proxynator.Core.Configuration;

/// <summary>Traffic capture settings.</summary>
public sealed record CaptureSettings
{
    /// <summary>The capture backend to use.</summary>
    public CaptureMode Mode { get; set; } = CaptureMode.Auto;

    /// <summary>Whether connections to loopback addresses are subject to rules. Off by default.</summary>
    public bool ProxyLoopback { get; set; }
}
