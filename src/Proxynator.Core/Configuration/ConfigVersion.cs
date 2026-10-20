namespace Proxynator.Core.Configuration;

/// <summary>Configuration schema versions understood by this build.</summary>
public static class ConfigVersion
{
    /// <summary>The oldest version that can still be loaded (through migrations).</summary>
    public const int Minimum = 1;

    /// <summary>The version this build writes and works with.</summary>
    public const int Current = 1;
}
