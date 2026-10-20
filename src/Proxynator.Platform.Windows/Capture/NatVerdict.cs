namespace Proxynator.Platform.Windows.Capture;

/// <summary>What to do with a packet after <see cref="ReflectNat.Process"/>.</summary>
internal enum NatVerdict
{
    /// <summary>Not ours: reinject unchanged.</summary>
    PassThrough,

    /// <summary>Rewritten: reinject as an inbound packet (checksums must be recalculated).</summary>
    Reflect,

    /// <summary>Drop the packet.</summary>
    Drop,
}
