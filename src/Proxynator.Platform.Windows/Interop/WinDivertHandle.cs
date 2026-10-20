using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>A WinDivert handle; closing it removes all of its filters and restores normal packet flow.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WinDivertHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public WinDivertHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => WinDivertNative.Close(handle);
}
