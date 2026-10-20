namespace Proxynator.Platform.Windows.Interop;

/// <summary><c>WINDIVERT_FLAG_*</c> values for <c>WinDivertOpen</c>.</summary>
[Flags]
internal enum WinDivertFlags : ulong
{
    None = 0,
    Sniff = 0x0001,
    Drop = 0x0002,
    RecvOnly = 0x0004,
    SendOnly = 0x0008,
    NoInstall = 0x0010,
    Fragments = 0x0020,
}
