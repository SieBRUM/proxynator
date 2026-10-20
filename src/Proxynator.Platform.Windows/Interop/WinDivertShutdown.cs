namespace Proxynator.Platform.Windows.Interop;

/// <summary><c>WINDIVERT_SHUTDOWN</c>.</summary>
internal enum WinDivertShutdown
{
    Recv = 0x1,
    Send = 0x2,
    Both = 0x3,
}
