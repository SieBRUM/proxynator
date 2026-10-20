namespace Proxynator.Platform.Windows.Interop;

/// <summary><c>WINDIVERT_LAYER</c>.</summary>
internal enum WinDivertLayer
{
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}
