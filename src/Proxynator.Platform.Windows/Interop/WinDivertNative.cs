using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>WinDivert 2.2 user-mode API (<c>WinDivert.dll</c>).</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class WinDivertNative
{
    public const string Library = "WinDivert.dll";

    /// <summary><c>WINDIVERT_MTU_MAX</c>: the largest packet WinDivert can return.</summary>
    public const int MaxPacketSize = 40 + 0xFFFF;

    public const int ErrorNoData = 232;
    public const int ErrorOperationAborted = 995;
    public const int ErrorInvalidHandle = 6;

    [LibraryImport(Library, EntryPoint = "WinDivertOpen", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial WinDivertHandle Open(string filter, WinDivertLayer layer, short priority, WinDivertFlags flags);

    [LibraryImport(Library, EntryPoint = "WinDivertRecv", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Recv(WinDivertHandle handle, byte* packet, uint packetLength, uint* receivedLength, WinDivertAddress* address);

    [LibraryImport(Library, EntryPoint = "WinDivertSend", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Send(WinDivertHandle handle, byte* packet, uint packetLength, uint* sentLength, WinDivertAddress* address);

    [LibraryImport(Library, EntryPoint = "WinDivertShutdown", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Shutdown(WinDivertHandle handle, WinDivertShutdown how);

    [LibraryImport(Library, EntryPoint = "WinDivertClose", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Close(nint handle);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperCalcChecksums", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CalcChecksums(byte* packet, uint packetLength, WinDivertAddress* address, ulong flags);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperCompileFilter", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CompileFilter(string filter, WinDivertLayer layer, byte* filterObject, uint filterObjectLength, byte** errorString, uint* errorPosition);
}
