using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>Named pipe and process wait functions.</summary>
[SupportedOSPlatform("windows")]
internal static partial class PipeNative
{
    public const int ErrorFileNotFound = 2;
    public const int ErrorSemTimeout = 121;
    public const uint Infinite = 0xFFFFFFFF;
    public const uint WaitObject0 = 0;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", EntryPoint = "WaitNamedPipeW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WaitNamedPipe(string name, uint timeoutMilliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsWow64Process(SafeProcessHandle process, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
}
