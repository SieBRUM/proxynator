using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>Process-related kernel32 functions.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class Kernel32
{
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint Th32csSnapProcess = 0x2;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char* exeName, ref uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetProcessTimes(SafeProcessHandle process, out long creationTime, out long exitTime, out long kernelTime, out long userTime);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Process32First(SafeFileHandle snapshot, ProcessEntry32* entry);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Process32Next(SafeFileHandle snapshot, ProcessEntry32* entry);

    /// <summary><c>PROCESSENTRY32W</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nuint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        public ExeFileBuffer ExeFile;

        public readonly string ExeFileName
        {
            get
            {
                ReadOnlySpan<char> name = ExeFile;
                var end = name.IndexOf('\0');
                return new string(end < 0 ? name : name[..end]);
            }
        }
    }

    [InlineArray(260)]
    public struct ExeFileBuffer
    {
        private char element;
    }
}
