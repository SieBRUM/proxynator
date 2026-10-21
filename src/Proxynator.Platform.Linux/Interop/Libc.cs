using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Linux.Interop;

/// <summary>libc functions not exposed by .NET.</summary>
[SupportedOSPlatform("linux")]
internal static partial class Libc
{
    public const int RlimitMemlock = 8;
    public const int SolSocket = 1;
    public const int SoPeerCred = 17;

    [LibraryImport("libc", SetLastError = true)]
    public static partial int setrlimit(int resource, in RLimit limit);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int chown(string path, int owner, int group);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int open(string path, int flags);

    [LibraryImport("libc", SetLastError = true)]
    public static partial int close(int fd);

    [StructLayout(LayoutKind.Sequential)]
    public struct RLimit
    {
        public ulong Current;
        public ulong Maximum;
    }

    /// <summary><c>struct ucred</c> (SO_PEERCRED).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct UCred
    {
        public int ProcessId;
        public uint UserId;
        public uint GroupId;
    }
}
