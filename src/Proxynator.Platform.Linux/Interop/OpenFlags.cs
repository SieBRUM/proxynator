using System.Runtime.InteropServices;

namespace Proxynator.Platform.Linux.Interop;

/// <summary>
/// <c>open(2)</c> flags whose values depend on the architecture. x86 and x86-64 use the historical values; arm64 (and
/// the other asm-generic architectures) differ, e.g. x86's <c>O_DIRECTORY</c> is arm64's <c>O_DIRECT</c>, which makes
/// opening a directory fail with EINVAL.
/// </summary>
internal static class OpenFlags
{
    public const int ReadOnly = 0;
    public const int CloseOnExec = 0x80000;

    /// <summary><c>O_DIRECTORY</c> for this process's architecture.</summary>
    public static int Directory => DirectoryFor(RuntimeInformation.ProcessArchitecture);

    /// <summary><c>O_DIRECTORY</c> on <paramref name="architecture"/>.</summary>
    public static int DirectoryFor(Architecture architecture) => architecture switch
    {
        Architecture.X86 or Architecture.X64 => 0x10000, // 0200000
        Architecture.Arm or Architecture.Arm64 => 0x4000, // 040000
        _ => throw new PlatformNotSupportedException($"O_DIRECTORY is not known for {architecture}."),
    };
}
