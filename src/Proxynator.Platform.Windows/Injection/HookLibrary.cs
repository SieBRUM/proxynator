using System.Runtime.Versioning;

namespace Proxynator.Platform.Windows.Injection;

/// <summary>
/// The injected hook DLLs (<c>native/windows/hook</c>), shipped next to the executables: one per target bitness.
/// </summary>
public static class HookLibrary
{
    /// <summary>The DLL injected into 64-bit processes; the CLI also calls its launch exports.</summary>
    public const string FileName64 = "proxynator-hook64.dll";

    /// <summary>The DLL injected into 32-bit (WOW64) processes.</summary>
    public const string FileName32 = "proxynator-hook32.dll";

    /// <summary>The directory the DLLs are expected in.</summary>
    public static string Directory => AppContext.BaseDirectory;

    /// <summary>The full path of the DLL for the given bitness.</summary>
    public static string PathFor(bool is64Bit) => Path.Combine(Directory, is64Bit ? FileName64 : FileName32);

    /// <summary>The hook DLLs that are missing from <see cref="Directory"/>.</summary>
    public static IReadOnlyList<string> Missing() =>
        [.. new[] { FileName64, FileName32 }.Where(file => !File.Exists(Path.Combine(Directory, file)))];

    /// <summary>The full path of a pipe name, e.g. <c>\\.\pipe\proxynator.v1.hook</c>.</summary>
    public static string PipePath(string pipeName) => $@"\\.\pipe\{pipeName}";

    /// <summary>Whether a pipe with this name exists (the service is serving hooks).</summary>
    [SupportedOSPlatform("windows")]
    public static bool PipeExists(string pipeName) =>
        Interop.PipeNative.WaitNamedPipe(PipePath(pipeName), 1) ||
        System.Runtime.InteropServices.Marshal.GetLastPInvokeError() == Interop.PipeNative.ErrorSemTimeout;
}
