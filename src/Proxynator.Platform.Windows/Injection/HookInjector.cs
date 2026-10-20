using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Injection;

/// <summary>
/// Starts processes with the hook DLL (<c>proxynator run</c>) or loads it into running ones (<c>proxynator attach</c>).
/// The work is done by exports of the 64-bit hook DLL (loading it does not hook the caller: hooks are only installed
/// in processes that carry the hook payload). 32-bit targets get the 32-bit DLL: on start through the Detours helper
/// process, on attach through a 32-bit <c>rundll32.exe</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class HookInjector
{
    private const int ErrorBadExeFormat = 193;
    private static readonly TimeSpan HelperTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Starts <paramref name="applicationPath"/> with the full <paramref name="commandLine"/> (argument 0 included),
    /// inheriting this process's console and standard handles, with the hook DLL loaded before any of its code runs.
    /// </summary>
    /// <exception cref="InjectionException">The process could not be started or injected.</exception>
    public static HookedProcess Start(string applicationPath, string commandLine, string? workingDirectory, string hookPipeName)
    {
        ArgumentException.ThrowIfNullOrEmpty(applicationPath);
        ArgumentNullException.ThrowIfNull(commandLine);
        ArgumentException.ThrowIfNullOrEmpty(hookPipeName);
        EnsureLibrary();

        // CreateProcessW may write to the command line buffer, so it must be a private copy.
        var buffer = new char[commandLine.Length + 1];
        commandLine.CopyTo(buffer);
        uint error;
        ProcessInformation information;
        unsafe
        {
            fixed (char* line = buffer)
            {
                error = HookExports.CreateProcess(applicationPath, line, workingDirectory, HookLibrary.PipePath(hookPipeName), out information);
            }
        }

        if (error != 0)
        {
            throw new InjectionException($"Cannot start {applicationPath} with the hook DLL: {new Win32Exception((int)error).Message} (error {error}).");
        }

        using (new SafeFileHandle(information.Thread, ownsHandle: true))
        {
            return new HookedProcess(new SafeProcessHandle(information.Process, ownsHandle: true), (int)information.ProcessId);
        }
    }

    /// <summary>Loads the hook DLL into the running process <paramref name="processId"/>.</summary>
    /// <exception cref="InjectionException">The process could not be opened or injected.</exception>
    public static void Attach(int processId, string hookPipeName)
    {
        ArgumentException.ThrowIfNullOrEmpty(hookPipeName);
        EnsureLibrary();
        var pipe = HookLibrary.PipePath(hookPipeName);
        var error = HookExports.Attach((uint)processId, pipe);
        if (error == ErrorBadExeFormat)
        {
            // A 32-bit process: only 32-bit code can find LoadLibraryW in it.
            error = AttachThroughHelper(processId, pipe);
        }

        if (error != 0)
        {
            throw new InjectionException($"Cannot load the hook DLL into process {processId}: {new Win32Exception((int)error).Message} (error {error}).");
        }
    }

    private static uint AttachThroughHelper(int processId, string pipe)
    {
        var rundll32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "rundll32.exe");
        var start = new ProcessStartInfo(rundll32)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            // rundll32 "<dll>",<export> <rest>: the export gets <rest> verbatim, here "<pid> <pipe path>".
            Arguments = string.Create(CultureInfo.InvariantCulture, $"\"{HookLibrary.PathFor(is64Bit: false)}\",ProxynatorAttachRundll {processId} {pipe}"),
        };
        using var helper = Process.Start(start) ?? throw new InjectionException($"Cannot start {rundll32}.");
        if (!helper.WaitForExit(HelperTimeout))
        {
            helper.Kill();
            throw new InjectionException($"{rundll32} did not finish attaching to process {processId}.");
        }

        return unchecked((uint)helper.ExitCode);
    }

    private static void EnsureLibrary()
    {
        var missing = HookLibrary.Missing();
        if (missing.Count > 0)
        {
            throw new InjectionException($"The hook DLLs are missing in {HookLibrary.Directory}: {string.Join(", ", missing)}.");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    private static unsafe partial class HookExports
    {
        [LibraryImport(HookLibrary.FileName64, EntryPoint = "ProxynatorCreateProcess", StringMarshalling = StringMarshalling.Utf16)]
        public static partial uint CreateProcess(string applicationName, char* commandLine, string? currentDirectory, string hookPipe, out ProcessInformation processInformation);

        [LibraryImport(HookLibrary.FileName64, EntryPoint = "ProxynatorAttach", StringMarshalling = StringMarshalling.Utf16)]
        public static partial uint Attach(uint processId, string hookPipe);
    }
}
