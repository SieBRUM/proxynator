using System.Diagnostics;
using System.Runtime.Versioning;
using Proxynator.Ipc;
using Proxynator.Platform.Linux;
using Proxynator.Platform.Linux.Preload;
using Proxynator.Platform.Windows.Injection;

namespace Proxynator.Cli;

/// <summary>
/// <c>proxynator run</c> and <c>proxynator attach</c>: user-mode capture of chosen processes (Windows injection mode,
/// Linux preload mode).
/// </summary>
internal sealed class InjectionCommands(string endpoint, TextWriter output, TextWriter error)
{
    /// <summary>Starts <paramref name="command"/> with the hook DLL and, unless <paramref name="detach"/>, waits for it and returns its exit code.</summary>
    public async Task<int> RunAsync(string command, IReadOnlyList<string> arguments, bool detach)
    {
        if (OperatingSystem.IsWindows())
        {
            return await RunOnWindowsAsync(command, arguments, detach).ConfigureAwait(false);
        }

        if (OperatingSystem.IsLinux())
        {
            return await RunOnLinuxAsync(command, arguments, detach).ConfigureAwait(false);
        }

        error.WriteLine("'proxynator run' is available on Windows and Linux.");
        return ExitCodes.Failure;
    }

    /// <summary>Loads the hook DLL into the running process <paramref name="processId"/>.</summary>
    public int Attach(int processId)
    {
        if (!OperatingSystem.IsWindows())
        {
            error.WriteLine("'proxynator attach' is only available on Windows: a library cannot be preloaded into a running Linux process.");
            error.WriteLine("On Linux, start the program with 'proxynator run', or use the ebpf capture mode, which catches running processes too.");
            return ExitCodes.Failure;
        }

        return AttachOnWindows(processId);
    }

    [SupportedOSPlatform("windows")]
    private async Task<int> RunOnWindowsAsync(string command, IReadOnlyList<string> arguments, bool detach)
    {
        var hookPipe = IpcEndpoint.HookEndpoint(endpoint);
        if (!CheckHookEndpoint(hookPipe))
        {
            return ExitCodes.ServiceUnreachable;
        }

        var program = ExecutableResolver.Resolve(
            command, Environment.CurrentDirectory, Environment.GetEnvironmentVariable("PATH"), Environment.GetEnvironmentVariable("PATHEXT"));
        if (program is null)
        {
            error.WriteLine($"'{command}' was not found in the current directory or on the PATH.");
            return ExitCodes.Failure;
        }

        string application;
        string commandLine;
        if (ExecutableResolver.IsBatchFile(program))
        {
            // Batch files run in cmd.exe, which is hooked too and passes the hook on to everything the script starts.
            application = Environment.GetEnvironmentVariable("ComSpec") is { Length: > 0 } comSpec
                ? comSpec
                : Path.Combine(Environment.SystemDirectory, "cmd.exe");
            commandLine = $"\"{application}\" /d /s /c \"{WindowsCommandLine.Join([program, .. arguments])}\"";
        }
        else
        {
            application = program;
            commandLine = WindowsCommandLine.Join([program, .. arguments]);
        }

        HookedProcess process;
        try
        {
            process = HookInjector.Start(application, commandLine, workingDirectory: null, hookPipe);
        }
        catch (InjectionException ex)
        {
            error.WriteLine(ex.Message);
            return ExitCodes.Failure;
        }

        using (process)
        {
            error.WriteLine($"proxynator: started {Path.GetFileName(program)} (pid {process.ProcessId}); its connections follow the proxynatord rules.");
            if (detach)
            {
                return ExitCodes.Success;
            }

            // Ctrl+C reaches the child through the shared console; keep waiting so its exit code is returned.
            ConsoleCancelEventHandler ignore = (_, e) => e.Cancel = true;
            Console.CancelKeyPress += ignore;
            try
            {
                return await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                Console.CancelKeyPress -= ignore;
            }
        }
    }

    [SupportedOSPlatform("linux")]
    private async Task<int> RunOnLinuxAsync(string command, IReadOnlyList<string> arguments, bool detach)
    {
        var hookSocket = IpcEndpoint.HookEndpoint(endpoint);
        if (!PreloadLauncher.IsServing(hookSocket))
        {
            error.WriteLine($"proxynatord is not accepting hooked processes at {hookSocket}.");
            error.WriteLine("Set \"settings.capture.mode\" to \"preload\" in the configuration and (re)start proxynatord. Check with 'proxynator status'.");
            return ExitCodes.ServiceUnreachable;
        }

        if (!File.Exists(NativeFiles.PathOf(NativeFiles.PreloadLibrary)))
        {
            error.WriteLine($"{NativeFiles.PathOf(NativeFiles.PreloadLibrary)} is missing; build it with build/build-native.sh.");
            return ExitCodes.Failure;
        }

        Process process;
        try
        {
            process = Process.Start(PreloadLauncher.CreateStartInfo(command, arguments, hookSocket, Environment.GetEnvironmentVariable("LD_PRELOAD")))!;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            error.WriteLine($"Cannot start '{command}': {ex.Message}");
            return ExitCodes.Failure;
        }

        using (process)
        {
            error.WriteLine($"proxynator: started {command} (pid {process.Id}); its connections follow the proxynatord rules.");
            if (detach)
            {
                return ExitCodes.Success;
            }

            // Ctrl+C reaches the child through the terminal's process group; keep waiting for its exit code.
            ConsoleCancelEventHandler ignore = (_, e) => e.Cancel = true;
            Console.CancelKeyPress += ignore;
            try
            {
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                return process.ExitCode;
            }
            finally
            {
                Console.CancelKeyPress -= ignore;
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private int AttachOnWindows(int processId)
    {
        var hookPipe = IpcEndpoint.HookEndpoint(endpoint);
        if (!CheckHookEndpoint(hookPipe))
        {
            return ExitCodes.ServiceUnreachable;
        }

        try
        {
            HookInjector.Attach(processId, hookPipe);
        }
        catch (InjectionException ex)
        {
            error.WriteLine(ex.Message);
            return ExitCodes.Failure;
        }

        output.WriteLine($"Hook loaded into process {processId}. Its new connections, and those of processes it starts, follow the proxynatord rules; open connections are not affected.");
        return ExitCodes.Success;
    }

    [SupportedOSPlatform("windows")]
    private bool CheckHookEndpoint(string hookPipe)
    {
        if (HookLibrary.PipeExists(hookPipe))
        {
            return true;
        }

        error.WriteLine($"proxynatord is not accepting hooked processes at {HookLibrary.PipePath(hookPipe)}.");
        error.WriteLine("Set \"settings.capture.mode\" to \"injection\" in the configuration and (re)start proxynatord. Check with 'proxynator status'.");
        return false;
    }
}
