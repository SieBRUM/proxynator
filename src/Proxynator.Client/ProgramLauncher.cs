using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using Proxynator.Ipc;
using Proxynator.Platform.Linux;
using Proxynator.Platform.Linux.Preload;
using Proxynator.Platform.Windows.Injection;

namespace Proxynator.Client;

/// <summary>
/// Starts programs with Proxynator's hook, or loads it into running ones: the user-mode capture modes (Windows
/// <c>injection</c>, Linux <c>preload</c>). Shared by <c>proxynator run|attach</c> and the GUI.
/// </summary>
/// <param name="endpoint">The service's control endpoint; hooks register at <see cref="IpcEndpoint.HookEndpoint"/>.</param>
public sealed class ProgramLauncher(string endpoint)
{
    /// <summary>Whether programs can be started with the hook on this OS.</summary>
    public static bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

    /// <summary>Whether the hook can be loaded into running processes on this OS (Windows only).</summary>
    public static bool CanAttach => OperatingSystem.IsWindows();

    /// <summary>The capture mode the service must run in for this class to work, e.g. <c>injection</c>.</summary>
    public static string RequiredCaptureMode => OperatingSystem.IsWindows() ? "injection" : "preload";

    /// <summary>
    /// Why programs cannot be started with the hook right now (service not accepting hooked processes, native parts
    /// missing), or null when they can.
    /// </summary>
    public string? CheckReady()
    {
        try
        {
            EnsureReady();
            return null;
        }
        catch (LaunchException ex)
        {
            return ex.Message;
        }
    }

    /// <summary>
    /// Starts <paramref name="program"/> (a path, or a command on the PATH) and everything it starts with the hook.
    /// Console programs inherit this process's console, or get a new one when there is none (GUI).
    /// </summary>
    /// <exception cref="LaunchException">The program could not be started with the hook.</exception>
    public LaunchedProgram Start(string program, IReadOnlyList<string> arguments, string? workingDirectory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        ArgumentNullException.ThrowIfNull(arguments);
        EnsureReady();
        if (OperatingSystem.IsWindows())
        {
            return StartOnWindows(program, arguments, workingDirectory);
        }

        return OperatingSystem.IsLinux() ? StartOnLinux(program, arguments, workingDirectory) : throw new PlatformNotSupportedException();
    }

    /// <summary>
    /// Opens a terminal whose shell, and everything started from it, carries the hook: PowerShell in a new console on
    /// Windows, the desktop's terminal emulator running the user's shell on Linux.
    /// </summary>
    /// <exception cref="LaunchException">No terminal could be started with the hook.</exception>
    public LaunchedProgram OpenTerminal()
    {
        EnsureReady();
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsWindows())
        {
            var shell = ExecutableResolver.Resolve("pwsh.exe", home, Environment.GetEnvironmentVariable("PATH"), null)
                ?? Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            return StartOnWindows(shell, ["-NoLogo"], home);
        }

        return OperatingSystem.IsLinux() ? OpenTerminalOnLinux(home) : throw new PlatformNotSupportedException();
    }

    /// <summary>Loads the hook into the running process <paramref name="processId"/> (Windows only).</summary>
    /// <exception cref="LaunchException">The hook could not be loaded.</exception>
    public void Attach(int processId)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new LaunchException(
                "Attaching is only available on Windows: a library cannot be preloaded into a running Linux process." + Environment.NewLine +
                "On Linux, start the program with Proxynator, or use the ebpf capture mode, which catches running processes too.");
        }

        EnsureReady();
        try
        {
            HookInjector.Attach(processId, IpcEndpoint.HookEndpoint(endpoint));
        }
        catch (InjectionException ex)
        {
            throw new LaunchException(ex.Message, ex);
        }
    }

    private void EnsureReady()
    {
        if (OperatingSystem.IsWindows())
        {
            EnsureReadyOnWindows();
        }
        else if (OperatingSystem.IsLinux())
        {
            EnsureReadyOnLinux();
        }
        else
        {
            throw new LaunchException("Starting programs with the hook is available on Windows and Linux.");
        }
    }

    [SupportedOSPlatform("windows")]
    private void EnsureReadyOnWindows()
    {
        var hookPipe = IpcEndpoint.HookEndpoint(endpoint);
        if (!HookLibrary.PipeExists(hookPipe))
        {
            throw new LaunchException(
                $"proxynatord is not accepting hooked processes at {HookLibrary.PipePath(hookPipe)}." + Environment.NewLine +
                "Set \"settings.capture.mode\" to \"injection\" in the configuration and (re)start proxynatord. Check with 'proxynator status'.",
                serviceUnavailable: true);
        }

        if (HookLibrary.Missing() is { Count: > 0 } missing)
        {
            throw new LaunchException($"{string.Join(" and ", missing)} missing from {HookLibrary.Directory}; build them with build/build-native.ps1.");
        }
    }

    [SupportedOSPlatform("linux")]
    private void EnsureReadyOnLinux()
    {
        var hookSocket = IpcEndpoint.HookEndpoint(endpoint);
        if (!PreloadLauncher.IsServing(hookSocket))
        {
            throw new LaunchException(
                $"proxynatord is not accepting hooked processes at {hookSocket}." + Environment.NewLine +
                "Set \"settings.capture.mode\" to \"preload\" in the configuration and (re)start proxynatord. Check with 'proxynator status'.",
                serviceUnavailable: true);
        }

        if (!File.Exists(NativeFiles.PathOf(NativeFiles.PreloadLibrary)))
        {
            throw new LaunchException($"{NativeFiles.PathOf(NativeFiles.PreloadLibrary)} is missing; build it with build/build-native.sh.");
        }
    }

    [SupportedOSPlatform("windows")]
    private LaunchedProgram StartOnWindows(string command, IReadOnlyList<string> arguments, string? workingDirectory)
    {
        var program = ExecutableResolver.Resolve(
            command,
            workingDirectory ?? Environment.CurrentDirectory,
            Environment.GetEnvironmentVariable("PATH"),
            Environment.GetEnvironmentVariable("PATHEXT"));
        if (program is null)
        {
            throw new LaunchException($"'{command}' was not found in the {(workingDirectory is null ? "current" : "working")} directory or on the PATH.");
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

        try
        {
            return LaunchedProgram.From(HookInjector.Start(application, commandLine, workingDirectory, IpcEndpoint.HookEndpoint(endpoint)), Path.GetFileName(program));
        }
        catch (InjectionException ex)
        {
            throw new LaunchException(ex.Message, ex);
        }
    }

    [SupportedOSPlatform("linux")]
    private LaunchedProgram StartOnLinux(string command, IReadOnlyList<string> arguments, string? workingDirectory)
    {
        var start = PreloadLauncher.CreateStartInfo(command, arguments, IpcEndpoint.HookEndpoint(endpoint), Environment.GetEnvironmentVariable("LD_PRELOAD"));
        if (workingDirectory is not null)
        {
            start.WorkingDirectory = workingDirectory;
        }

        return StartProcess(start, command);
    }

    [SupportedOSPlatform("linux")]
    private LaunchedProgram OpenTerminalOnLinux(string home)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        var terminal = LinuxTerminals.Find(path, File.Exists)
            ?? throw new LaunchException($"No terminal emulator found on the PATH (tried {string.Join(", ", LinuxTerminals.Known.Select(t => t.Program))}).");

        // The terminal itself runs without the library (some terminals hand the command to a server process, which
        // would not inherit it anyway); env sets it for the shell, and so for everything started from the shell.
        var shell = Environment.GetEnvironmentVariable("SHELL") is { Length: > 0 } userShell ? userShell : "/bin/sh";
        var start = new ProcessStartInfo(terminal.Path) { UseShellExecute = false, WorkingDirectory = home };
        foreach (var argument in terminal.Arguments(BuildShellCommand(shell)))
        {
            start.ArgumentList.Add(argument);
        }

        return StartProcess(start, Path.GetFileName(terminal.Path));
    }

    [SupportedOSPlatform("linux")]
    private string[] BuildShellCommand(string shell)
    {
        var library = NativeFiles.PathOf(NativeFiles.PreloadLibrary);
        var existing = Environment.GetEnvironmentVariable("LD_PRELOAD");
        var preload = string.IsNullOrEmpty(existing) ? library : $"{library}:{existing}";
        return ["env", $"LD_PRELOAD={preload}", $"{PreloadLauncher.EndpointVariable}={IpcEndpoint.HookEndpoint(endpoint)}", shell];
    }

    private static LaunchedProgram StartProcess(ProcessStartInfo start, string name)
    {
        try
        {
            return LaunchedProgram.From(Process.Start(start)!, name);
        }
        catch (Win32Exception ex)
        {
            throw new LaunchException($"Cannot start '{name}': {ex.Message}", ex);
        }
    }
}
