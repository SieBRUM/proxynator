using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Platform.Linux.Capture;
using Proxynator.Platform.Linux.Interop;
using Proxynator.Platform.Linux.Processes;

namespace Proxynator.Platform.Linux;

/// <summary>The Linux platform module (Ubuntu, Kali and other systemd distributions, x64).</summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxPlatformModule : IPlatformModule, IDisposable
{
    private readonly LinuxProcessInfoProvider processInfo = new();
    private readonly LinuxPrivilegeChecker privilegeChecker = new();

    private static readonly string[] ResolvectlPaths = ["/usr/bin/resolvectl", "/bin/resolvectl"];

    /// <inheritdoc />
    public string Name => "Linux";

    /// <inheritdoc />
    public CaptureMode DefaultCaptureMode => CaptureMode.Ebpf;

    /// <inheritdoc />
    public IPrivilegeChecker PrivilegeChecker => privilegeChecker;

    /// <inheritdoc />
    public IProcessInfoProvider ProcessInfo => processInfo;

    /// <inheritdoc />
    public void Dispose() => processInfo.Dispose();

    /// <inheritdoc />
    public bool Supports(CaptureMode mode) => mode is CaptureMode.Ebpf or CaptureMode.Preload;

    /// <inheritdoc />
    public ICaptureBackend CreateCaptureBackend(CaptureMode mode, ILoggerFactory loggerFactory) => mode switch
    {
        CaptureMode.Ebpf => new BpfCaptureBackend(processInfo, loggerFactory),
        CaptureMode.Preload => new PreloadCaptureBackend(processInfo, loggerFactory.CreateLogger<PreloadCaptureBackend>()),
        CaptureMode.Nftables => throw new NotSupportedException("The nftables capture mode is not implemented; use \"ebpf\" (default) or \"preload\"."),
        _ => throw new NotSupportedException($"Capture mode '{mode}' is not available on Linux. Use \"ebpf\" or \"preload\"."),
    };

    /// <inheritdoc />
    public bool TryFlushSystemDnsCache(out string detail)
    {
        // systemd-resolved is the usual system cache (Ubuntu); without it, most programs don't cache at all.
        if (ResolvectlPaths.FirstOrDefault(File.Exists) is not { } resolvectl)
        {
            detail = "No systemd-resolved (resolvectl) on this machine, so there is no system DNS cache to clear.";
            return false;
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(resolvectl, ["flush-caches"])
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            }) ?? throw new InvalidOperationException("resolvectl did not start.");
            if (!process.WaitForExit(5000))
            {
                process.Kill();
                detail = "resolvectl flush-caches did not finish within 5 seconds.";
                return false;
            }

            var error = process.StandardError.ReadToEnd().Trim();
            detail = process.ExitCode == 0
                ? "Cleared the systemd-resolved cache."
                : $"resolvectl flush-caches failed (exit code {process.ExitCode}): {error}";
            return process.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            detail = $"Cannot run resolvectl: {ex.Message}";
            return false;
        }
    }

    /// <inheritdoc />
    public IEnumerable<DiagnosticResult> RunDiagnostics()
    {
        var privileges = privilegeChecker.Check();
        yield return new DiagnosticResult("Privileges", privileges.IsSufficient ? DiagnosticStatus.Ok : DiagnosticStatus.Error, privileges.Description);

        yield return CgroupFinder.FindCgroup2Mount() is { } cgroup
            ? new DiagnosticResult("cgroup v2", DiagnosticStatus.Ok, $"Mounted at {cgroup}.")
            : new DiagnosticResult("cgroup v2", DiagnosticStatus.Error, "No cgroup v2 hierarchy is mounted (needed by the ebpf mode).");

        yield return File.Exists("/sys/kernel/btf/vmlinux")
            ? new DiagnosticResult("Kernel BTF", DiagnosticStatus.Ok, "/sys/kernel/btf/vmlinux is present.")
            : new DiagnosticResult("Kernel BTF", DiagnosticStatus.Error, "The kernel has no BTF (needed by the ebpf mode); use the preload mode.");

        yield return LibBpf.TryLoad() is { } error
            ? new DiagnosticResult("libbpf", DiagnosticStatus.Error, $"libbpf is not installed (apt install libbpf1): {error}")
            : new DiagnosticResult("libbpf", DiagnosticStatus.Ok, "libbpf is installed.");

        foreach (var (file, mode) in new[] { (NativeFiles.BpfObject, "ebpf"), (NativeFiles.PreloadLibrary, "preload") })
        {
            var path = NativeFiles.PathOf(file);
            yield return File.Exists(path)
                ? new DiagnosticResult(file, DiagnosticStatus.Ok, $"Found in {NativeFiles.Directory}.")
                : new DiagnosticResult(file, DiagnosticStatus.Warning, $"Missing in {NativeFiles.Directory}; the {mode} mode needs it (build/build-native.sh).");
        }
    }
}
