using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Platform.Windows.Capture;
using Proxynator.Platform.Windows.Interop;
using Proxynator.Platform.Windows.Processes;

namespace Proxynator.Platform.Windows;

/// <summary>The Windows platform module.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPlatformModule : IPlatformModule
{
    private readonly WindowsProcessInfoProvider processInfo = new();
    private readonly WindowsPrivilegeChecker privilegeChecker = new();

    /// <inheritdoc />
    public string Name => "Windows";

    /// <inheritdoc />
    public CaptureMode DefaultCaptureMode => CaptureMode.WinDivert;

    /// <inheritdoc />
    public IPrivilegeChecker PrivilegeChecker => privilegeChecker;

    /// <inheritdoc />
    public IProcessInfoProvider ProcessInfo => processInfo;

    /// <inheritdoc />
    public bool Supports(CaptureMode mode) => mode is CaptureMode.WinDivert;

    /// <inheritdoc />
    public ICaptureBackend CreateCaptureBackend(CaptureMode mode, ILoggerFactory loggerFactory) => mode switch
    {
        CaptureMode.WinDivert => new WinDivertCaptureBackend(processInfo, loggerFactory.CreateLogger<WinDivertCaptureBackend>()),
        CaptureMode.Injection => throw new NotSupportedException("The injection capture mode is not implemented yet (roadmap phase 4). Use \"windivert\"."),
        _ => throw new NotSupportedException($"Capture mode '{mode}' is not available on Windows. Use \"windivert\"."),
    };

    /// <inheritdoc />
    public IEnumerable<DiagnosticResult> RunDiagnostics()
    {
        var privileges = privilegeChecker.Check();
        yield return new DiagnosticResult("Administrator", privileges.IsSufficient ? DiagnosticStatus.Ok : DiagnosticStatus.Error, privileges.Description);

        yield return Environment.Is64BitOperatingSystem && Environment.Is64BitProcess
            ? new DiagnosticResult("Architecture", DiagnosticStatus.Ok, "64-bit OS and process.")
            : new DiagnosticResult("Architecture", DiagnosticStatus.Error, "Proxynator needs a 64-bit Windows and a 64-bit process.");

        var directory = AppContext.BaseDirectory;
        var missing = new[] { WinDivertNative.Library, "WinDivert64.sys" }.Where(file => !File.Exists(Path.Combine(directory, file))).ToList();
        yield return missing.Count == 0
            ? new DiagnosticResult("WinDivert files", DiagnosticStatus.Ok, $"WinDivert.dll and WinDivert64.sys found in {directory}.")
            : new DiagnosticResult("WinDivert files", DiagnosticStatus.Error, $"Missing in {directory}: {string.Join(", ", missing)}. Build on Windows (or with -p:IncludeWinDivert=true) so they are downloaded.");
    }
}
