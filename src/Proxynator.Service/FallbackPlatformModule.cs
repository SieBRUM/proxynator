using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;

namespace Proxynator.Service;

/// <summary>
/// Used on platforms without a capture implementation yet (Linux until roadmap phase 5). The service still runs with
/// <c>--no-capture</c>, which keeps the control API and relay usable for development.
/// </summary>
internal sealed class FallbackPlatformModule : IPlatformModule, IPrivilegeChecker, IProcessInfoProvider
{
    public string Name => RuntimeInformation.OSDescription;

    public CaptureMode DefaultCaptureMode => OperatingSystem.IsLinux() ? CaptureMode.Ebpf : CaptureMode.Auto;

    public IPrivilegeChecker PrivilegeChecker => this;

    public IProcessInfoProvider ProcessInfo => this;

    public bool Supports(CaptureMode mode) => false;

    public ICaptureBackend CreateCaptureBackend(CaptureMode mode, ILoggerFactory loggerFactory) =>
        throw new NotSupportedException($"Traffic capture is not implemented on {Name} yet (Linux support is roadmap phase 5). Start proxynatord with --no-capture to run without capture.");

    public PrivilegeCheckResult Check() => Environment.IsPrivilegedProcess
        ? new PrivilegeCheckResult(true, "Running as root.")
        : new PrivilegeCheckResult(false, "Root privileges are required for traffic capture. Run with sudo.");

    public ProcessInfo? GetProcessInfo(int processId) => null;

    public IEnumerable<DiagnosticResult> RunDiagnostics()
    {
        var privileges = Check();
        yield return new DiagnosticResult("Privileges", privileges.IsSufficient ? DiagnosticStatus.Ok : DiagnosticStatus.Warning, privileges.Description);
        yield return new DiagnosticResult("Capture support", DiagnosticStatus.Warning, $"Traffic capture is not implemented on {Name} yet (roadmap phase 5).");
    }
}
