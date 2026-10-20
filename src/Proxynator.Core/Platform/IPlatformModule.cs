using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Processes;

namespace Proxynator.Core.Platform;

/// <summary>Everything platform-specific the service needs. One implementation per operating system.</summary>
public interface IPlatformModule
{
    /// <summary>Display name, e.g. <c>Windows</c>.</summary>
    string Name { get; }

    /// <summary>The capture mode <see cref="CaptureMode.Auto"/> resolves to.</summary>
    CaptureMode DefaultCaptureMode { get; }

    /// <summary>Checks for the privileges the capture backends need.</summary>
    IPrivilegeChecker PrivilegeChecker { get; }

    /// <summary>Looks up processes that own connections.</summary>
    IProcessInfoProvider ProcessInfo { get; }

    /// <summary>Whether <paramref name="mode"/> is implemented on this platform.</summary>
    bool Supports(CaptureMode mode);

    /// <summary>Creates the capture backend for <paramref name="mode"/>.</summary>
    /// <exception cref="NotSupportedException">The mode is not available on this platform.</exception>
    ICaptureBackend CreateCaptureBackend(CaptureMode mode, ILoggerFactory loggerFactory);

    /// <summary>Platform-specific checks for <c>proxynator doctor</c>.</summary>
    IEnumerable<DiagnosticResult> RunDiagnostics();
}
