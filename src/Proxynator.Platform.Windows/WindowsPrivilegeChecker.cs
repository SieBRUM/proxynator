using System.Runtime.Versioning;
using System.Security.Principal;
using Proxynator.Core.Platform;

namespace Proxynator.Platform.Windows;

/// <summary>Requires an elevated Administrator token (needed to load the WinDivert driver).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPrivilegeChecker : IPrivilegeChecker
{
    /// <inheritdoc />
    public PrivilegeCheckResult Check()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator)
            ? new PrivilegeCheckResult(true, $"Running elevated as {identity.Name}.")
            : new PrivilegeCheckResult(false, "Administrator privileges are required. Run from an elevated prompt (Run as administrator) or install proxynatord as a Windows service.");
    }
}
