using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using Proxynator.Ipc;

namespace Proxynator.Client;

/// <summary>
/// Starts proxynatord from an unprivileged client (the GUI's "Start proxynatord" button). The service needs
/// Administrator / root, so the start is elevated: through the UAC prompt on Windows, through polkit (<c>pkexec</c>)
/// on Linux. An installed service (Windows service or systemd unit) is preferred over running the executable.
/// </summary>
public static class ServiceStarter
{
    /// <summary>The name of the Windows service and the systemd unit.</summary>
    public const string ServiceName = "proxynatord";

    /// <summary>The systemd unit files the <c>.deb</c> (or an administrator) installs.</summary>
    public static readonly IReadOnlyList<string> SystemdUnitPaths =
    [
        "/etc/systemd/system/proxynatord.service",
        "/lib/systemd/system/proxynatord.service",
        "/usr/lib/systemd/system/proxynatord.service",
    ];

    /// <summary>
    /// How to start the service, or null with <paramref name="problem"/> explaining why it cannot be started from here.
    /// The installed service is used only with the default endpoint: it always listens there.
    /// </summary>
    public static ServiceStartPlan? Plan(ServiceStartEnvironment environment, out string problem)
    {
        ArgumentNullException.ThrowIfNull(environment);
        problem = string.Empty;
        var useService = environment.ServiceInstalled && environment.Endpoint == (environment.IsWindows ? IpcEndpoint.DefaultPipeName : IpcEndpoint.DefaultUnixSocketPath);
        var executable = Path.Combine(environment.Directory, environment.IsWindows ? "proxynatord.exe" : "proxynatord");
        string[] endpointArguments = environment.Endpoint == (environment.IsWindows ? IpcEndpoint.DefaultPipeName : IpcEndpoint.DefaultUnixSocketPath)
            ? []
            : ["--endpoint", environment.Endpoint];

        if (environment.IsWindows)
        {
            if (useService)
            {
                return new ServiceStartPlan("sc.exe", ["start", ServiceName], $"sc.exe start {ServiceName} (as Administrator)");
            }

            if (!environment.FileExists(executable))
            {
                problem = $"{executable} was not found. Start proxynatord from an elevated prompt.";
                return null;
            }

            return new ServiceStartPlan(executable, endpointArguments, $"{executable}{string.Concat(endpointArguments.Select(a => " " + a))} (as Administrator)");
        }

        const string Pkexec = "/usr/bin/pkexec";
        if (!environment.FileExists(Pkexec))
        {
            problem = useService
                ? $"pkexec is not installed. Run: sudo systemctl start {ServiceName}"
                : $"pkexec is not installed. Run: sudo {executable}";
            return null;
        }

        if (useService)
        {
            return new ServiceStartPlan(Pkexec, ["systemctl", "start", ServiceName], $"pkexec systemctl start {ServiceName}");
        }

        if (!environment.FileExists(executable))
        {
            problem = $"{executable} was not found. Install the package, or run proxynatord as root.";
            return null;
        }

        return new ServiceStartPlan(Pkexec, [executable, .. endpointArguments], $"pkexec {executable}{string.Concat(endpointArguments.Select(a => " " + a))}");
    }

    /// <summary>The plan for this machine, or null with <paramref name="problem"/>.</summary>
    public static ServiceStartPlan? PlanForThisMachine(string endpoint, out string problem)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
        {
            problem = "Starting proxynatord is supported on Windows and Linux.";
            return null;
        }

        var installed = OperatingSystem.IsWindows() ? WindowsServiceInstalled() : SystemdUnitPaths.Any(File.Exists);
        return Plan(new ServiceStartEnvironment(OperatingSystem.IsWindows(), AppContext.BaseDirectory, endpoint, installed, File.Exists), out problem);
    }

    /// <summary>
    /// Runs <paramref name="plan"/> elevated. Returns null when it was started, otherwise why not (e.g. the UAC prompt
    /// was cancelled). The service may still take a few seconds to accept connections.
    /// </summary>
    public static string? Start(ServiceStartPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var start = new ProcessStartInfo(plan.FileName) { UseShellExecute = OperatingSystem.IsWindows() };
        foreach (var argument in plan.Arguments)
        {
            start.ArgumentList.Add(argument);
        }

        if (OperatingSystem.IsWindows())
        {
            start.Verb = "runas"; // the UAC prompt
            start.WorkingDirectory = AppContext.BaseDirectory;
        }

        try
        {
            using var process = Process.Start(start);
            return null;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "Cancelled: proxynatord needs Administrator rights.";
        }
        catch (Win32Exception ex)
        {
            return $"Cannot run {plan.Description}: {ex.Message}";
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool WindowsServiceInstalled()
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
        return key is not null;
    }
}
