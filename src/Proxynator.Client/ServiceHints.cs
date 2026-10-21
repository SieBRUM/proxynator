using Proxynator.Ipc;

namespace Proxynator.Client;

/// <summary>Explanations shown by the CLI and the GUI when something about the service is not right.</summary>
public static class ServiceHints
{
    /// <summary>Why the service at <paramref name="endpoint"/> may be unreachable and how to fix it (two lines).</summary>
    public static IReadOnlyList<string> Unreachable(string endpoint) =>
    [
        $"Cannot reach proxynatord at {IpcEndpoint.Describe(endpoint)}. Is it running?",
        OperatingSystem.IsWindows()
            ? "Start it from an elevated prompt (e.g. 'proxynatord --config config.json'). When it runs as a Windows service, run this program elevated too."
            : "Start it with 'sudo systemctl start proxynatord' (package install) or 'sudo proxynatord --config config.json'. As a service, clients need root or membership of the 'proxynator' group.",
    ];
}
