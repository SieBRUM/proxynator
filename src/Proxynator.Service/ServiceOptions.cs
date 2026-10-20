namespace Proxynator.Service;

/// <summary>Command-line options of <c>proxynatord</c>.</summary>
internal sealed record ServiceOptions
{
    /// <summary>The configuration file; created on the first <c>config load</c> if it does not exist.</summary>
    public required string ConfigPath { get; init; }

    /// <summary>The IPC endpoint (pipe name on Windows, socket path elsewhere).</summary>
    public required string Endpoint { get; init; }

    /// <summary>Run the relay and control API without capturing traffic (development and testing).</summary>
    public bool NoCapture { get; init; }

    /// <summary>Debug-level logging for Proxynator components.</summary>
    public bool Verbose { get; init; }
}
