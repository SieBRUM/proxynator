namespace Proxynator.Ipc;

/// <summary>
/// Where the control API is served: a named pipe on Windows (<c>\\.\pipe\proxynator.v1</c>), a Unix domain socket
/// elsewhere (<c>/run/proxynator/proxynator.sock</c>). The value is a pipe name on Windows and a socket path otherwise.
/// </summary>
public static class IpcEndpoint
{
    /// <summary>The default pipe name on Windows.</summary>
    public const string DefaultPipeName = "proxynator.v1";

    /// <summary>The default socket path on Linux.</summary>
    public const string DefaultUnixSocketPath = "/run/proxynator/proxynator.sock";

    /// <summary>The environment variable that overrides the endpoint for the CLI and the service.</summary>
    public const string EnvironmentVariable = "PROXYNATOR_ENDPOINT";

    /// <summary>The platform default, overridable with <see cref="EnvironmentVariable"/>.</summary>
    public static string Default =>
        Environment.GetEnvironmentVariable(EnvironmentVariable) is { Length: > 0 } fromEnvironment
            ? fromEnvironment
            : OperatingSystem.IsWindows() ? DefaultPipeName : DefaultUnixSocketPath;

    /// <summary>A human-readable form, e.g. <c>\\.\pipe\proxynator.v1</c>.</summary>
    public static string Describe(string endpoint) => OperatingSystem.IsWindows() ? $@"\\.\pipe\{endpoint}" : endpoint;
}
