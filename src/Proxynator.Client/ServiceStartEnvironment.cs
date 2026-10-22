namespace Proxynator.Client;

/// <summary>The facts a <see cref="ServiceStartPlan"/> depends on, so planning can be tested on any OS.</summary>
/// <param name="IsWindows">Windows (UAC) or Linux (pkexec).</param>
/// <param name="Directory">The directory of the client, where proxynatord is shipped.</param>
/// <param name="Endpoint">The control endpoint the client uses.</param>
/// <param name="ServiceInstalled">A Windows service or systemd unit named proxynatord exists.</param>
/// <param name="FileExists">File existence check.</param>
public sealed record ServiceStartEnvironment(bool IsWindows, string Directory, string Endpoint, bool ServiceInstalled, Func<string, bool> FileExists);
