namespace Proxynator.Core.Processes;

/// <summary>One observed process.</summary>
/// <param name="ProcessId">The PID.</param>
/// <param name="ParentProcessId">The parent PID at creation (may have been reused since).</param>
/// <param name="CreationTime">Creation time in OS-specific units; with the PID it identifies the process.</param>
/// <param name="Name">Executable file name.</param>
/// <param name="ExecutablePath">Full path, when it could be read.</param>
public sealed record ProcessRecord(int ProcessId, int ParentProcessId, long CreationTime, string Name, string? ExecutablePath);
