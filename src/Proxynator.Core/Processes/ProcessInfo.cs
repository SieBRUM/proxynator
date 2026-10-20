namespace Proxynator.Core.Processes;

/// <summary>A process that owns a connection.</summary>
/// <param name="ProcessId">The OS process ID.</param>
/// <param name="Name">The executable file name, e.g. <c>test.exe</c> or <c>curl</c>.</param>
/// <param name="ExecutablePath">The full executable path, when it could be determined.</param>
public sealed record ProcessInfo(int ProcessId, string Name, string? ExecutablePath)
{
    /// <summary>Parent, grandparent, ... of the process, nearest first. Used for child-process rules.</summary>
    public IReadOnlyList<ProcessInfo> Ancestors { get; init; } = [];
}
