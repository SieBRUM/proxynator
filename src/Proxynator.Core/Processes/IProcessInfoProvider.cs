namespace Proxynator.Core.Processes;

/// <summary>Looks up process details. Implemented per platform.</summary>
public interface IProcessInfoProvider
{
    /// <summary>Returns details for <paramref name="processId"/>, or <see langword="null"/> if it is unknown or gone.</summary>
    ProcessInfo? GetProcessInfo(int processId);
}
