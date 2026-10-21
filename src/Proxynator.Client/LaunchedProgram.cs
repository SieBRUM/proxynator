using System.Diagnostics;
using System.Runtime.Versioning;
using Proxynator.Platform.Windows.Injection;

namespace Proxynator.Client;

/// <summary>A program started with Proxynator's hook by <see cref="ProgramLauncher"/>.</summary>
public abstract class LaunchedProgram : IDisposable
{
    private protected LaunchedProgram(int processId, string name)
    {
        ProcessId = processId;
        Name = name;
    }

    /// <summary>The process ID.</summary>
    public int ProcessId { get; }

    /// <summary>The program's file name, e.g. <c>curl.exe</c>.</summary>
    public string Name { get; }

    /// <summary>Waits until the process exits and returns its exit code.</summary>
    public abstract Task<int> WaitForExitAsync(CancellationToken cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Releases the process handle.</summary>
    protected abstract void Dispose(bool disposing);

    internal static LaunchedProgram From(Process process, string name) => new ManagedProcess(process, name);

    [SupportedOSPlatform("windows")]
    internal static LaunchedProgram From(HookedProcess process, string name) => new InjectedProcess(process, name);

    private sealed class ManagedProcess(Process process, string name) : LaunchedProgram(process.Id, name)
    {
        public override async Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return process.ExitCode;
        }

        protected override void Dispose(bool disposing) => process.Dispose();
    }

    [SupportedOSPlatform("windows")]
    private sealed class InjectedProcess(HookedProcess process, string name) : LaunchedProgram(process.ProcessId, name)
    {
        public override Task<int> WaitForExitAsync(CancellationToken cancellationToken) => process.WaitForExitAsync(cancellationToken);

        protected override void Dispose(bool disposing) => process.Dispose();
    }
}
