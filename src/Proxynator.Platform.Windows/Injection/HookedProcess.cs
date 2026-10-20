using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Injection;

/// <summary>A process started with the hook DLL.</summary>
[SupportedOSPlatform("windows")]
public sealed class HookedProcess : IDisposable
{
    private readonly SafeProcessHandle handle;

    internal HookedProcess(SafeProcessHandle handle, int processId)
    {
        this.handle = handle;
        ProcessId = processId;
    }

    /// <summary>The process ID.</summary>
    public int ProcessId { get; }

    /// <summary>Waits until the process exits and returns its exit code.</summary>
    public Task<int> WaitForExitAsync(CancellationToken cancellationToken) => Task.Run(
        () =>
        {
            while (PipeNative.WaitForSingleObject(handle, 200) != PipeNative.WaitObject0)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            return PipeNative.GetExitCodeProcess(handle, out var exitCode) ? unchecked((int)exitCode) : -1;
        },
        cancellationToken);

    /// <inheritdoc />
    public void Dispose() => handle.Dispose();
}
