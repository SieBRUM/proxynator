using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Proxynator.Core.Processes;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Processes;

/// <summary>
/// Resolves PIDs to process names, paths and ancestors. A <see cref="ProcessTree"/> is refreshed from a process
/// snapshot every two seconds (and whenever an unknown process shows up), so a child can still be matched by a
/// parent that has already exited, e.g. a console-script launcher. Results are cached per (PID, creation time).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class WindowsProcessInfoProvider : IProcessInfoProvider, IDisposable
{
    private const int MaxCacheSize = 4096;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    private readonly ProcessTree tree = new();
    private readonly ConcurrentDictionary<int, CachedProcess> cache = new();
    private readonly Lock refreshLock = new();
    private readonly Timer refreshTimer;

    /// <summary>Creates the provider and starts tracking processes.</summary>
    public WindowsProcessInfoProvider()
    {
        refreshTimer = new Timer(_ => Refresh(), null, TimeSpan.Zero, RefreshInterval);
    }

    /// <inheritdoc />
    public ProcessInfo? GetProcessInfo(int processId)
    {
        switch (processId)
        {
            case < 0:
                return null;
            case 0:
                return new ProcessInfo(0, "System Idle Process", null);
            case 4:
                return new ProcessInfo(4, "System", null);
        }

        var creationTime = GetCreationTime(processId);
        if (creationTime is null)
        {
            // Gone already: the most recent record is the best we have.
            return tree.FindRunning(processId) is { } gone ? ToInfo(gone) : null;
        }

        if (cache.TryGetValue(processId, out var cached) && cached.CreationTime == creationTime)
        {
            return cached.Info;
        }

        if (tree.Find(processId, creationTime.Value) is null)
        {
            Refresh();
        }

        var record = tree.Find(processId, creationTime.Value) ?? CreateRecord(processId, parentId: 0, creationTime.Value, fallbackName: null);
        var info = ToInfo(record);
        if (cache.Count >= MaxCacheSize)
        {
            cache.Clear();
        }

        cache[processId] = new CachedProcess(creationTime.Value, info);
        return info;
    }

    /// <inheritdoc />
    public void Dispose() => refreshTimer.Dispose();

    private ProcessInfo ToInfo(ProcessRecord record) =>
        new(record.ProcessId, record.Name, record.ExecutablePath) { Ancestors = tree.GetAncestors(record.ProcessId, record.CreationTime) };

    /// <summary>Takes a process snapshot and feeds it to the tree. Known processes are not queried again.</summary>
    private void Refresh()
    {
        lock (refreshLock)
        {
            using var snapshot = Kernel32.CreateToolhelp32Snapshot(Kernel32.Th32csSnapProcess, 0);
            if (snapshot.IsInvalid)
            {
                return;
            }

            var running = new List<ProcessRecord>();
            var entry = new Kernel32.ProcessEntry32 { Size = (uint)sizeof(Kernel32.ProcessEntry32) };
            if (!Kernel32.Process32First(snapshot, &entry))
            {
                return;
            }

            do
            {
                var pid = (int)entry.ProcessId;
                var parent = (int)entry.ParentProcessId;
                var exeName = entry.ExeFileName;
                var known = tree.FindRunning(pid);
                if (known is not null && known.ParentProcessId == parent && string.Equals(known.Name, exeName, StringComparison.OrdinalIgnoreCase))
                {
                    running.Add(known);
                }
                else if (GetCreationTime(pid) is { } creation)
                {
                    running.Add(CreateRecord(pid, parent, creation, exeName));
                }
            }
            while (Kernel32.Process32Next(snapshot, &entry));

            tree.Observe(running);
        }
    }

    private static ProcessRecord CreateRecord(int processId, int parentId, long creationTime, string? fallbackName)
    {
        var path = GetImagePath(processId);
        var name = path is not null ? Path.GetFileName(path) : fallbackName ?? $"pid {processId}";
        return new ProcessRecord(processId, parentId, creationTime, name, path);
    }

    private static long? GetCreationTime(int processId)
    {
        using var process = Kernel32.OpenProcess(Kernel32.ProcessQueryLimitedInformation, false, (uint)processId);
        if (process.IsInvalid || !Kernel32.GetProcessTimes(process, out var creation, out _, out _, out _))
        {
            return null;
        }

        return creation;
    }

    private static string? GetImagePath(int processId)
    {
        using var process = Kernel32.OpenProcess(Kernel32.ProcessQueryLimitedInformation, false, (uint)processId);
        if (process.IsInvalid)
        {
            return null;
        }

        var buffer = stackalloc char[1024];
        uint size = 1024;
        return Kernel32.QueryFullProcessImageName(process, 0, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }

    private sealed record CachedProcess(long CreationTime, ProcessInfo Info);
}
