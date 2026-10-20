using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Proxynator.Core.Processes;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Processes;

/// <summary>
/// Resolves PIDs to process names, paths and ancestors. Results are cached per (PID, creation time), so a reused
/// PID is never confused with the process that had it before.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class WindowsProcessInfoProvider : IProcessInfoProvider
{
    private const int MaxAncestors = 16;
    private const int MaxCacheSize = 4096;

    private readonly ConcurrentDictionary<int, CachedProcess> cache = new();

    /// <inheritdoc />
    public ProcessInfo? GetProcessInfo(int processId)
    {
        if (processId <= 0)
        {
            return processId == 0 ? new ProcessInfo(0, "System Idle Process", null) : null;
        }

        var creationTime = GetCreationTime(processId);
        if (creationTime is null)
        {
            return processId == 4 ? new ProcessInfo(4, "System", null) : null;
        }

        if (cache.TryGetValue(processId, out var cached) && cached.CreationTime == creationTime)
        {
            return cached.Info;
        }

        if (cache.Count >= MaxCacheSize)
        {
            cache.Clear();
        }

        var info = Build(processId, creationTime.Value);
        cache[processId] = new CachedProcess(creationTime.Value, info);
        return info;
    }

    private static ProcessInfo Build(int processId, long creationTime)
    {
        var parents = SnapshotProcesses();
        var path = GetImagePath(processId);
        var name = path is not null ? Path.GetFileName(path) : parents.GetValueOrDefault(processId).Name ?? $"pid {processId}";

        var ancestors = new List<ProcessInfo>();
        var childCreationTime = creationTime;
        var current = processId;
        while (ancestors.Count < MaxAncestors && parents.TryGetValue(current, out var entry) && entry.ParentId > 4 && entry.ParentId != current)
        {
            // A parent must be older than its child; otherwise the parent PID has been reused by an unrelated process.
            var parentCreation = GetCreationTime(entry.ParentId);
            if (parentCreation is null || parentCreation > childCreationTime)
            {
                break;
            }

            var parentPath = GetImagePath(entry.ParentId);
            var parentName = parentPath is not null ? Path.GetFileName(parentPath) : parents.GetValueOrDefault(entry.ParentId).Name ?? $"pid {entry.ParentId}";
            ancestors.Add(new ProcessInfo(entry.ParentId, parentName, parentPath));
            childCreationTime = parentCreation.Value;
            current = entry.ParentId;
        }

        return new ProcessInfo(processId, name, path) { Ancestors = ancestors };
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

    private static Dictionary<int, (int ParentId, string? Name)> SnapshotProcesses()
    {
        var result = new Dictionary<int, (int, string?)>();
        using var snapshot = Kernel32.CreateToolhelp32Snapshot(Kernel32.Th32csSnapProcess, 0);
        if (snapshot.IsInvalid)
        {
            return result;
        }

        var entry = new Kernel32.ProcessEntry32 { Size = (uint)sizeof(Kernel32.ProcessEntry32) };
        if (!Kernel32.Process32First(snapshot, &entry))
        {
            return result;
        }

        do
        {
            result[(int)entry.ProcessId] = ((int)entry.ParentProcessId, entry.ExeFileName);
        }
        while (Kernel32.Process32Next(snapshot, &entry));

        return result;
    }

    private sealed record CachedProcess(long CreationTime, ProcessInfo Info);
}
