using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.Versioning;
using Proxynator.Core.Processes;

namespace Proxynator.Platform.Linux.Processes;

/// <summary>
/// Resolves PIDs from <c>/proc</c>. A <see cref="ProcessTree"/> is refreshed every two seconds (and for unknown
/// processes), so children can be matched by parents that have already exited. A cached entry is reused while the
/// process's start time and command name are unchanged (exec keeps the PID but changes the name).
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxProcessInfoProvider : IProcessInfoProvider, IDisposable
{
    private const int MaxCacheSize = 8192;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    private readonly string procRoot;
    private readonly ProcessTree tree = new();
    private readonly ConcurrentDictionary<int, CachedProcess> cache = new();
    private readonly Lock refreshLock = new();
    private readonly Timer refreshTimer;

    /// <summary>Creates the provider and starts tracking processes.</summary>
    public LinuxProcessInfoProvider()
        : this("/proc")
    {
    }

    internal LinuxProcessInfoProvider(string procRoot)
    {
        this.procRoot = procRoot;
        refreshTimer = new Timer(_ => Refresh(), null, TimeSpan.Zero, RefreshInterval);
    }

    /// <inheritdoc />
    public ProcessInfo? GetProcessInfo(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        var stat = ReadStat(processId);
        if (stat is null)
        {
            return tree.FindRunning(processId) is { } gone ? ToInfo(gone) : null;
        }

        if (cache.TryGetValue(processId, out var cached) && cached.StartTime == stat.StartTime && cached.Command == stat.Command)
        {
            return cached.Info;
        }

        if (tree.Find(processId, stat.StartTime) is null)
        {
            Refresh();
        }

        var record = CreateRecord(stat);
        tree.Add(record);
        var info = ToInfo(record);
        if (cache.Count >= MaxCacheSize)
        {
            cache.Clear();
        }

        cache[processId] = new CachedProcess(stat.StartTime, stat.Command, info);
        return info;
    }

    /// <summary>The PIDs of all running processes.</summary>
    public IEnumerable<int> RunningProcessIds()
    {
        foreach (var directory in Directory.EnumerateDirectories(procRoot))
        {
            if (int.TryParse(Path.GetFileName(directory), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
            {
                yield return pid;
            }
        }
    }

    /// <inheritdoc />
    public void Dispose() => refreshTimer.Dispose();

    private ProcessInfo ToInfo(ProcessRecord record) =>
        record.ToInfo() with { Ancestors = tree.GetAncestors(record.ProcessId, record.CreationTime) };

    private void Refresh()
    {
        lock (refreshLock)
        {
            var running = new List<ProcessRecord>();
            foreach (var pid in RunningProcessIds())
            {
                var stat = ReadStat(pid);
                if (stat is null)
                {
                    continue;
                }

                var known = tree.Find(pid, stat.StartTime);
                running.Add(known is not null && cache.TryGetValue(pid, out var cached) && cached.Command == stat.Command ? known : CreateRecord(stat));
            }

            tree.Observe(running);
        }
    }

    private ProcStat? ReadStat(int processId)
    {
        try
        {
            return ProcStat.Parse(File.ReadAllText(Path.Combine(procRoot, processId.ToString(CultureInfo.InvariantCulture), "stat")));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private ProcessRecord CreateRecord(ProcStat stat)
    {
        var directory = Path.Combine(procRoot, stat.ProcessId.ToString(CultureInfo.InvariantCulture));
        string? executable = null;
        IReadOnlyList<string> arguments = [];
        try
        {
            executable = File.ResolveLinkTarget(Path.Combine(directory, "exe"), returnFinalTarget: false)?.FullName;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Kernel threads and other users' processes without privileges.
        }

        try
        {
            arguments = File.ReadAllText(Path.Combine(directory, "cmdline")).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Exited meanwhile.
        }

        var identity = ProcessIdentity.Resolve(stat.Command, executable, arguments, File.Exists);
        return new ProcessRecord(stat.ProcessId, stat.ParentProcessId, stat.StartTime, identity.Name, identity.ExecutablePath, identity.ScriptPath);
    }

    private sealed record CachedProcess(long StartTime, string Command, ProcessInfo Info);
}
