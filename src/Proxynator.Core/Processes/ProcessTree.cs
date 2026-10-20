namespace Proxynator.Core.Processes;

/// <summary>
/// Remembers processes, including exited ones for <c>retention</c>, so the ancestors of a process can be found even
/// after a launcher has exited (e.g. a console-script launcher that started <c>python.exe</c>). A parent is only
/// accepted if it was created before its child, which rules out reused PIDs. Thread-safe.
/// </summary>
public sealed class ProcessTree(TimeProvider? timeProvider = null, TimeSpan? retention = null)
{
    private const int MaxDepth = 16;

    private readonly Lock sync = new();
    private readonly Dictionary<int, List<Entry>> byPid = [];
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;
    private readonly TimeSpan retention = retention ?? TimeSpan.FromMinutes(10);

    /// <summary>The number of remembered processes (running and recently exited).</summary>
    public int Count
    {
        get
        {
            lock (sync)
            {
                return byPid.Values.Sum(list => list.Count);
            }
        }
    }

    /// <summary>
    /// Records a complete snapshot of running processes: new ones are added, ones missing from the snapshot are marked
    /// exited, and exited ones older than the retention period are forgotten.
    /// </summary>
    public void Observe(IEnumerable<ProcessRecord> running)
    {
        ArgumentNullException.ThrowIfNull(running);
        var now = time.GetUtcNow();
        lock (sync)
        {
            var seen = new HashSet<(int, long)>();
            foreach (var record in running)
            {
                seen.Add((record.ProcessId, record.CreationTime));
                AddOrRefresh(record, now);
            }

            foreach (var (pid, list) in byPid)
            {
                foreach (var entry in list)
                {
                    if (entry.ExitedAt is null && !seen.Contains((pid, entry.Record.CreationTime)))
                    {
                        entry.ExitedAt = now;
                    }
                }

                list.RemoveAll(e => e.ExitedAt is { } exited && now - exited > retention);
                if (list.Count == 0)
                {
                    byPid.Remove(pid);
                }
            }
        }
    }

    /// <summary>Records one running process without affecting the others.</summary>
    public void Add(ProcessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (sync)
        {
            AddOrRefresh(record, time.GetUtcNow());
        }
    }

    /// <summary>The running (not exited) process currently using <paramref name="processId"/>, if known.</summary>
    public ProcessRecord? FindRunning(int processId)
    {
        lock (sync)
        {
            return byPid.TryGetValue(processId, out var list) ? list.LastOrDefault(e => e.ExitedAt is null)?.Record : null;
        }
    }

    /// <summary>The process with this PID and creation time, if known.</summary>
    public ProcessRecord? Find(int processId, long creationTime)
    {
        lock (sync)
        {
            return FindCore(processId, creationTime);
        }
    }

    /// <summary>Parent, grandparent, ... of the given process, nearest first, as far as they are known.</summary>
    public IReadOnlyList<ProcessInfo> GetAncestors(int processId, long creationTime)
    {
        var ancestors = new List<ProcessInfo>();
        lock (sync)
        {
            var current = FindCore(processId, creationTime);
            while (current is not null && ancestors.Count < MaxDepth && current.ParentProcessId > 0 && current.ParentProcessId != current.ProcessId)
            {
                var parent = FindParent(current);
                if (parent is null)
                {
                    break;
                }

                ancestors.Add(parent.ToInfo());
                current = parent;
            }
        }

        return ancestors;
    }

    private ProcessRecord? FindCore(int processId, long creationTime) =>
        byPid.TryGetValue(processId, out var list) ? list.Find(e => e.Record.CreationTime == creationTime)?.Record : null;

    /// <summary>The newest process with the parent's PID that was created no later than the child.</summary>
    private ProcessRecord? FindParent(ProcessRecord child) =>
        byPid.TryGetValue(child.ParentProcessId, out var list)
            ? list.Where(e => e.Record.CreationTime <= child.CreationTime).MaxBy(e => e.Record.CreationTime)?.Record
            : null;

    private void AddOrRefresh(ProcessRecord record, DateTimeOffset now)
    {
        if (!byPid.TryGetValue(record.ProcessId, out var list))
        {
            byPid[record.ProcessId] = list = [];
        }

        var existing = list.Find(e => e.Record.CreationTime == record.CreationTime);
        if (existing is null)
        {
            // A new process with this PID means any older one is gone.
            foreach (var older in list.Where(e => e.ExitedAt is null))
            {
                older.ExitedAt = now;
            }

            list.Add(new Entry(record));
            list.Sort((a, b) => a.Record.CreationTime.CompareTo(b.Record.CreationTime));
        }
        else
        {
            // Same process; on Linux exec() keeps PID and start time but changes the program.
            existing.ExitedAt = null;
            existing.Record = record;
        }
    }

    private sealed class Entry(ProcessRecord record)
    {
        public ProcessRecord Record { get; set; } = record;

        public DateTimeOffset? ExitedAt { get; set; }
    }
}
