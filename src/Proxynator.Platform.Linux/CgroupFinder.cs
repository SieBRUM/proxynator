namespace Proxynator.Platform.Linux;

/// <summary>Finds the cgroup v2 hierarchy the eBPF programs attach to (its root covers every process).</summary>
internal static class CgroupFinder
{
    /// <summary>The cgroup2 mount point: <c>/sys/fs/cgroup</c> (unified) or <c>/sys/fs/cgroup/unified</c> (hybrid).</summary>
    public static string? FindCgroup2Mount(string mountInfo)
    {
        string? found = null;
        foreach (var line in mountInfo.Split('\n'))
        {
            // id parent major:minor root mountpoint options [optional...] - fstype source superoptions
            var separator = line.IndexOf(" - ", StringComparison.Ordinal);
            if (separator < 0)
            {
                continue;
            }

            var fields = line[..separator].Split(' ');
            var fsType = line[(separator + 3)..].Split(' ')[0];
            if (fsType != "cgroup2" || fields.Length < 5 || fields[3] != "/")
            {
                continue;
            }

            var mountPoint = fields[4].Replace("\\040", " ", StringComparison.Ordinal);
            if (mountPoint == "/sys/fs/cgroup")
            {
                return mountPoint;
            }

            found ??= mountPoint;
        }

        return found;
    }

    public static string? FindCgroup2Mount()
    {
        try
        {
            return FindCgroup2Mount(File.ReadAllText("/proc/self/mountinfo"));
        }
        catch (IOException)
        {
            return null;
        }
    }
}
