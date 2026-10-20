using System.Globalization;

namespace Proxynator.Platform.Linux.Processes;

/// <summary>The fields of <c>/proc/&lt;pid&gt;/stat</c> Proxynator needs.</summary>
/// <param name="ProcessId">The PID.</param>
/// <param name="Command">The command name (<c>comm</c>, at most 15 characters).</param>
/// <param name="ParentProcessId">The parent PID.</param>
/// <param name="StartTime">Start time in clock ticks since boot; with the PID it identifies the process.</param>
internal sealed record ProcStat(int ProcessId, string Command, int ParentProcessId, long StartTime)
{
    /// <summary>Parses the content of a stat file. <c>comm</c> may contain spaces and parentheses.</summary>
    public static ProcStat? Parse(string stat)
    {
        var open = stat.IndexOf('(', StringComparison.Ordinal);
        var close = stat.LastIndexOf(')');
        if (open < 0 || close < open || !int.TryParse(stat.AsSpan(0, open).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var pid))
        {
            return null;
        }

        // After ")": state(3) ppid(4) ... starttime(22); field 3 is index 0 here.
        var fields = stat[(close + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 20 ||
            !int.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var parent) ||
            !long.TryParse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture, out var start))
        {
            return null;
        }

        return new ProcStat(pid, stat[(open + 1)..close], parent, start);
    }
}
