using System.Globalization;

namespace Proxynator.Cli;

/// <summary>Human-readable output helpers.</summary>
internal static class Format
{
    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? string.Create(CultureInfo.InvariantCulture, $"{bytes} B")
            : string.Create(CultureInfo.InvariantCulture, $"{value:0.#} {units[unit]}");
    }

    public static string Duration(TimeSpan duration) => duration.TotalHours >= 1
        ? string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalHours}h{duration.Minutes:00}m")
        : duration.TotalMinutes >= 1
            ? string.Create(CultureInfo.InvariantCulture, $"{duration.Minutes}m{duration.Seconds:00}s")
            : string.Create(CultureInfo.InvariantCulture, $"{duration.Seconds}s");

    /// <summary>Writes rows as left-aligned columns separated by two spaces.</summary>
    public static void Table(TextWriter output, IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<string>> rows)
    {
        var all = new List<IReadOnlyList<string>> { headers };
        all.AddRange(rows);
        var widths = headers.Select((_, column) => all.Max(row => row[column].Length)).ToArray();
        foreach (var row in all)
        {
            output.WriteLine(string.Join("  ", row.Select((cell, column) => column == row.Count - 1 ? cell : cell.PadRight(widths[column]))).TrimEnd());
        }
    }
}
