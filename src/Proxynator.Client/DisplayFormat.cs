using System.Globalization;

namespace Proxynator.Client;

/// <summary>Human-readable values shared by the CLI and the GUI.</summary>
public static class DisplayFormat
{
    /// <summary>A byte count, e.g. <c>512 B</c>, <c>1.5 KB</c>.</summary>
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

    /// <summary>A duration, e.g. <c>5s</c>, <c>2m05s</c>, <c>3h07m</c>.</summary>
    public static string Duration(TimeSpan duration) => duration.TotalHours >= 1
        ? string.Create(CultureInfo.InvariantCulture, $"{(int)duration.TotalHours}h{duration.Minutes:00}m")
        : duration.TotalMinutes >= 1
            ? string.Create(CultureInfo.InvariantCulture, $"{duration.Minutes}m{duration.Seconds:00}s")
            : string.Create(CultureInfo.InvariantCulture, $"{Math.Max(0, duration.Seconds)}s");
}
