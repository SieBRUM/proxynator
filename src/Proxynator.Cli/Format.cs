namespace Proxynator.Cli;

/// <summary>Human-readable output helpers.</summary>
internal static class Format
{
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
