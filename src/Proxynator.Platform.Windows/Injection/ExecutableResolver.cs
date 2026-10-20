namespace Proxynator.Platform.Windows.Injection;

/// <summary>Finds the program for <c>proxynator run</c> the way a command prompt does (PATH and PATHEXT).</summary>
public static class ExecutableResolver
{
    private const string DefaultPathExtensions = ".COM;.EXE;.BAT;.CMD";

    /// <summary>
    /// Resolves <paramref name="command"/> to a full path: as given when it contains a directory, otherwise from the
    /// current directory and then each <paramref name="path"/> entry, trying the <paramref name="pathExtensions"/>
    /// when it has no extension. Returns null when nothing is found.
    /// </summary>
    public static string? Resolve(string command, string currentDirectory, string? path, string? pathExtensions, Func<string, bool>? fileExists = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(command);
        fileExists ??= File.Exists;
        var extensions = (string.IsNullOrWhiteSpace(pathExtensions) ? DefaultPathExtensions : pathExtensions)
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var candidates = HasDirectory(command)
            ? [Path.GetFullPath(command, currentDirectory)]
            : new[] { currentDirectory }
                .Concat((path ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(d => d.Trim('"')))
                .Where(d => d.Length > 0)
                .Select(d => Path.Combine(d, command));

        foreach (var candidate in candidates)
        {
            if (Path.HasExtension(candidate) && fileExists(candidate))
            {
                return candidate;
            }

            foreach (var extension in extensions)
            {
                if (fileExists(candidate + extension))
                {
                    return candidate + extension;
                }
            }
        }

        return null;
    }

    /// <summary>Whether Windows runs <paramref name="file"/> through <c>cmd.exe</c> (batch files).</summary>
    public static bool IsBatchFile(string file) =>
        file.EndsWith(".cmd", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".bat", StringComparison.OrdinalIgnoreCase);

    private static bool HasDirectory(string command) =>
        command.Contains('\\', StringComparison.Ordinal) || command.Contains('/', StringComparison.Ordinal) || command.Contains(':', StringComparison.Ordinal);
}
