namespace Proxynator.Client;

/// <summary>
/// Terminal emulators that can run a command, in order of preference, and how each is told to: the Debian
/// alternative <c>x-terminal-emulator</c> first (the desktop's choice, qterminal on Kali), then common ones.
/// </summary>
public static class LinuxTerminals
{
    /// <summary>The known terminals and the arguments that make them run a command (the command's words follow).</summary>
    public static IReadOnlyList<(string Program, IReadOnlyList<string> Prefix)> Known { get; } =
    [
        ("x-terminal-emulator", ["-e"]),
        ("qterminal", ["-e"]),
        ("gnome-terminal", ["--"]),
        ("konsole", ["-e"]),
        ("xfce4-terminal", ["-x"]),
        ("kitty", []),
        ("alacritty", ["-e"]),
        ("xterm", ["-e"]),
    ];

    /// <summary>The first known terminal on <paramref name="path"/>, or null.</summary>
    public static Terminal? Find(string? path, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        var directories = (path ?? string.Empty).Split(':', StringSplitOptions.RemoveEmptyEntries);
        foreach (var (program, prefix) in Known)
        {
            foreach (var directory in directories)
            {
                // Linux paths, also when this logic is tested on Windows.
                var candidate = $"{directory.TrimEnd('/')}/{program}";
                if (fileExists(candidate))
                {
                    return new Terminal(candidate, prefix);
                }
            }
        }

        return null;
    }

    /// <summary>A terminal emulator found on the PATH.</summary>
    /// <param name="Path">Its full path.</param>
    /// <param name="Prefix">The arguments before the command.</param>
    public sealed record Terminal(string Path, IReadOnlyList<string> Prefix)
    {
        /// <summary>The terminal's arguments for running <paramref name="command"/>.</summary>
        public IReadOnlyList<string> Arguments(IReadOnlyList<string> command) => [.. Prefix, .. command];
    }
}
