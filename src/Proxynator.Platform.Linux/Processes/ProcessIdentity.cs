using System.Text.RegularExpressions;

namespace Proxynator.Platform.Linux.Processes;

/// <summary>
/// The name, executable and script rules match a Linux process by.
/// <list type="bullet">
/// <item>Scripts started through their shebang (<c>nxc</c>, <c>roadrecon</c>: pipx installs Python scripts) are
/// named after the script by the kernel, while <c>/proc/&lt;pid&gt;/exe</c> is the interpreter.</item>
/// <item>Scripts started as <c>python3 tool.py</c> or through <c>#!/usr/bin/env python3</c> are named after the
/// interpreter.</item>
/// </list>
/// In both cases the script's path is reported, so a rule for <c>nxc</c> or <c>tool.py</c> matches.
/// </summary>
internal static partial class ProcessIdentity
{
    private const int CommLength = 15;

    /// <param name="command">The <c>comm</c> value (truncated to 15 characters by the kernel).</param>
    /// <param name="executable">The target of <c>/proc/&lt;pid&gt;/exe</c>, if readable.</param>
    /// <param name="arguments">The command line arguments (<c>/proc/&lt;pid&gt;/cmdline</c>).</param>
    /// <param name="fileExists">Checks script candidates (relative paths are relative to the process; ignored).</param>
    public static (string Name, string? ExecutablePath, string? ScriptPath) Resolve(
        string command, string? executable, IReadOnlyList<string> arguments, Func<string, bool> fileExists)
    {
        var exePath = executable is null ? null : StripDeleted(executable);
        var exeName = exePath is null ? null : Path.GetFileName(exePath);

        // comm is what ps shows (e.g. python3 for /usr/bin/python3 -> python3.12); when truncated, the file name.
        var name = command.Length >= CommLength && exeName?.StartsWith(command, StringComparison.Ordinal) == true ? exeName : command;
        var interpreter = exeName is not null && IsInterpreter(exeName);

        if (exeName is not null && !StartsWithCommand(exeName, command) && !(interpreter && IsInterpreter(command)))
        {
            // Started through a shebang: comm is the script's name, the arguments contain its path.
            foreach (var argument in arguments.Take(4))
            {
                var argumentName = Path.GetFileName(argument);
                if (argumentName.Length > 0 && StartsWithCommand(argumentName, command))
                {
                    return (argumentName, exePath, argument);
                }
            }

            return (name, exePath, null);
        }

        // An interpreter runs the script given as its first non-option argument (python3 tool.py).
        var candidates = arguments.Skip(1).Take(3).Where(a => !a.StartsWith('-')).ToList();
        var script = interpreter
            ? candidates.FirstOrDefault(a => a.Contains('/', StringComparison.Ordinal) && fileExists(a)) ?? candidates.FirstOrDefault(fileExists)
            : null;
        return (name, exePath, script);
    }

    private static bool StartsWithCommand(string name, string command) =>
        name == command || name.StartsWith(command, StringComparison.Ordinal) && (command.Length >= CommLength || IsInterpreter(name));

    private static bool IsInterpreter(string name) => InterpreterPattern().IsMatch(name);

    [GeneratedRegex(@"^(python|pypy|perl|ruby|node|nodejs|php|bash|sh|dash|zsh|pwsh)[0-9.]*$")]
    private static partial Regex InterpreterPattern();

    private static string StripDeleted(string path) =>
        path.EndsWith(" (deleted)", StringComparison.Ordinal) ? path[..^" (deleted)".Length] : path;
}
