using Proxynator.Core.Processes;

namespace Proxynator.Core.Rules;

/// <summary>
/// Matches a process by file name, or by full path when the pattern contains a path separator. Both separators
/// are accepted on every platform. The script an interpreter runs counts too (<see cref="ProcessInfo.ScriptPath"/>).
/// </summary>
internal sealed class ProcessPattern
{
    private readonly WildcardPattern pattern;
    private readonly bool matchPath;

    public ProcessPattern(string text)
    {
        matchPath = text.Contains('/', StringComparison.Ordinal) || text.Contains('\\', StringComparison.Ordinal);
        pattern = new WildcardPattern(matchPath ? NormalizePath(text) : text);
    }

    /// <summary>Matches the executable, or the script an interpreter runs.</summary>
    public bool IsMatch(ProcessInfo process) => matchPath
        ? (process.ExecutablePath is { } path && pattern.IsMatch(NormalizePath(path))) ||
          (process.ScriptPath is { } script && pattern.IsMatch(NormalizePath(script)))
        : pattern.IsMatch(process.Name) ||
          (process.ScriptPath is { } scriptPath && pattern.IsMatch(Path.GetFileName(NormalizePath(scriptPath))));

    private static string NormalizePath(string path) => path.Replace('\\', '/');
}
