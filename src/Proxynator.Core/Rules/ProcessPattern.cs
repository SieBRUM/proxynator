using Proxynator.Core.Processes;

namespace Proxynator.Core.Rules;

/// <summary>
/// Matches a process by file name, or by full path when the pattern contains a path separator. Both separators
/// are accepted on every platform.
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

    public bool IsMatch(ProcessInfo process) => matchPath
        ? process.ExecutablePath is { } path && pattern.IsMatch(NormalizePath(path))
        : pattern.IsMatch(process.Name);

    private static string NormalizePath(string path) => path.Replace('\\', '/');
}
