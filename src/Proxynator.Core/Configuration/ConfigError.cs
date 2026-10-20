namespace Proxynator.Core.Configuration;

/// <summary>A configuration problem, located by a JSON path such as <c>$.rules[2].action.target</c>.</summary>
public sealed record ConfigError(string Path, string Message)
{
    /// <inheritdoc />
    public override string ToString() => $"{Path}: {Message}";
}
