using Avalonia;
using Avalonia.Controls;
using Avalonia.Data.Converters;

namespace Proxynator.Gui.Converters;

/// <summary>Value converters used in XAML.</summary>
internal static class Display
{
    /// <summary>Enum values as they are written in the configuration file (<c>WinDivert</c> → <c>windivert</c>).</summary>
    public static readonly FuncValueConverter<object?, string> ConfigName = new(value => value?.ToString()?.ToLowerInvariant() ?? string.Empty);

    /// <summary>An application resource by key, e.g. a navigation icon.</summary>
    public static readonly FuncValueConverter<string?, object?> Resource = new(key =>
        key is not null && Application.Current is { } app && app.TryFindResource(key, out var value) ? value : null);

    /// <summary>True for a non-empty string.</summary>
    public static readonly FuncValueConverter<string?, bool> NotEmpty = new(value => !string.IsNullOrEmpty(value));
}
