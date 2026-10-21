namespace Proxynator.Gui.ViewModels;

/// <summary>Lists edited as text: entries separated by commas, semicolons or new lines.</summary>
internal static class ListText
{
    private static readonly char[] Separators = [',', ';', '\n', '\r'];

    public static IReadOnlyList<string> Parse(string? text) =>
        (text ?? string.Empty).Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static string Format(IEnumerable<string> values) => string.Join(", ", values);
}
