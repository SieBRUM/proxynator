using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Proxynator.Core.Net;

/// <summary>An inclusive range of ports, written as <c>443</c> or <c>8000-8100</c>.</summary>
public readonly record struct PortRange(int Start, int End)
{
    /// <summary>Whether <paramref name="port"/> lies in the range.</summary>
    public bool Contains(int port) => port >= Start && port <= End;

    /// <summary>Parses <c>443</c> or <c>8000-8100</c>.</summary>
    public static bool TryParse([NotNullWhen(true)] string? text, out PortRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var dash = text.IndexOf('-', StringComparison.Ordinal);
        var startText = dash < 0 ? text : text[..dash];
        var endText = dash < 0 ? text : text[(dash + 1)..];
        if (!TryParsePort(startText, out var start) || !TryParsePort(endText, out var end) || end < start)
        {
            return false;
        }

        range = new PortRange(start, end);
        return true;
    }

    /// <inheritdoc />
    public override string ToString() =>
        Start == End ? Start.ToString(CultureInfo.InvariantCulture) : string.Create(CultureInfo.InvariantCulture, $"{Start}-{End}");

    private static bool TryParsePort(string text, out int port) =>
        int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}
