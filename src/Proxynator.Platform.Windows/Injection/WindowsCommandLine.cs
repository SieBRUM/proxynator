using System.Text;

namespace Proxynator.Platform.Windows.Injection;

/// <summary>Builds Windows command lines that <c>CommandLineToArgvW</c> and the C runtime split back into the same arguments.</summary>
public static class WindowsCommandLine
{
    /// <summary>Quotes and joins <paramref name="arguments"/>.</summary>
    public static string Join(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var builder = new StringBuilder();
        foreach (var argument in arguments)
        {
            if (builder.Length > 0)
            {
                builder.Append(' ');
            }

            Append(builder, argument);
        }

        return builder.ToString();
    }

    /// <summary>Appends one argument, quoted only when needed.</summary>
    public static void Append(StringBuilder builder, string argument)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.Length > 0 && argument.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0)
        {
            builder.Append(argument);
            return;
        }

        builder.Append('"');
        var backslashes = 0;
        foreach (var c in argument)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            // Backslashes are literal unless they precede a quote: then each must be doubled, and the quote escaped.
            builder.Append('\\', c == '"' ? (backslashes * 2) + 1 : backslashes);
            builder.Append(c);
            backslashes = 0;
        }

        // Before the closing quote, all trailing backslashes must be doubled.
        builder.Append('\\', backslashes * 2);
        builder.Append('"');
    }
}
