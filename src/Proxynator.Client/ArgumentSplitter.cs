using System.Text;

namespace Proxynator.Client;

/// <summary>
/// Splits an argument string typed into the GUI into arguments: whitespace separates them, double or single quotes
/// group (<c>"C:\Program Files\x"</c>, <c>'a b'</c>), and a backslash escapes only a quote, so Windows paths need no
/// doubling.
/// </summary>
public static class ArgumentSplitter
{
    /// <summary>Splits <paramref name="text"/>; an unterminated quote runs to the end.</summary>
    public static IReadOnlyList<string> Split(string? text)
    {
        var arguments = new List<string>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return arguments;
        }

        var current = new StringBuilder();
        var inArgument = false;
        char? quote = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '\\' && i + 1 < text.Length && text[i + 1] is '"' or '\'')
            {
                current.Append(text[++i]);
                inArgument = true;
            }
            else if (quote is not null)
            {
                if (c == quote)
                {
                    quote = null;
                }
                else
                {
                    current.Append(c);
                }
            }
            else if (c is '"' or '\'')
            {
                quote = c;
                inArgument = true;
            }
            else if (char.IsWhiteSpace(c))
            {
                if (inArgument)
                {
                    arguments.Add(current.ToString());
                    current.Clear();
                    inArgument = false;
                }
            }
            else
            {
                current.Append(c);
                inArgument = true;
            }
        }

        if (inArgument)
        {
            arguments.Add(current.ToString());
        }

        return arguments;
    }
}
