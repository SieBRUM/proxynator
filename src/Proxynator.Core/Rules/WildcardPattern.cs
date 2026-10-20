namespace Proxynator.Core.Rules;

/// <summary>Case-insensitive glob matching with <c>*</c> (any run of characters) and <c>?</c> (one character).</summary>
internal sealed class WildcardPattern(string pattern)
{
    public string Pattern { get; } = pattern;

    public bool IsMatch(string input) => IsMatch(Pattern, input);

    public override string ToString() => Pattern;

    private static bool IsMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> input)
    {
        int p = 0, i = 0, star = -1, starInput = 0;
        while (i < input.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(input[i])))
            {
                p++;
                i++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                starInput = i;
            }
            else if (star >= 0)
            {
                p = star + 1;
                i = ++starInput;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}
