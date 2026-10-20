using System.Text;
using Proxynator.Platform.Windows.Injection;

namespace Proxynator.Platform.Windows.Tests;

public sealed class WindowsCommandLineTests
{
    [Theory]
    [InlineData(new[] { "nxc", "smb", "10.0.0.1" }, "nxc smb 10.0.0.1")]
    [InlineData(new[] { "python", "-c", "print('a b')" }, "python -c \"print('a b')\"")]
    [InlineData(new[] { "x", "" }, "x \"\"")]
    [InlineData(new[] { "x", "say \"hi\"" }, "x \"say \\\"hi\\\"\"")]
    [InlineData(new[] { "x", @"C:\dir with space\" }, "x \"C:\\dir with space\\\\\"")]
    [InlineData(new[] { "x", @"C:\no\space\" }, @"x C:\no\space\")]
    public void Quotes_only_when_needed(string[] arguments, string expected)
    {
        Assert.Equal(expected, WindowsCommandLine.Join(arguments));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("two words")]
    [InlineData("")]
    [InlineData("\"")]
    [InlineData("\\\"")]
    [InlineData("a\\\\\"b")]
    [InlineData("trailing\\")]
    [InlineData("trailing\\\\ space\\\\")]
    [InlineData("tab\there")]
    [InlineData("-p 'P@ss w0rd!\"'")]
    public void Arguments_survive_the_C_runtime_parser(string argument)
    {
        var line = WindowsCommandLine.Join(["program.exe", argument, "next"]);

        Assert.Equal(["program.exe", argument, "next"], Parse(line));
    }

    /// <summary>The argument rules of the Microsoft C runtime (and CommandLineToArgvW for arguments after the first).</summary>
    private static List<string> Parse(string line)
    {
        var arguments = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        var hasArgument = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '\\')
            {
                var start = i;
                while (i < line.Length && line[i] == '\\')
                {
                    i++;
                }

                var count = i - start;
                if (i < line.Length && line[i] == '"')
                {
                    current.Append('\\', count / 2);
                    if (count % 2 == 1)
                    {
                        current.Append('"');
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else
                {
                    current.Append('\\', count);
                    i--;
                }

                hasArgument = true;
            }
            else if (c == '"')
            {
                inQuotes = !inQuotes;
                hasArgument = true;
            }
            else if (!inQuotes && c is ' ' or '\t')
            {
                if (hasArgument)
                {
                    arguments.Add(current.ToString());
                    current.Clear();
                    hasArgument = false;
                }
            }
            else
            {
                current.Append(c);
                hasArgument = true;
            }
        }

        if (hasArgument)
        {
            arguments.Add(current.ToString());
        }

        return arguments;
    }
}
