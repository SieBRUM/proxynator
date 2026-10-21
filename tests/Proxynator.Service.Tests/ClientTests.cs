using Proxynator.Client;

namespace Proxynator.Service.Tests;

/// <summary>The pure helpers shared by the CLI and the GUI.</summary>
public class ClientTests
{
    public static TheoryData<string?, string[]> Arguments => new()
    {
        { null, [] },
        { "   ", [] },
        { "-v https://example.com", ["-v", "https://example.com"] },
        { "  a   b  ", ["a", "b"] },
        { "\"C:\\Program Files\\x\\y.txt\" --flag", ["C:\\Program Files\\x\\y.txt", "--flag"] },
        { "'a b' c", ["a b", "c"] },
        { "say \\\"hi\\\"", ["say", "\"hi\""] },
        { "--user=\"cn=reader,dc=corp\" -x", ["--user=cn=reader,dc=corp", "-x"] },
        { "\"\" empty", ["", "empty"] },
        { "\"unterminated quote", ["unterminated quote"] },
        { "\"it's\"", ["it's"] },
        { "C:\\tools\\nc.exe", ["C:\\tools\\nc.exe"] },
    };

    [Theory]
    [MemberData(nameof(Arguments))]
    public void Argument_strings_are_split(string? text, string[] expected) => Assert.Equal(expected, ArgumentSplitter.Split(text));

    [Theory]
    [InlineData(0, "0s")]
    [InlineData(5, "5s")]
    [InlineData(125, "2m05s")]
    [InlineData(3 * 3600 + 7 * 60, "3h07m")]
    [InlineData(-3, "0s")]
    public void Durations_are_formatted(int seconds, string expected) => Assert.Equal(expected, DisplayFormat.Duration(TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void The_preferred_terminal_on_the_path_is_chosen()
    {
        string[] present = ["/usr/bin/xterm", "/usr/local/bin/konsole"];
        var terminal = LinuxTerminals.Find("/usr/local/bin:/usr/bin", present.Contains);

        Assert.NotNull(terminal);
        Assert.Equal("/usr/local/bin/konsole", terminal.Path);
        Assert.Equal(["-e", "env", "sh"], terminal.Arguments(["env", "sh"]));
    }

    [Fact]
    public void The_debian_alternative_wins_and_gnome_terminal_takes_a_double_dash()
    {
        Assert.Equal("/usr/bin/x-terminal-emulator", LinuxTerminals.Find("/usr/bin", f => f.EndsWith("x-terminal-emulator", StringComparison.Ordinal) || f.EndsWith("xterm", StringComparison.Ordinal))?.Path);
        Assert.Equal(["--", "bash"], LinuxTerminals.Find("/usr/bin", f => f.EndsWith("gnome-terminal", StringComparison.Ordinal))?.Arguments(["bash"]));
        Assert.Null(LinuxTerminals.Find(null, _ => true));
        Assert.Null(LinuxTerminals.Find("/usr/bin", _ => false));
    }
}
