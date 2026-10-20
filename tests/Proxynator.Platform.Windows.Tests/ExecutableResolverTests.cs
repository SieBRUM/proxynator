using Proxynator.Platform.Windows.Injection;

namespace Proxynator.Platform.Windows.Tests;

public sealed class ExecutableResolverTests
{
    private static readonly string Current = Path.Combine(Path.GetTempPath(), "work");
    private static readonly string LocalBin = Path.Combine(Path.GetTempPath(), "user", ".local", "bin");
    private static readonly string PythonDir = Path.Combine(Path.GetTempPath(), "Python312");

    private static string? Resolve(string command, params string[] existing) =>
        ExecutableResolver.Resolve(command, Current, $"{LocalBin};\"{PythonDir}\";", ".COM;.EXE;.BAT;.CMD", existing.Contains);

    [Fact]
    public void Commands_are_found_on_the_path_with_an_extension()
    {
        var nxc = Path.Combine(LocalBin, "nxc") + ".EXE";

        Assert.Equal(nxc, Resolve("nxc", nxc));
    }

    [Fact]
    public void The_current_directory_comes_first()
    {
        var local = Path.Combine(Current, "python") + ".EXE";
        var onPath = Path.Combine(PythonDir, "python") + ".EXE";

        Assert.Equal(local, Resolve("python", local, onPath));
        Assert.Equal(onPath, Resolve("python", onPath));
    }

    [Fact]
    public void Commands_with_an_extension_are_used_as_given()
    {
        var script = Path.Combine(LocalBin, "tool.cmd");

        Assert.Equal(script, Resolve("tool.cmd", script));
        Assert.True(ExecutableResolver.IsBatchFile(script));
    }

    [Fact]
    public void Paths_are_not_searched()
    {
        var program = Path.Combine(PythonDir, "python.exe");

        Assert.Equal(program, Resolve(program, program));
        Assert.Null(Resolve(Path.Combine("sub", "missing.exe")));
    }

    [Fact]
    public void Unknown_commands_resolve_to_null()
    {
        Assert.Null(Resolve("does-not-exist"));
    }
}
