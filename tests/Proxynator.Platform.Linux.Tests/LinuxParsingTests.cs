using Proxynator.Platform.Linux;
using Proxynator.Platform.Linux.Processes;

namespace Proxynator.Platform.Linux.Tests;

/// <summary>The /proc, mountinfo and group file parsing: pure code, tested on every OS.</summary>
public sealed class LinuxParsingTests
{
    [Fact]
    public void Proc_stat_handles_spaces_and_parentheses_in_the_command()
    {
        var stat = ProcStat.Parse("4242 (my (odd) prog) S 1000 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100 18446744073709551615");

        Assert.Equal(new ProcStat(4242, "my (odd) prog", 1000, 98765), stat);
    }

    [Theory]
    [InlineData("")]
    [InlineData("4242 (short) S 1")]
    [InlineData("x (name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20")]
    public void Malformed_stat_lines_are_rejected(string line)
    {
        Assert.Null(ProcStat.Parse(line));
    }

    public static TheoryData<string, string?, string[], string, string?, string?> Identities() => new()
    {
        // A plain program.
        { "curl", "/usr/bin/curl", ["curl", "-sS", "http://x"], "curl", "/usr/bin/curl", null },
        // pipx: the script's shebang names the venv's python, so the kernel names the process after the script.
        { "nxc", "/usr/bin/python3.12", ["/home/u/.local/pipx/venvs/netexec/bin/python", "/home/u/.local/bin/nxc", "smb"], "nxc", "/usr/bin/python3.12", "/home/u/.local/bin/nxc" },
        // python3 tool.py, or #!/usr/bin/env python3: named after the interpreter, the script is reported.
        { "python3", "/usr/bin/python3.12", ["python3", "-u", "/opt/tools/tool.py", "--flag"], "python3", "/usr/bin/python3.12", "/opt/tools/tool.py" },
        { "python3", "/usr/bin/python3.12", ["python3", "-c", "print(1)"], "python3", "/usr/bin/python3.12", null },
        // comm is truncated to 15 characters.
        { "very-long-progr", "/opt/very-long-program-name", ["/opt/very-long-program-name"], "very-long-program-name", "/opt/very-long-program-name", null },
        // A deleted (updated) binary.
        { "app", "/opt/app (deleted)", ["/opt/app"], "app", "/opt/app", null },
        // Unreadable exe (kernel thread or no permission).
        { "kworker/0:1", null, [], "kworker/0:1", null, null },
    };

    [Theory]
    [MemberData(nameof(Identities))]
    public void Process_identity(string command, string? executable, string[] arguments, string name, string? path, string? script)
    {
        var existing = new HashSet<string> { "/home/u/.local/bin/nxc", "/opt/tools/tool.py" };

        Assert.Equal((name, path, script), ProcessIdentity.Resolve(command, executable, arguments, existing.Contains));
    }

    [Theory]
    [InlineData("25 1 0:22 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw,nsdelegate", "/sys/fs/cgroup")]
    [InlineData("30 25 0:26 / /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw\n31 25 0:27 / /sys/fs/cgroup/cpu rw shared:11 - cgroup cgroup rw,cpu", "/sys/fs/cgroup/unified")]
    [InlineData("31 25 0:27 / /sys/fs/cgroup/cpu rw shared:11 - cgroup cgroup rw,cpu", null)]
    public void The_cgroup2_mount_is_found(string mountInfo, string? expected)
    {
        Assert.Equal(expected, CgroupFinder.FindCgroup2Mount(mountInfo));
    }

    [Theory]
    [InlineData("000001ffffffffff", true)] // root
    [InlineData("0000000000201000", true)] // CAP_NET_ADMIN + CAP_SYS_ADMIN
    [InlineData("000000c000001000", true)] // CAP_NET_ADMIN + CAP_BPF + CAP_PERFMON
    [InlineData("0000008000001000", false)] // CAP_BPF without CAP_PERFMON
    [InlineData("0000000000000000", false)]
    public void Capabilities_are_checked(string capEff, bool sufficient)
    {
        var capabilities = Capabilities.ParseCapEff($"Name:\tproxynatord\nCapInh:\t0000000000000000\nCapEff:\t{capEff}\n");

        Assert.NotNull(capabilities);
        Assert.Equal(sufficient, Capabilities.Evaluate(capabilities.Value).IsSufficient);
    }

    [Fact]
    public void The_control_group_id_is_read_from_the_group_file()
    {
        const string groups = "root:x:0:\nadm:x:4:syslog,u\nproxynator:x:998:alice,bob\n";

        Assert.Equal(998, UnixGroups.FindGroupId(groups, "proxynator"));
        Assert.Null(UnixGroups.FindGroupId(groups, "missing"));
    }
}
