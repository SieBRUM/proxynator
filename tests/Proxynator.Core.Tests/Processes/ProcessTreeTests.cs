using Proxynator.Core.Processes;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Processes;

public class ProcessTreeTests
{
    private readonly ManualTimeProvider time = new();

    private static ProcessRecord P(int pid, int parent, long created, string name) => new(pid, parent, created, name, $@"C:\bin\{name}");

    [Fact]
    public void Ancestors_are_found_nearest_first()
    {
        var tree = new ProcessTree(time);
        tree.Observe([P(10, 1, 100, "explorer.exe"), P(20, 10, 200, "nxc.exe"), P(30, 20, 300, "python.exe")]);

        Assert.Equal(["nxc.exe", "explorer.exe"], tree.GetAncestors(30, 300).Select(a => a.Name));
    }

    [Fact]
    public void Exited_parents_are_remembered_for_the_retention_period()
    {
        var tree = new ProcessTree(time, TimeSpan.FromMinutes(10));
        tree.Observe([P(20, 1, 200, "nxc.exe"), P(30, 20, 300, "python.exe")]);
        tree.Observe([P(30, 20, 300, "python.exe")]); // the launcher exited

        Assert.Equal("nxc.exe", Assert.Single(tree.GetAncestors(30, 300)).Name);

        time.Advance(TimeSpan.FromMinutes(11));
        tree.Observe([P(30, 20, 300, "python.exe")]);
        Assert.Empty(tree.GetAncestors(30, 300));
    }

    [Fact]
    public void A_reused_parent_pid_is_not_mistaken_for_the_real_parent()
    {
        var tree = new ProcessTree(time);
        tree.Observe([P(20, 1, 200, "launcher.exe"), P(30, 20, 300, "child.exe")]);
        tree.Observe([P(20, 1, 400, "unrelated.exe"), P(30, 20, 300, "child.exe")]); // PID 20 reused after the launcher exited

        Assert.Equal("launcher.exe", Assert.Single(tree.GetAncestors(30, 300)).Name);
        Assert.Equal("unrelated.exe", tree.FindRunning(20)!.Name);
    }

    [Fact]
    public void Parents_created_after_the_child_are_ignored()
    {
        var tree = new ProcessTree(time);
        tree.Observe([P(20, 1, 500, "newer.exe"), P(30, 20, 300, "child.exe")]);

        Assert.Empty(tree.GetAncestors(30, 300));
    }

    [Fact]
    public void Cycles_and_self_parents_terminate()
    {
        var tree = new ProcessTree(time);
        tree.Observe([P(1, 1, 1, "self.exe"), P(2, 3, 2, "a.exe"), P(3, 2, 2, "b.exe")]);

        Assert.Empty(tree.GetAncestors(1, 1));
        Assert.True(tree.GetAncestors(2, 2).Count <= 16);
    }
}
