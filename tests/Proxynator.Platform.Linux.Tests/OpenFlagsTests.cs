using System.Runtime.InteropServices;
using Proxynator.Platform.Linux.Interop;

namespace Proxynator.Platform.Linux.Tests;

public class OpenFlagsTests
{
    [Theory]
    [InlineData(Architecture.X64, 0x10000)]
    [InlineData(Architecture.X86, 0x10000)]
    [InlineData(Architecture.Arm64, 0x4000)] // 0x10000 is O_DIRECT there: opening the cgroup directory fails (EINVAL)
    [InlineData(Architecture.Arm, 0x4000)]
    public void O_DIRECTORY_depends_on_the_architecture(Architecture architecture, int expected) =>
        Assert.Equal(expected, OpenFlags.DirectoryFor(architecture));

    [Fact]
    public void Unknown_architectures_are_refused_rather_than_guessed() =>
        Assert.Throws<PlatformNotSupportedException>(() => OpenFlags.DirectoryFor(Architecture.S390x));
}
