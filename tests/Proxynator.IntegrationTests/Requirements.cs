using System.Security.Principal;

namespace Proxynator.IntegrationTests;

/// <summary>
/// Tests for another operating system are skipped. On the right one, a missing requirement skips the test, unless
/// PROXYNATOR_REQUIRE_INTEGRATION=1 (CI), which turns it into a failure so the tests can never pass silently.
/// </summary>
internal static class Requirements
{
    /// <summary>Windows, elevated (Administrator).</summary>
    public static void ElevatedWindows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows capture tests run on Windows.");
        Require(IsElevated(), "Capture integration tests need an elevated (Administrator) process.");
    }

    /// <summary>Like <see cref="ElevatedWindows"/>, and the hook DLLs (built by build/build-native.ps1) must be present.</summary>
    public static void ElevatedWindowsWithHooks()
    {
        ElevatedWindows();
        var missing = Platform.Windows.Injection.HookLibrary.Missing();
        Require(missing.Count == 0, $"The hook DLLs are missing ({string.Join(", ", missing)}); build them with build/build-native.ps1.");
    }

    /// <summary>Linux, root, and the native parts (built by build/build-native.sh).</summary>
    public static void RootLinux()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux capture tests run on Linux.");
        Require(Environment.IsPrivilegedProcess, "Linux capture integration tests need root (sudo).");
        var missing = new[] { Platform.Linux.NativeFiles.BpfObject, Platform.Linux.NativeFiles.PreloadLibrary }
            .Where(file => !File.Exists(Platform.Linux.NativeFiles.PathOf(file)))
            .ToList();
        Require(missing.Count == 0, $"The Linux capture parts are missing ({string.Join(", ", missing)}); build them with build/build-native.sh.");
    }

    private static void Require(bool condition, string message)
    {
        if (condition)
        {
            return;
        }

        if (Environment.GetEnvironmentVariable("PROXYNATOR_REQUIRE_INTEGRATION") == "1")
        {
            Assert.Fail(message + " PROXYNATOR_REQUIRE_INTEGRATION=1 is set, so this is an error.");
        }

        Assert.Skip(message);
    }

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
