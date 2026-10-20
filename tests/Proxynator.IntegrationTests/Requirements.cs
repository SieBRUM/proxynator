using System.Security.Principal;

namespace Proxynator.IntegrationTests;

internal static class Requirements
{
    /// <summary>Skips the test unless running elevated on Windows (or fails, when CI requires these tests).</summary>
    public static void ElevatedWindows()
    {
        string? missing = !OperatingSystem.IsWindows()
            ? "Capture integration tests need Windows."
            : !IsElevated() ? "Capture integration tests need an elevated (Administrator) process." : null;
        if (missing is null)
        {
            return;
        }

        if (Environment.GetEnvironmentVariable("PROXYNATOR_REQUIRE_INTEGRATION") == "1")
        {
            Assert.Fail(missing + " PROXYNATOR_REQUIRE_INTEGRATION=1 is set, so this is an error.");
        }

        Assert.Skip(missing);
    }

    /// <summary>Like <see cref="ElevatedWindows"/>, and the hook DLLs (built by build/build-native.ps1) must be present.</summary>
    public static void ElevatedWindowsWithHooks()
    {
        ElevatedWindows();
        var missing = Platform.Windows.Injection.HookLibrary.Missing();
        if (missing.Count == 0)
        {
            return;
        }

        var message = $"The hook DLLs are missing ({string.Join(", ", missing)}); build them with build/build-native.ps1.";
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
