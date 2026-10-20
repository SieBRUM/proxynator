using System.Security.Principal;

namespace Proxynator.IntegrationTests;

internal static class Requirements
{
    /// <summary>Skips the test unless running elevated on Windows (or fails, when CI requires these tests).</summary>
    public static void ElevatedWindows()
    {
        string? missing = !OperatingSystem.IsWindows()
            ? "WinDivert integration tests need Windows."
            : !IsElevated() ? "WinDivert integration tests need an elevated (Administrator) process." : null;
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
