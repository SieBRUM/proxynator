using System.Diagnostics;

namespace Proxynator.IntegrationTests;

/// <summary>Runs the curl.exe that ships with Windows: a real, unmodified, proxy-unaware client process.</summary>
internal static class Curl
{
    // IPv4 only (runners rarely have IPv6), quiet, bounded, print just the HTTP status code.
    private static readonly string[] CommonArguments = ["-4", "-sS", "--max-time", "20", "-o", "NUL", "-w", "%{http_code}"];

    public static async Task<(int ExitCode, string Output, string Error)> RunAsync(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "curl.exe"))
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in CommonArguments.Concat(arguments))
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, (await output).Trim(), (await error).Trim());
    }
}
