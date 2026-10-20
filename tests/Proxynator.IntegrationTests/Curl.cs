using System.Diagnostics;

namespace Proxynator.IntegrationTests;

/// <summary>Runs unmodified, proxy-unaware Windows programs (curl.exe, nslookup.exe, a venv's pip.exe).</summary>
internal static class Curl
{
    // IPv4 only (runners rarely have IPv6), quiet, bounded, print just the HTTP status code.
    private static readonly string[] CommonArguments = ["-4", "-sS", "--max-time", "20", "-o", "NUL"];

    /// <summary>Runs curl.exe; the output is the HTTP status code, or the <c>-w</c> format given in <paramref name="writeOut"/>.</summary>
    public static Task<(int ExitCode, string Output, string Error)> RunAsync(string url, string writeOut = "%{http_code}") =>
        Tool.RunAsync(Path.Combine(Environment.SystemDirectory, "curl.exe"), [.. CommonArguments, "-w", writeOut, url]);
}

internal static class Tool
{
    public static async Task<(int ExitCode, string Output, string Error)> RunAsync(string fileName, IEnumerable<string> arguments, int timeoutSeconds = 60)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, (await output).Trim(), (await error).Trim());
    }
}
