using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Proxynator.Platform.Windows;

/// <summary>
/// Adds and removes the inbound firewall rule for the relay port. Redirected connections reach the relay as
/// inbound packets from the original destination's address, so Windows Defender Firewall must allow them.
/// Connections that are not redirected by Proxynator are dropped before they reach the relay port.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsFirewall(ILogger logger)
{
    private const string RuleName = "Proxynator relay";

    /// <summary>Replaces any stale rules with ones allowing the relay ports (UDP only when non-zero) for the current program.</summary>
    public void AllowRelayPorts(int tcpPort, int udpPort)
    {
        RemoveRelayRule();
        AddRule("TCP", tcpPort);
        if (udpPort != 0)
        {
            AddRule("UDP", udpPort);
        }
    }

    private void AddRule(string protocol, int port)
    {
        var program = Environment.ProcessPath ?? string.Empty;
        Run(
            LogLevel.Warning,
            "advfirewall", "firewall", "add", "rule", $"name={RuleName}", "dir=in", "action=allow", $"protocol={protocol}",
            string.Create(CultureInfo.InvariantCulture, $"localport={port}"), $"program={program}", "profile=any", "enable=yes");
    }

    public void RemoveRelayRule() => Run(LogLevel.Debug, "advfirewall", "firewall", "delete", "rule", $"name={RuleName}");

    private void Run(LogLevel failureLevel, params string[] arguments)
    {
        var command = string.Join(' ', arguments.Take(4));
        try
        {
            var startInfo = new ProcessStartInfo("netsh") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo)!;
            var output = (process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd()).Trim();
            if (!process.WaitForExit(15_000))
            {
                process.Kill();
            }

            if (process.ExitCode != 0)
            {
                Log.NetshFailed(logger, failureLevel, command, output);
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Log.NetshFailed(logger, failureLevel, command, ex.Message);
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 2100, Message = "netsh {Command} failed; if Windows Defender Firewall is enabled, redirected connections may not reach the relay: {Output}")]
        public static partial void NetshFailed(ILogger logger, LogLevel level, string command, string output);
    }
}
