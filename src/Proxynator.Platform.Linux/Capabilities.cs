using System.Globalization;
using Proxynator.Core.Platform;

namespace Proxynator.Platform.Linux;

/// <summary>Linux capability checks for the eBPF capture (pure code, so it is tested on every OS).</summary>
internal static class Capabilities
{
    private const int CapNetAdmin = 12;
    private const int CapSysAdmin = 21;
    private const int CapPerfmon = 38;
    private const int CapBpf = 39;

    internal static PrivilegeCheckResult Evaluate(ulong capabilities)
    {
        bool Has(int capability) => (capabilities & (1UL << capability)) != 0;
        var bpf = Has(CapSysAdmin) || (Has(CapBpf) && Has(CapPerfmon));
        if (Has(CapNetAdmin) && bpf)
        {
            return new PrivilegeCheckResult(true, "Running with CAP_NET_ADMIN and BPF capabilities.");
        }

        return new PrivilegeCheckResult(false,
            "Root privileges are required (or CAP_NET_ADMIN with CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN). Run with sudo, or install the package and use 'sudo systemctl start proxynatord'.");
    }

    internal static ulong? ParseCapEff(string status)
    {
        foreach (var line in status.Split('\n'))
        {
            if (line.StartsWith("CapEff:", StringComparison.Ordinal) &&
                ulong.TryParse(line["CapEff:".Length..].Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
            {
                return value;
            }
        }

        return null;
    }
}
