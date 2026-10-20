using System.Globalization;
using System.Runtime.Versioning;
using Proxynator.Core.Platform;

namespace Proxynator.Platform.Linux;

/// <summary>Root, or the capabilities the eBPF capture needs (CAP_NET_ADMIN, CAP_BPF and CAP_PERFMON, or CAP_SYS_ADMIN).</summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxPrivilegeChecker : IPrivilegeChecker
{
    /// <inheritdoc />
    public PrivilegeCheckResult Check()
    {
        if (ReadEffectiveCapabilities() is not { } capabilities)
        {
            return Environment.IsPrivilegedProcess ? new PrivilegeCheckResult(true, "Running as root.") : Capabilities.Evaluate(0);
        }

        // Root in a container can lack capabilities, so they are checked even for root.
        var result = Capabilities.Evaluate(capabilities);
        return result.IsSufficient && Environment.IsPrivilegedProcess ? new PrivilegeCheckResult(true, "Running as root.") : result;
    }

    private static ulong? ReadEffectiveCapabilities()
    {
        try
        {
            return Capabilities.ParseCapEff(File.ReadAllText("/proc/self/status"));
        }
        catch (IOException)
        {
            return null;
        }
    }
}
