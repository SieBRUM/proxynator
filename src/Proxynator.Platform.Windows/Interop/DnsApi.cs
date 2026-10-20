using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>DNS client functions.</summary>
[SupportedOSPlatform("windows")]
internal static partial class DnsApi
{
    /// <summary>Clears the DNS client cache (like <c>ipconfig /flushdns</c>), so no fake-IP answers outlive the service.</summary>
    [LibraryImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool FlushResolverCache();
}
