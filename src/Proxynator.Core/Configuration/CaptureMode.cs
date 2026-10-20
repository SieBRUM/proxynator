using System.Text.Json.Serialization;

namespace Proxynator.Core.Configuration;

/// <summary>How outbound connections are captured and redirected into the relay.</summary>
public enum CaptureMode
{
    /// <summary>The platform default: <see cref="WinDivert"/> on Windows, <see cref="Ebpf"/> on Linux.</summary>
    [JsonStringEnumMemberName("auto")]
    Auto,

    /// <summary>Windows: kernel-level packet redirection through the WinDivert driver.</summary>
    [JsonStringEnumMemberName("windivert")]
    WinDivert,

    /// <summary>Windows: user-mode Winsock hooking through an injected DLL.</summary>
    [JsonStringEnumMemberName("injection")]
    Injection,

    /// <summary>Linux: cgroup eBPF connect hooks.</summary>
    [JsonStringEnumMemberName("ebpf")]
    Ebpf,

    /// <summary>Linux: cgroup matching with nftables redirection.</summary>
    [JsonStringEnumMemberName("nftables")]
    Nftables,

    /// <summary>Linux: user-mode hooking through an <c>LD_PRELOAD</c> library.</summary>
    [JsonStringEnumMemberName("preload")]
    Preload,
}
