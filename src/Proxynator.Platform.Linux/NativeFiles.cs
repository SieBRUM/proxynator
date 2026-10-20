namespace Proxynator.Platform.Linux;

/// <summary>
/// The native parts of the Linux capture, built by build/build-native.sh and shipped next to the executables.
/// </summary>
public static class NativeFiles
{
    /// <summary>The eBPF programs of the <c>ebpf</c> capture mode (native/linux/bpf).</summary>
    public const string BpfObject = "proxynator.bpf.o";

    /// <summary>The <c>LD_PRELOAD</c> library of the <c>preload</c> capture mode (native/linux/preload).</summary>
    public const string PreloadLibrary = "libproxynator-preload.so";

    /// <summary>The directory the files are expected in.</summary>
    public static string Directory => AppContext.BaseDirectory;

    /// <summary>The full path of one of the files.</summary>
    public static string PathOf(string file) => Path.Combine(Directory, file);
}
