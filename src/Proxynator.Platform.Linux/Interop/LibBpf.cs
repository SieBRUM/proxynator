using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Linux.Interop;

/// <summary>
/// The subset of libbpf (https://github.com/libbpf/libbpf, LGPL-2.1 OR BSD-2-Clause) used to load the capture
/// programs. Loaded dynamically from the system: libbpf.so.1 (Ubuntu 24.04, Kali) or libbpf.so.0 (Ubuntu 22.04).
/// Pointer-returning functions may return an encoded error with libbpf 0.x; always check with <see cref="IsError"/>.
/// </summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class LibBpf
{
    public const string Library = "libbpf";
    private static readonly string[] Candidates = ["libbpf.so.1", "libbpf.so.0", "libbpf.so"];

    static LibBpf()
    {
        NativeLibrary.SetDllImportResolver(typeof(LibBpf).Assembly, Resolve);
    }

    /// <summary>Loads libbpf; returns the error when it is not installed.</summary>
    public static string? TryLoad()
    {
        try
        {
            Marshal.Prelink(typeof(LibBpf).GetMethod(nameof(libbpf_get_error), BindingFlags.Public | BindingFlags.Static)!);
            return null;
        }
        catch (DllNotFoundException ex)
        {
            return ex.Message;
        }
    }

    public static bool IsError(nint pointer) => pointer == 0 || libbpf_get_error(pointer) != 0;

    [LibraryImport(Library)]
    public static partial nint libbpf_get_error(nint pointer);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint bpf_object__open_file(string path, nint options);

    [LibraryImport(Library)]
    public static partial int bpf_object__load(nint bpfObject);

    [LibraryImport(Library)]
    public static partial void bpf_object__close(nint bpfObject);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint bpf_object__find_program_by_name(nint bpfObject, string name);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int bpf_object__find_map_fd_by_name(nint bpfObject, string name);

    [LibraryImport(Library)]
    public static partial nint bpf_program__attach_cgroup(nint program, int cgroupFd);

    [LibraryImport(Library)]
    public static partial nint bpf_program__attach(nint program);

    [LibraryImport(Library)]
    public static partial int bpf_link__destroy(nint link);

    [LibraryImport(Library)]
    public static partial int bpf_map_update_elem(int fd, void* key, void* value, ulong flags);

    [LibraryImport(Library)]
    public static partial int bpf_map_lookup_elem(int fd, void* key, void* value);

    [LibraryImport(Library)]
    public static partial int bpf_map_delete_elem(int fd, void* key);

    [LibraryImport(Library)]
    public static partial int bpf_map_get_next_key(int fd, void* key, void* nextKey);

    [LibraryImport(Library)]
    public static partial nint ring_buffer__new(int mapFd, delegate* unmanaged<nint, nint, nuint, int> sampleCallback, nint context, nint options);

    [LibraryImport(Library)]
    public static partial int ring_buffer__poll(nint ringBuffer, int timeoutMilliseconds);

    [LibraryImport(Library)]
    public static partial void ring_buffer__free(nint ringBuffer);

    private static nint Resolve(string name, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (name != Library)
        {
            return 0;
        }

        foreach (var candidate in Candidates)
        {
            if (NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        return 0;
    }
}
