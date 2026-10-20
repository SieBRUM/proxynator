using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Proxynator.Platform.Linux.Interop;

namespace Proxynator.Platform.Linux.Capture;

/// <summary>The native ring buffer callback for exec() events of the eBPF programs.</summary>
[SupportedOSPlatform("linux")]
internal static unsafe class EventCallback
{
    /// <summary>Opens the ring buffer; <paramref name="backend"/> is a GCHandle to the <see cref="BpfCaptureBackend"/>.</summary>
    public static nint Open(int mapFd, nint backend) => LibBpf.ring_buffer__new(mapFd, &OnEvent, backend, 0);

    [UnmanagedCallersOnly]
    private static int OnEvent(nint context, nint data, nuint size)
    {
        try
        {
            if (size >= sizeof(uint) && GCHandle.FromIntPtr(context).Target is BpfCaptureBackend backend)
            {
                backend.OnProcessExec(*(int*)data);
            }
        }
#pragma warning disable CA1031 // An exception must never cross into native code.
        catch (Exception)
#pragma warning restore CA1031
        {
        }

        return 0;
    }
}
