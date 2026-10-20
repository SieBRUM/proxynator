using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>IP Helper API: connection-owner lookups.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class IpHelper
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(byte* table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint addressFamily, int tableClass, uint reserved);

    /// <summary>Finds the PID owning a TCP connection, or -1 if it is not in the table.</summary>
    public static int FindTcpOwner(bool ipv6, int localPort, UInt128 remoteAddress, int remotePort)
    {
        uint size = 0;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var result = GetExtendedTcpTable(null, ref size, false, ipv6 ? AfInet6 : AfInet, TcpTableOwnerPidAll, 0);
            if (result != ErrorInsufficientBuffer)
            {
                return -1;
            }

            size += 4096; // the table can grow between the two calls
            var buffer = ArrayPool<byte>.Shared.Rent((int)size);
            try
            {
                fixed (byte* pointer = buffer)
                {
                    result = GetExtendedTcpTable(pointer, ref size, false, ipv6 ? AfInet6 : AfInet, TcpTableOwnerPidAll, 0);
                }

                if (result == 0)
                {
                    return TcpTableParser.FindOwner(buffer.AsSpan(0, (int)size), ipv6, localPort, remoteAddress, remotePort);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        return -1;
    }
}
