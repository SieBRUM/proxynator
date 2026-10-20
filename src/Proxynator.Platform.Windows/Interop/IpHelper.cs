using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>IP Helper API: socket-owner lookups.</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class IpHelper
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    private delegate uint TableQuery(byte* table, ref uint size);

    private delegate int TableSearch(ReadOnlySpan<byte> table);

    /// <summary>Finds the PID owning a TCP connection, or -1 if it is not in the table.</summary>
    public static int FindTcpOwner(bool ipv6, int localPort, UInt128 remoteAddress, int remotePort) =>
        Search(
            (byte* table, ref uint size) => GetExtendedTcpTable(table, ref size, false, ipv6 ? AfInet6 : AfInet, TcpTableOwnerPidAll, 0),
            table => TcpTableParser.FindOwner(table, ipv6, localPort, remoteAddress, remotePort));

    /// <summary>Finds the PID owning the UDP socket bound to <paramref name="localPort"/>, or -1.</summary>
    public static int FindUdpOwner(bool ipv6, int localPort) =>
        Search(
            (byte* table, ref uint size) => GetExtendedUdpTable(table, ref size, false, ipv6 ? AfInet6 : AfInet, UdpTableOwnerPid, 0),
            table => TcpTableParser.FindUdpOwner(table, ipv6, localPort));

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(byte* table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint addressFamily, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(byte* table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint addressFamily, int tableClass, uint reserved);

    private static int Search(TableQuery query, TableSearch search)
    {
        uint size = 0;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (query(null, ref size) != ErrorInsufficientBuffer)
            {
                return -1;
            }

            size += 4096; // the table can grow between the two calls
            var buffer = ArrayPool<byte>.Shared.Rent((int)size);
            try
            {
                uint result;
                fixed (byte* pointer = buffer)
                {
                    result = query(pointer, ref size);
                }

                if (result == 0)
                {
                    return search(buffer.AsSpan(0, (int)size));
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
