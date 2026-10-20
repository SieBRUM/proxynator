using System.Buffers.Binary;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>
/// Searches the raw output of <c>GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)</c> for the owner of a connection.
/// Kept free of P/Invoke so it can be unit-tested on any OS.
/// </summary>
internal static class TcpTableParser
{
    /// <summary><c>sizeof(MIB_TCPROW_OWNER_PID)</c>.</summary>
    public const int IPv4RowSize = 24;

    /// <summary><c>sizeof(MIB_TCP6ROW_OWNER_PID)</c>.</summary>
    public const int IPv6RowSize = 56;

    /// <summary>Returns the owning PID of the row with the given local port and remote endpoint, or -1.</summary>
    public static int FindOwner(ReadOnlySpan<byte> table, bool ipv6, int localPort, UInt128 remoteAddress, int remotePort)
    {
        if (table.Length < 4)
        {
            return -1;
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        var rowSize = ipv6 ? IPv6RowSize : IPv4RowSize;
        var rows = table[4..];
        for (var i = 0; i < count && (i + 1) * rowSize <= rows.Length; i++)
        {
            var row = rows.Slice(i * rowSize, rowSize);
            int rowLocalPort, rowRemotePort, pid;
            UInt128 rowRemote;
            if (ipv6)
            {
                // ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid
                rowLocalPort = BinaryPrimitives.ReadUInt16BigEndian(row[20..]);
                rowRemote = AddressKey.FromIPv6(row.Slice(24, 16));
                rowRemotePort = BinaryPrimitives.ReadUInt16BigEndian(row[44..]);
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(row[52..]);
            }
            else
            {
                // dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid (addresses and ports in network order)
                rowLocalPort = BinaryPrimitives.ReadUInt16BigEndian(row[8..]);
                rowRemote = AddressKey.FromIPv4(row.Slice(12, 4));
                rowRemotePort = BinaryPrimitives.ReadUInt16BigEndian(row[16..]);
                pid = (int)BinaryPrimitives.ReadUInt32LittleEndian(row[20..]);
            }

            if (rowLocalPort == localPort && rowRemotePort == remotePort && rowRemote == remoteAddress)
            {
                return pid;
            }
        }

        return -1;
    }
}
