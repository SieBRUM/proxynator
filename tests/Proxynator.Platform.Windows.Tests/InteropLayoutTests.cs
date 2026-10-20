using System.Buffers.Binary;
using System.Net;
using System.Runtime.CompilerServices;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Tests;

/// <summary>The managed structs must match windivert.h byte for byte; they are passed to the driver by pointer.</summary>
public class InteropLayoutTests
{
    [Fact]
    public void WinDivertAddress_is_80_bytes()
    {
        Assert.Equal(WinDivertAddress.Size, Unsafe.SizeOf<WinDivertAddress>());
    }

    [Fact]
    public void Socket_data_layout_matches_the_header()
    {
        var data = default(WinDivertSocketData);
        ref var start = ref Unsafe.As<WinDivertSocketData, byte>(ref data);

        Assert.True(Unsafe.SizeOf<WinDivertSocketData>() <= 64);
        Assert.Equal(16, Offset(ref start, ref Unsafe.As<uint, byte>(ref data.ProcessId)));
        Assert.Equal(20, Offset(ref start, ref Unsafe.As<AddressWords, byte>(ref data.LocalAddr)));
        Assert.Equal(36, Offset(ref start, ref Unsafe.As<AddressWords, byte>(ref data.RemoteAddr)));
        Assert.Equal(52, Offset(ref start, ref Unsafe.As<ushort, byte>(ref data.LocalPort)));
        Assert.Equal(54, Offset(ref start, ref Unsafe.As<ushort, byte>(ref data.RemotePort)));
        Assert.Equal(56, Offset(ref start, ref data.Protocol));
    }

    [Fact]
    public void Address_bitfield_accessors()
    {
        // Layer 3 (socket), event 4 (connect), sniffed, outbound, IPv6
        var address = WinDivertAddress.FromBits(3u | (4u << 8) | (1u << 16) | (1u << 17) | (1u << 20));

        Assert.Equal(WinDivertLayer.Socket, address.Layer);
        Assert.Equal(WinDivertEvent.SocketConnect, address.Event);
        Assert.True(address.Sniffed);
        Assert.True(address.Outbound);
        Assert.True(address.IPv6);
        Assert.False(address.Loopback);

        address.Outbound = false;
        Assert.False(address.Outbound);
        Assert.Equal(WinDivertEvent.SocketConnect, address.Event);
    }

    [Fact]
    public void Socket_data_is_read_from_the_union()
    {
        var address = WinDivertAddress.FromBits(3);
        address.SetSocketData(new WinDivertSocketData
        {
            ProcessId = 1234,
            LocalAddr = AddressWords.FromIPAddress(IPAddress.Parse("192.168.1.10")),
            RemoteAddr = AddressWords.FromIPAddress(IPAddress.Parse("2001:db8::1")),
            LocalPort = 50000,
            RemotePort = 443,
            Protocol = 6,
        });

        var socket = address.Socket;
        Assert.Equal(1234u, socket.ProcessId);
        Assert.Equal(IPAddress.Parse("192.168.1.10"), socket.LocalAddress);
        Assert.Equal(IPAddress.Parse("2001:db8::1"), socket.RemoteAddress);
        Assert.Equal((50000, 443), (socket.LocalPort, socket.RemotePort));
    }

    [Fact]
    public void Ipv4_addresses_use_windivert_mapped_word_order()
    {
        var words = AddressWords.FromIPAddress(IPAddress.Parse("10.1.2.3"));

        // ::ffff:10.1.2.3 as host-order words, least significant first.
        Assert.Equal([0x0A010203u, 0x0000FFFFu, 0u, 0u], new[] { words[0], words[1], words[2], words[3] });
        Assert.Equal(AddressKey.FromIPAddress(IPAddress.Parse("10.1.2.3")), words.ToUInt128());
    }

    [Fact]
    public void Tcp_table_lookup_finds_ipv4_and_ipv6_owners()
    {
        var v4 = new byte[4 + (2 * TcpTableParser.IPv4RowSize)];
        BinaryPrimitives.WriteUInt32LittleEndian(v4, 2);
        WriteIPv4Row(v4.AsSpan(4), "10.0.0.2", 1111, "1.1.1.1", 80, pid: 7);
        WriteIPv4Row(v4.AsSpan(4 + TcpTableParser.IPv4RowSize), "10.0.0.2", 50000, "93.184.216.34", 443, pid: 42);

        Assert.Equal(42, TcpTableParser.FindOwner(v4, false, 50000, AddressKey.FromIPAddress(IPAddress.Parse("93.184.216.34")), 443));
        Assert.Equal(-1, TcpTableParser.FindOwner(v4, false, 50000, AddressKey.FromIPAddress(IPAddress.Parse("93.184.216.34")), 80));

        var v6 = new byte[4 + TcpTableParser.IPv6RowSize];
        BinaryPrimitives.WriteUInt32LittleEndian(v6, 1);
        var row = v6.AsSpan(4);
        BinaryPrimitives.WriteUInt16BigEndian(row[20..], 50001);
        IPAddress.Parse("2001:db8::1").GetAddressBytes().CopyTo(row[24..]);
        BinaryPrimitives.WriteUInt16BigEndian(row[44..], 443);
        BinaryPrimitives.WriteUInt32LittleEndian(row[52..], 99);

        Assert.Equal(99, TcpTableParser.FindOwner(v6, true, 50001, AddressKey.FromIPAddress(IPAddress.Parse("2001:db8::1")), 443));
    }

    private static void WriteIPv4Row(Span<byte> row, string local, int localPort, string remote, int remotePort, int pid)
    {
        IPAddress.Parse(local).GetAddressBytes().CopyTo(row[4..]);
        BinaryPrimitives.WriteUInt16BigEndian(row[8..], (ushort)localPort);
        IPAddress.Parse(remote).GetAddressBytes().CopyTo(row[12..]);
        BinaryPrimitives.WriteUInt16BigEndian(row[16..], (ushort)remotePort);
        BinaryPrimitives.WriteUInt32LittleEndian(row[20..], (uint)pid);
    }

    private static int Offset(ref byte start, ref byte field) => (int)Unsafe.ByteOffset(ref start, ref field);
}
