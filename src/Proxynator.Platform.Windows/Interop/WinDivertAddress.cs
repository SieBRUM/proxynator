using System.Buffers.Binary;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Proxynator.Core.Net;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>
/// <c>WINDIVERT_ADDRESS</c> (80 bytes): timestamp, a 32-bit bitfield (layer, event, flags), a reserved word and a
/// 64-byte union of per-layer data.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WinDivertAddress
{
    public const int Size = 80;

    private const int OutboundBit = 17;

    public long Timestamp;
    private uint bits;
    private readonly uint reserved2;
    private Union64 data;

    public readonly WinDivertLayer Layer => (WinDivertLayer)(byte)bits;

    public readonly WinDivertEvent Event => (WinDivertEvent)(byte)(bits >> 8);

    public readonly bool Sniffed => GetBit(16);

    public bool Outbound
    {
        readonly get => GetBit(OutboundBit);
        set => bits = value ? bits | (1u << OutboundBit) : bits & ~(1u << OutboundBit);
    }

    public readonly bool Loopback => GetBit(18);

    public readonly bool Impostor => GetBit(19);

    public readonly bool IPv6 => GetBit(20);

    /// <summary><c>Network.IfIdx</c> (network layers only).</summary>
    public readonly uint InterfaceIndex => BinaryPrimitives.ReadUInt32LittleEndian(data);

    /// <summary><c>Socket.*</c> / <c>Flow.*</c> data (socket and flow layers only).</summary>
    public readonly WinDivertSocketData Socket => MemoryMarshal.Read<WinDivertSocketData>(data);

    /// <summary>Creates an address with the given raw bitfield, for tests.</summary>
    internal static WinDivertAddress FromBits(uint bits) => new() { bits = bits };

    /// <summary>Writes socket data into the union, for tests.</summary>
    internal void SetSocketData(in WinDivertSocketData socket) => MemoryMarshal.Write(data, in socket);

    private readonly bool GetBit(int bit) => (bits & (1u << bit)) != 0;

    [InlineArray(64)]
    private struct Union64
    {
        private byte element;
    }
}

/// <summary><c>WINDIVERT_DATA_SOCKET</c> / <c>WINDIVERT_DATA_FLOW</c>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WinDivertSocketData
{
    public ulong EndpointId;
    public ulong ParentEndpointId;
    public uint ProcessId;
    public AddressWords LocalAddr;
    public AddressWords RemoteAddr;
    public ushort LocalPort;
    public ushort RemotePort;
    public byte Protocol;

    public readonly IPAddress LocalAddress => LocalAddr.ToIPAddress();

    public readonly IPAddress RemoteAddress => RemoteAddr.ToIPAddress();
}

/// <summary>
/// An IPv6 address as four host-order 32-bit words, most significant word last (WinDivert's format). IPv4
/// addresses are IPv4-mapped (<c>::ffff:a.b.c.d</c>).
/// </summary>
[InlineArray(4)]
internal struct AddressWords
{
    private uint element;

    public static AddressWords FromIPAddress(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        (address.IsIPv4MappedToIPv6 || address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? address
            : address.MapToIPv6()).TryWriteBytes(bytes, out _);
        var words = default(AddressWords);
        for (var i = 0; i < 4; i++)
        {
            words[3 - i] = BinaryPrimitives.ReadUInt32BigEndian(bytes[(i * 4)..]);
        }

        return words;
    }

    public readonly IPAddress ToIPAddress()
    {
        Span<byte> bytes = stackalloc byte[16];
        for (var i = 0; i < 4; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes[(i * 4)..], this[3 - i]);
        }

        return new IPAddress(bytes).Normalize();
    }

    /// <summary>The address as a 128-bit big-endian number (IPv4 as IPv4-mapped), for allocation-free keys.</summary>
    public readonly UInt128 ToUInt128() => new(((ulong)this[3] << 32) | this[2], ((ulong)this[1] << 32) | this[0]);
}
