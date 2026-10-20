using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Proxynator.Platform.Windows.Interop;

/// <summary>
/// Allocation-free representation of an IP address as a 128-bit big-endian number; IPv4 addresses are stored
/// IPv4-mapped (<c>::ffff:a.b.c.d</c>) so both families share one key space.
/// </summary>
internal static class AddressKey
{
    private static readonly UInt128 IPv4MappedPrefix = (UInt128)0xFFFF << 32;

    public static UInt128 FromIPv4(ReadOnlySpan<byte> address) => IPv4MappedPrefix | BinaryPrimitives.ReadUInt32BigEndian(address);

    public static UInt128 FromIPv6(ReadOnlySpan<byte> address) => BinaryPrimitives.ReadUInt128BigEndian(address);

    public static UInt128 FromIPAddress(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out var written);
        return address.AddressFamily == AddressFamily.InterNetwork ? FromIPv4(bytes[..written]) : FromIPv6(bytes);
    }

    public static IPAddress ToIPAddress(UInt128 key)
    {
        if (key >> 32 == 0xFFFF)
        {
            Span<byte> v4 = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(v4, (uint)key);
            return new IPAddress(v4);
        }

        Span<byte> v6 = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(v6, key);
        return new IPAddress(v6);
    }
}
