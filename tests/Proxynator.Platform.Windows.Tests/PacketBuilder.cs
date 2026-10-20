using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Proxynator.Platform.Windows.Tests;

/// <summary>Builds minimal IPv4/IPv6 TCP packets for NAT tests (checksums are left zero).</summary>
internal static class PacketBuilder
{
    public const byte Fin = 0x01;
    public const byte Syn = 0x02;
    public const byte Rst = 0x04;
    public const byte Ack = 0x10;

    public static byte[] Tcp(string source, int sourcePort, string destination, int destinationPort, byte flags, int payload = 0)
    {
        var src = IPAddress.Parse(source);
        var dst = IPAddress.Parse(destination);
        var isIPv6 = src.AddressFamily == AddressFamily.InterNetworkV6;
        var ipHeader = isIPv6 ? 40 : 20;
        var packet = new byte[ipHeader + 20 + payload];
        if (isIPv6)
        {
            packet[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)(20 + payload));
            packet[6] = 6;
            packet[7] = 64;
            src.GetAddressBytes().CopyTo(packet, 8);
            dst.GetAddressBytes().CopyTo(packet, 24);
        }
        else
        {
            packet[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), 0x4000); // don't fragment
            packet[8] = 128;
            packet[9] = 6;
            src.GetAddressBytes().CopyTo(packet, 12);
            dst.GetAddressBytes().CopyTo(packet, 16);
        }

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipHeader), (ushort)sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipHeader + 2), (ushort)destinationPort);
        packet[ipHeader + 12] = 5 << 4;
        packet[ipHeader + 13] = flags;
        return packet;
    }

    /// <summary>A UDP packet: a TCP packet with the protocol field changed (ports sit at the same offsets).</summary>
    public static byte[] Udp(string source, int sourcePort, string destination, int destinationPort)
    {
        var packet = Tcp(source, sourcePort, destination, destinationPort, 0);
        if (packet[0] >> 4 == 6)
        {
            packet[6] = 17;
        }
        else
        {
            packet[9] = 17;
        }

        return packet;
    }

    public static (string Source, int SourcePort, string Destination, int DestinationPort) Read(byte[] packet)
    {
        var isIPv6 = packet[0] >> 4 == 6;
        var ipHeader = isIPv6 ? 40 : (packet[0] & 0xF) * 4;
        var addressLength = isIPv6 ? 16 : 4;
        var source = new IPAddress(packet.AsSpan(isIPv6 ? 8 : 12, addressLength));
        var destination = new IPAddress(packet.AsSpan(isIPv6 ? 24 : 16, addressLength));
        return (
            source.ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHeader)),
            destination.ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ipHeader + 2)));
    }
}
