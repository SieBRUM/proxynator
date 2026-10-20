using System.Buffers.Binary;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Packets;

/// <summary>
/// A mutable view of an IPv4 or IPv6 packet carrying TCP or UDP. Only the fields the NAT needs are exposed;
/// checksums are recalculated by WinDivert after rewriting. Ports sit at the same offsets in both headers.
/// </summary>
internal ref struct TransportPacket
{
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;
    private const byte FlagFin = 0x01;
    private const byte FlagSyn = 0x02;
    private const byte FlagRst = 0x04;
    private const byte FlagAck = 0x10;

    private readonly Span<byte> packet;
    private readonly int sourceOffset;
    private readonly int destinationOffset;
    private readonly int addressLength;
    private readonly int tcpOffset;

    private TransportPacket(Span<byte> packet, bool isIPv6, bool isUdp, int sourceOffset, int destinationOffset, int tcpOffset)
    {
        this.packet = packet;
        IsIPv6 = isIPv6;
        IsUdp = isUdp;
        this.sourceOffset = sourceOffset;
        this.destinationOffset = destinationOffset;
        addressLength = isIPv6 ? 16 : 4;
        this.tcpOffset = tcpOffset;
    }

    public bool IsIPv6 { get; }

    /// <summary>UDP rather than TCP. TCP flags read as false for UDP.</summary>
    public bool IsUdp { get; }

    public readonly UInt128 SourceAddress => ReadAddress(sourceOffset);

    public readonly UInt128 DestinationAddress => ReadAddress(destinationOffset);

    public int SourcePort
    {
        readonly get => BinaryPrimitives.ReadUInt16BigEndian(packet[tcpOffset..]);
        set => BinaryPrimitives.WriteUInt16BigEndian(packet[tcpOffset..], (ushort)value);
    }

    public int DestinationPort
    {
        readonly get => BinaryPrimitives.ReadUInt16BigEndian(packet[(tcpOffset + 2)..]);
        set => BinaryPrimitives.WriteUInt16BigEndian(packet[(tcpOffset + 2)..], (ushort)value);
    }

    public readonly bool IsSyn => (Flags & FlagSyn) != 0;

    public readonly bool IsAck => (Flags & FlagAck) != 0;

    public readonly bool IsFin => (Flags & FlagFin) != 0;

    public readonly bool IsRst => (Flags & FlagRst) != 0;

    /// <summary>A SYN without ACK: the first packet of a new outbound connection.</summary>
    public readonly bool IsConnectionAttempt => IsSyn && !IsAck;

    private readonly byte Flags => IsUdp ? (byte)0 : packet[tcpOffset + 13];

    /// <summary>
    /// Parses <paramref name="packet"/>. Returns <see langword="false"/> for other protocols, IP fragments and
    /// truncated packets, which the NAT leaves alone.
    /// </summary>
    public static bool TryParse(Span<byte> packet, out TransportPacket tcp)
    {
        tcp = default;
        if (packet.Length < 20)
        {
            return false;
        }

        switch (packet[0] >> 4)
        {
            case 4:
            {
                var headerLength = (packet[0] & 0x0F) * 4;
                var fragment = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
                var moreFragments = (fragment & 0x2000) != 0;
                var fragmentOffset = fragment & 0x1FFF;
                var protocol = packet[9];
                if (headerLength < 20 || protocol is not (ProtocolTcp or ProtocolUdp) || moreFragments || fragmentOffset != 0 ||
                    packet.Length < headerLength + MinimumHeader(protocol))
                {
                    return false;
                }

                tcp = new TransportPacket(packet, isIPv6: false, protocol == ProtocolUdp, 12, 16, headerLength);
                return true;
            }

            case 6:
            {
                if (packet.Length < 40)
                {
                    return false;
                }

                var nextHeader = packet[6];
                var offset = 40;
                while (nextHeader is 0 or 43 or 60) // hop-by-hop, routing, destination options
                {
                    if (packet.Length < offset + 8)
                    {
                        return false;
                    }

                    nextHeader = packet[offset];
                    offset += (packet[offset + 1] + 1) * 8;
                }

                if (nextHeader is not (ProtocolTcp or ProtocolUdp) || packet.Length < offset + MinimumHeader(nextHeader))
                {
                    return false;
                }

                tcp = new TransportPacket(packet, isIPv6: true, nextHeader == ProtocolUdp, 8, 24, offset);
                return true;
            }

            default:
                return false;
        }
    }

    private static int MinimumHeader(byte protocol) => protocol == ProtocolUdp ? 8 : 20;

    /// <summary>Swaps the source and destination addresses (ports are left alone).</summary>
    public readonly void SwapAddresses()
    {
        Span<byte> temporary = stackalloc byte[16];
        var source = packet.Slice(sourceOffset, addressLength);
        var destination = packet.Slice(destinationOffset, addressLength);
        source.CopyTo(temporary);
        destination.CopyTo(source);
        temporary[..addressLength].CopyTo(destination);
    }

    private readonly UInt128 ReadAddress(int offset) => IsIPv6
        ? AddressKey.FromIPv6(packet.Slice(offset, 16))
        : AddressKey.FromIPv4(packet.Slice(offset, 4));
}
