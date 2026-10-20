using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Proxynator.Core.NameResolution;

/// <summary>The small subset of the DNS wire format (RFC 1035) that fake-IP DNS and the upstream resolver need.</summary>
internal static class DnsWire
{
    public const ushort TypeA = 1;
    public const ushort TypeAaaa = 28;
    public const ushort TypeSvcb = 64;
    public const ushort TypeHttps = 65;
    public const ushort ClassIn = 1;

    private const int HeaderLength = 12;
    private const ushort FlagResponse = 0x8000;
    private const ushort FlagRecursionDesired = 0x0100;
    private const ushort FlagRecursionAvailable = 0x0080;

    /// <summary>Parses a standard query (QR=0, OPCODE=0) and its first question.</summary>
    public static bool TryParseQuery(ReadOnlySpan<byte> message, out DnsQuestion question)
    {
        question = default;
        if (message.Length < HeaderLength)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        if ((flags & FlagResponse) != 0 || ((flags >> 11) & 0xF) != 0 || BinaryPrimitives.ReadUInt16BigEndian(message[4..]) == 0)
        {
            return false;
        }

        var offset = HeaderLength;
        if (!TryReadName(message, ref offset, out var name) || offset + 4 > message.Length)
        {
            return false;
        }

        question = new DnsQuestion(
            BinaryPrimitives.ReadUInt16BigEndian(message),
            (flags & FlagRecursionDesired) != 0,
            name,
            BinaryPrimitives.ReadUInt16BigEndian(message[offset..]),
            BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]),
            offset + 4);
        return true;
    }

    /// <summary>
    /// Builds a NOERROR response to <paramref name="query"/>: one A record with <paramref name="address"/>, or no
    /// records at all (NODATA) when it is <see langword="null"/>.
    /// </summary>
    public static byte[] BuildResponse(ReadOnlySpan<byte> query, DnsQuestion question, IPAddress? address, uint ttl)
    {
        var questionBytes = query[HeaderLength..question.End];
        var response = new byte[HeaderLength + questionBytes.Length + (address is null ? 0 : 16)];
        var span = response.AsSpan();
        BinaryPrimitives.WriteUInt16BigEndian(span, question.Id);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], (ushort)(FlagResponse | FlagRecursionAvailable | (question.RecursionDesired ? FlagRecursionDesired : 0)));
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(span[6..], (ushort)(address is null ? 0 : 1));
        questionBytes.CopyTo(span[HeaderLength..]);

        if (address is not null)
        {
            var answer = span[(HeaderLength + questionBytes.Length)..];
            BinaryPrimitives.WriteUInt16BigEndian(answer, 0xC000 | HeaderLength); // pointer to the question name
            BinaryPrimitives.WriteUInt16BigEndian(answer[2..], TypeA);
            BinaryPrimitives.WriteUInt16BigEndian(answer[4..], ClassIn);
            BinaryPrimitives.WriteUInt32BigEndian(answer[6..], ttl);
            BinaryPrimitives.WriteUInt16BigEndian(answer[10..], 4);
            address.TryWriteBytes(answer[12..], out _);
        }

        return response;
    }

    /// <summary>Builds a recursive query for <paramref name="name"/>.</summary>
    public static byte[] BuildQuery(ushort id, string name, ushort type)
    {
        var labels = name.TrimEnd('.').Split('.');
        var length = HeaderLength + labels.Sum(l => l.Length + 1) + 1 + 4;
        var query = new byte[length];
        var span = query.AsSpan();
        BinaryPrimitives.WriteUInt16BigEndian(span, id);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..], FlagRecursionDesired);
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);
        var offset = HeaderLength;
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63)
            {
                throw new ArgumentException($"'{name}' is not a valid DNS name.", nameof(name));
            }

            query[offset++] = (byte)label.Length;
            offset += Encoding.ASCII.GetBytes(label, span[offset..]);
        }

        query[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(span[offset..], type);
        BinaryPrimitives.WriteUInt16BigEndian(span[(offset + 2)..], ClassIn);
        return query;
    }

    /// <summary>
    /// Extracts the A/AAAA addresses from a response to the query with <paramref name="id"/>. Returns
    /// <see langword="false"/> if the message is not a valid response to that query.
    /// </summary>
    public static bool TryParseAddresses(ReadOnlySpan<byte> message, ushort id, out List<IPAddress> addresses, out int responseCode)
    {
        addresses = [];
        responseCode = -1;
        if (message.Length < HeaderLength || BinaryPrimitives.ReadUInt16BigEndian(message) != id)
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        if ((flags & FlagResponse) == 0)
        {
            return false;
        }

        responseCode = flags & 0xF;
        int questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        int answers = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
        var offset = HeaderLength;
        for (var i = 0; i < questions; i++)
        {
            if (!TryReadName(message, ref offset, out _) || (offset += 4) > message.Length)
            {
                return false;
            }
        }

        for (var i = 0; i < answers; i++)
        {
            if (!TryReadName(message, ref offset, out _) || offset + 10 > message.Length)
            {
                return false;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
            offset += 10;
            if (offset + dataLength > message.Length)
            {
                return false;
            }

            if ((type == TypeA && dataLength == 4) || (type == TypeAaaa && dataLength == 16))
            {
                addresses.Add(new IPAddress(message.Slice(offset, dataLength)));
            }

            offset += dataLength;
        }

        return true;
    }

    /// <summary>Reads a (possibly compressed) name; <paramref name="offset"/> moves past it.</summary>
    public static bool TryReadName(ReadOnlySpan<byte> message, ref int offset, out string name)
    {
        name = string.Empty;
        var builder = new StringBuilder();
        var position = offset;
        var jumped = false;
        var jumps = 0;
        while (true)
        {
            if (position >= message.Length)
            {
                return false;
            }

            var length = message[position];
            if (length == 0)
            {
                position++;
                break;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (position + 1 >= message.Length || ++jumps > 16)
                {
                    return false;
                }

                if (!jumped)
                {
                    offset = position + 2;
                    jumped = true;
                }

                position = ((length & 0x3F) << 8) | message[position + 1];
                continue;
            }

            if ((length & 0xC0) != 0 || position + 1 + length > message.Length)
            {
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(message.Slice(position + 1, length)));
            if (builder.Length > 253)
            {
                return false;
            }

            position += 1 + length;
        }

        if (!jumped)
        {
            offset = position;
        }

        name = builder.ToString().ToLowerInvariant();
        return true;
    }

    public static AddressFamily FamilyFor(ushort type) => type == TypeAaaa ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
}
