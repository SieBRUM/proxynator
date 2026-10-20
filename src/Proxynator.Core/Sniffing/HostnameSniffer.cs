using System.Buffers.Binary;
using System.Text;
using Proxynator.Core.Net;

namespace Proxynator.Core.Sniffing;

/// <summary>
/// Recovers the destination hostname from the first client bytes of a connection: the SNI extension of a TLS
/// ClientHello, or the <c>Host</c> header of a plain HTTP request.
/// </summary>
public static class HostnameSniffer
{
    /// <summary>The most data worth buffering while looking for a hostname.</summary>
    public const int MaxSniffLength = 16 * 1024;

    private const byte TlsHandshake = 0x16;
    private const byte TlsClientHello = 0x01;
    private const ushort TlsServerNameExtension = 0x0000;
    private const byte TlsHostNameType = 0x00;

    private static readonly string[] HttpMethods = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "];

    /// <summary>Inspects <paramref name="data"/>, the bytes the client has sent so far.</summary>
    public static SniffStatus TrySniff(ReadOnlySpan<byte> data, out string? hostname)
    {
        hostname = null;
        if (data.IsEmpty)
        {
            return SniffStatus.NeedMoreData;
        }

        if (data[0] == TlsHandshake)
        {
            return TrySniffTls(data, out hostname);
        }

        return MatchHttpMethod(data) switch
        {
            SniffStatus.Found => TrySniffHttp(data, out hostname),
            var status => status,
        };
    }

    private static SniffStatus TrySniffTls(ReadOnlySpan<byte> data, out string? hostname)
    {
        hostname = null;
        if (data.Length < 5)
        {
            return SniffStatus.NeedMoreData;
        }

        if (data[1] != 3)
        {
            return SniffStatus.NotFound;
        }

        int recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..]);
        if (data.Length - 5 < recordLength)
        {
            return 5 + recordLength > MaxSniffLength ? SniffStatus.NotFound : SniffStatus.NeedMoreData;
        }

        var reader = new SpanReader(data.Slice(5, recordLength));
        if (!reader.TryReadByte(out var handshakeType) || handshakeType != TlsClientHello ||
            !reader.TryReadUInt24(out var helloLength) || !reader.TryReadSlice(helloLength, out var hello))
        {
            // Not a ClientHello, or one fragmented across several records (not supported).
            return SniffStatus.NotFound;
        }

        reader = new SpanReader(hello);
        if (!reader.TrySkip(2 + 32) ||
            !reader.TryReadByte(out var sessionIdLength) || !reader.TrySkip(sessionIdLength) ||
            !reader.TryReadUInt16(out var cipherSuitesLength) || !reader.TrySkip(cipherSuitesLength) ||
            !reader.TryReadByte(out var compressionLength) || !reader.TrySkip(compressionLength) ||
            !reader.TryReadUInt16(out var extensionsLength) || !reader.TryReadSlice(extensionsLength, out var extensions))
        {
            return SniffStatus.NotFound;
        }

        reader = new SpanReader(extensions);
        while (reader.TryReadUInt16(out var extensionType) && reader.TryReadUInt16(out var extensionLength) &&
               reader.TryReadSlice(extensionLength, out var extension))
        {
            if (extensionType == TlsServerNameExtension)
            {
                return TryReadServerName(extension, out hostname);
            }
        }

        return SniffStatus.NotFound;
    }

    private static SniffStatus TryReadServerName(ReadOnlySpan<byte> extension, out string? hostname)
    {
        hostname = null;
        var reader = new SpanReader(extension);
        if (!reader.TryReadUInt16(out var listLength) || !reader.TryReadSlice(listLength, out var list))
        {
            return SniffStatus.NotFound;
        }

        reader = new SpanReader(list);
        while (reader.TryReadByte(out var nameType) && reader.TryReadUInt16(out var nameLength) && reader.TryReadSlice(nameLength, out var name))
        {
            if (nameType == TlsHostNameType)
            {
                return TryAcceptHostname(Encoding.ASCII.GetString(name), out hostname);
            }
        }

        return SniffStatus.NotFound;
    }

    /// <summary>Returns Found for a complete known method, NeedMoreData for a prefix of one, else NotFound.</summary>
    private static SniffStatus MatchHttpMethod(ReadOnlySpan<byte> data)
    {
        var needMore = false;
        foreach (var method in HttpMethods)
        {
            var length = Math.Min(method.Length, data.Length);
            if (!Ascii.Equals(data[..length], method.AsSpan(0, length)))
            {
                continue;
            }

            if (data.Length >= method.Length)
            {
                return SniffStatus.Found;
            }

            needMore = true;
        }

        return needMore ? SniffStatus.NeedMoreData : SniffStatus.NotFound;
    }

    private static SniffStatus TrySniffHttp(ReadOnlySpan<byte> data, out string? hostname)
    {
        hostname = null;
        var totalLength = data.Length;
        ReadOnlySpan<byte> crlf = "\r\n"u8;
        ReadOnlySpan<byte> hostHeader = "host:"u8;

        // Skip the request line; only complete header lines are considered.
        var lineEnd = data.IndexOf(crlf);
        while (lineEnd >= 0)
        {
            data = data[(lineEnd + 2)..];
            lineEnd = data.IndexOf(crlf);
            if (lineEnd == 0)
            {
                return SniffStatus.NotFound;
            }

            if (lineEnd > 0 && lineEnd >= hostHeader.Length && Ascii.EqualsIgnoreCase(data[..hostHeader.Length], hostHeader))
            {
                var value = Encoding.ASCII.GetString(data[hostHeader.Length..lineEnd]).Trim();
                return TryAcceptHostname(StripPort(value), out hostname);
            }
        }

        return totalLength >= MaxSniffLength ? SniffStatus.NotFound : SniffStatus.NeedMoreData;
    }

    private static string StripPort(string hostValue)
    {
        if (hostValue.StartsWith('['))
        {
            return hostValue; // IPv6 literal, rejected below
        }

        var colon = hostValue.LastIndexOf(':');
        return colon >= 0 ? hostValue[..colon] : hostValue;
    }

    private static SniffStatus TryAcceptHostname(string candidate, out string? hostname)
    {
        candidate = candidate.TrimEnd('.');
        var isAddressLiteral = System.Net.IPAddress.TryParse(candidate.Trim('[', ']'), out _);
        if (!isAddressLiteral && TargetEndpoint.IsValidHostName(candidate))
        {
            hostname = candidate.ToLowerInvariant();
            return SniffStatus.Found;
        }

        hostname = null;
        return SniffStatus.NotFound;
    }

    private ref struct SpanReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> remaining = data;

        public bool TryReadByte(out byte value)
        {
            value = 0;
            if (remaining.IsEmpty)
            {
                return false;
            }

            value = remaining[0];
            remaining = remaining[1..];
            return true;
        }

        public bool TryReadUInt16(out int value)
        {
            value = 0;
            if (remaining.Length < 2)
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt16BigEndian(remaining);
            remaining = remaining[2..];
            return true;
        }

        public bool TryReadUInt24(out int value)
        {
            value = 0;
            if (remaining.Length < 3)
            {
                return false;
            }

            value = (remaining[0] << 16) | (remaining[1] << 8) | remaining[2];
            remaining = remaining[3..];
            return true;
        }

        public bool TrySkip(int count) => TryReadSlice(count, out _);

        public bool TryReadSlice(int count, out ReadOnlySpan<byte> slice)
        {
            slice = default;
            if (remaining.Length < count)
            {
                return false;
            }

            slice = remaining[..count];
            remaining = remaining[count..];
            return true;
        }
    }
}
