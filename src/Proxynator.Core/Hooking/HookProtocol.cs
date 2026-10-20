using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Proxynator.Core.Net;

namespace Proxynator.Core.Hooking;

/// <summary>
/// The registration protocol between hooked processes (the injected DLL on Windows, the preload library on Linux) and
/// the service. One session per process over a local stream (named pipe / Unix socket); the hook sends a request
/// and waits for its response, so requests never overlap within a session.
/// <code>
/// frame    = u32 length, body                      (length of body, at most MaxBodyLength)
/// body     = u8 version (1), u8 type, payload
/// requests:  Hello   u8 pointerBits
///            Connect u8 protocol (6 tcp, 17 udp), endpoint local, endpoint remote, string hostname
///            Resolve string hostname
/// responses: Hello   i32 servicePid
///            Connect u8 verdict (0 direct, 1 relay, 2 block), endpoint relay (verdict 1 only)
///            Resolve u8 faked (0 or 1), 4 bytes IPv4 address (faked only)
/// endpoint = u8 family (4 or 6), 4 or 16 address bytes, u32 scope id (family 6 only), u16 port
/// string   = u16 length, UTF-8 bytes (length 0 = absent)
/// </code>
/// All integers are little-endian. The native side lives in <c>native/windows/hook/protocol.h</c>; keep both in sync.
/// </summary>
public static class HookProtocol
{
    /// <summary>The protocol version in every message.</summary>
    public const byte Version = 1;

    /// <summary>The largest accepted message body.</summary>
    public const int MaxBodyLength = 1024;

    /// <summary>The longest hostname (DNS names are at most 253 characters).</summary>
    public const int MaxHostnameLength = 255;

    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;
    private const byte Family4 = 4;
    private const byte Family6 = 6;

    /// <summary>Parses a request body. Returns false for malformed or unsupported messages.</summary>
    public static bool TryParseRequest(ReadOnlySpan<byte> body, [NotNullWhen(true)] out HookRequest? request)
    {
        request = null;
        var reader = new Reader(body);
        if (!reader.TryByte(out var version) || version != Version || !reader.TryByte(out var type))
        {
            return false;
        }

        switch ((HookMessageType)type)
        {
            case HookMessageType.Hello when reader.TryByte(out var bits) && bits is 32 or 64:
                request = new HookHelloRequest(bits);
                break;
            case HookMessageType.Connect when reader.TryByte(out var protocol) && protocol is ProtocolTcp or ProtocolUdp &&
                                              reader.TryEndpoint(out var local) && reader.TryEndpoint(out var remote) &&
                                              reader.TryString(out var hostname):
                request = new HookConnectRequest(protocol == ProtocolTcp ? TransportProtocol.Tcp : TransportProtocol.Udp, local, remote, hostname);
                break;
            case HookMessageType.Resolve when reader.TryString(out var name) && name is not null:
                request = new HookResolveRequest(name);
                break;
            default:
                return false;
        }

        return reader.AtEnd;
    }

    /// <summary>Parses a response body. Returns false for malformed messages.</summary>
    public static bool TryParseResponse(ReadOnlySpan<byte> body, [NotNullWhen(true)] out HookResponse? response)
    {
        response = null;
        var reader = new Reader(body);
        if (!reader.TryByte(out var version) || version != Version || !reader.TryByte(out var type))
        {
            return false;
        }

        switch ((HookMessageType)type)
        {
            case HookMessageType.Hello when reader.TryInt32(out var pid):
                response = new HookHelloResponse(pid);
                break;
            case HookMessageType.Connect when reader.TryByte(out var verdict) && verdict <= (byte)HookVerdict.Block:
                IPEndPoint? relay = null;
                if ((HookVerdict)verdict == HookVerdict.Relay && !reader.TryEndpoint(out relay))
                {
                    return false;
                }

                response = new HookConnectResponse((HookVerdict)verdict, relay);
                break;
            case HookMessageType.Resolve when reader.TryByte(out var faked) && faked <= 1:
                IPAddress? address = null;
                if (faked == 1)
                {
                    if (!reader.TryBytes(4, out var bytes))
                    {
                        return false;
                    }

                    address = new IPAddress(bytes);
                }

                response = new HookResolveResponse(address);
                break;
            default:
                return false;
        }

        return reader.AtEnd;
    }

    /// <summary>Writes a request body; returns its length.</summary>
    public static int WriteRequest(HookRequest request, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(request);
        var writer = new Writer(destination);
        writer.Byte(Version);
        writer.Byte((byte)request.Type);
        switch (request)
        {
            case HookHelloRequest hello:
                writer.Byte((byte)hello.PointerBits);
                break;
            case HookConnectRequest connect:
                writer.Byte(connect.Protocol == TransportProtocol.Tcp ? ProtocolTcp : ProtocolUdp);
                writer.Endpoint(connect.LocalEndpoint);
                writer.Endpoint(connect.RemoteEndpoint);
                writer.String(connect.Hostname);
                break;
            case HookResolveRequest resolve:
                writer.String(resolve.Hostname);
                break;
            default:
                throw new ArgumentException($"Unknown request {request.GetType().Name}.", nameof(request));
        }

        return writer.Length;
    }

    /// <summary>Writes a response body; returns its length.</summary>
    public static int WriteResponse(HookResponse response, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(response);
        var writer = new Writer(destination);
        writer.Byte(Version);
        writer.Byte((byte)response.Type);
        switch (response)
        {
            case HookHelloResponse hello:
                writer.Int32(hello.ServiceProcessId);
                break;
            case HookConnectResponse connect:
                writer.Byte((byte)connect.Verdict);
                if (connect.Verdict == HookVerdict.Relay)
                {
                    writer.Endpoint(connect.RelayEndpoint ?? throw new ArgumentException("A relay verdict needs a relay endpoint.", nameof(response)));
                }

                break;
            case HookResolveResponse resolve:
                if (resolve.FakeAddress is { } address)
                {
                    if (address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        throw new ArgumentException("Fake addresses are IPv4.", nameof(response));
                    }

                    writer.Byte(1);
                    writer.Address(address);
                }
                else
                {
                    writer.Byte(0);
                }

                break;
            default:
                throw new ArgumentException($"Unknown response {response.GetType().Name}.", nameof(response));
        }

        return writer.Length;
    }

    /// <summary>
    /// Reads one frame into <paramref name="buffer"/> (at least <see cref="MaxBodyLength"/> bytes). Returns the body
    /// length, 0 at a clean end of stream, or -1 when the frame is too large or the stream ends mid-frame.
    /// </summary>
    public static async ValueTask<int> ReadFrameAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = buffer[..4];
        var read = await stream.ReadAtLeastAsync(header, 4, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return 0;
        }

        if (read < 4)
        {
            return -1;
        }

        var length = BinaryPrimitives.ReadUInt32LittleEndian(header.Span);
        if (length is 0 or > MaxBodyLength || length > buffer.Length)
        {
            return -1;
        }

        read = await stream.ReadAtLeastAsync(buffer[..(int)length], (int)length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        return read == length ? (int)length : -1;
    }

    /// <summary>Writes one frame (length prefix + body).</summary>
    public static async ValueTask WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)body.Length);
        body.CopyTo(frame.AsMemory(4));
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private ref struct Reader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> data = data;
        private int position;

        public readonly bool AtEnd => position == data.Length;

        public bool TryByte(out byte value)
        {
            if (position >= data.Length)
            {
                value = 0;
                return false;
            }

            value = data[position++];
            return true;
        }

        public bool TryBytes(int count, out ReadOnlySpan<byte> value)
        {
            if (data.Length - position < count)
            {
                value = default;
                return false;
            }

            value = data.Slice(position, count);
            position += count;
            return true;
        }

        public bool TryUInt16(out ushort value)
        {
            value = 0;
            if (!TryBytes(2, out var bytes))
            {
                return false;
            }

            value = BinaryPrimitives.ReadUInt16LittleEndian(bytes);
            return true;
        }

        public bool TryInt32(out int value)
        {
            value = 0;
            if (!TryBytes(4, out var bytes))
            {
                return false;
            }

            value = BinaryPrimitives.ReadInt32LittleEndian(bytes);
            return true;
        }

        public bool TryEndpoint([NotNullWhen(true)] out IPEndPoint? endpoint)
        {
            endpoint = null;
            if (!TryByte(out var family) || family is not (Family4 or Family6))
            {
                return false;
            }

            if (!TryBytes(family == Family4 ? 4 : 16, out var addressBytes))
            {
                return false;
            }

            var address = new IPAddress(addressBytes);
            if (family == Family6)
            {
                if (!TryInt32(out var scope))
                {
                    return false;
                }

                address.ScopeId = (uint)scope;
            }

            if (!TryUInt16(out var port))
            {
                return false;
            }

            endpoint = new IPEndPoint(address, port);
            return true;
        }

        public bool TryString(out string? value)
        {
            value = null;
            if (!TryUInt16(out var length) || length > MaxHostnameLength || !TryBytes(length, out var bytes))
            {
                return false;
            }

            if (length > 0)
            {
                try
                {
                    value = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes);
                }
                catch (ArgumentException)
                {
                    return false;
                }
            }

            return true;
        }
    }

    private ref struct Writer(Span<byte> data)
    {
        private readonly Span<byte> data = data;

        public int Length { get; private set; }

        public void Byte(byte value) => data[Length++] = value;

        public void Int32(int value)
        {
            BinaryPrimitives.WriteInt32LittleEndian(data[Length..], value);
            Length += 4;
        }

        public void UInt16(ushort value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(data[Length..], value);
            Length += 2;
        }

        public void Address(IPAddress address)
        {
            if (!address.TryWriteBytes(data[Length..], out var written))
            {
                throw new ArgumentException("The destination is too small.", nameof(address));
            }

            Length += written;
        }

        public void Endpoint(IPEndPoint endpoint)
        {
            var isV6 = endpoint.AddressFamily == AddressFamily.InterNetworkV6;
            Byte(isV6 ? Family6 : Family4);
            Address(endpoint.Address);
            if (isV6)
            {
                Int32((int)endpoint.Address.ScopeId);
            }

            UInt16((ushort)endpoint.Port);
        }

        public void String(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                UInt16(0);
                return;
            }

            var length = Encoding.UTF8.GetByteCount(value);
            if (length > MaxHostnameLength)
            {
                throw new ArgumentException($"Strings are limited to {MaxHostnameLength} UTF-8 bytes.", nameof(value));
            }

            UInt16((ushort)length);
            Length += Encoding.UTF8.GetBytes(value, data[Length..]);
        }
    }
}
