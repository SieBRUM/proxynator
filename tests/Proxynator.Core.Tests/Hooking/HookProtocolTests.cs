using System.Net;
using Proxynator.Core.Hooking;
using Proxynator.Core.Net;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Hooking;

public sealed class HookProtocolTests
{
    public static TheoryData<HookRequest> Requests() =>
    [
        new HookHelloRequest(32),
        new HookHelloRequest(64),
        new HookConnectRequest(TransportProtocol.Tcp, IPEndPoint.Parse("127.0.0.1:50000"), IPEndPoint.Parse("93.184.215.14:443"), "example.com"),
        new HookConnectRequest(TransportProtocol.Udp, IPEndPoint.Parse("0.0.0.0:0"), IPEndPoint.Parse("8.8.8.8:53"), null),
        new HookConnectRequest(TransportProtocol.Tcp, IPEndPoint.Parse("[::1]:50001"), IPEndPoint.Parse("[2001:db8::1]:80"), "bücher.example"),
        new HookResolveRequest("dc01.corp.local"),
    ];

    public static TheoryData<HookResponse> Responses() =>
    [
        new HookHelloResponse(4242),
        HookConnectResponse.Direct,
        HookConnectResponse.Block,
        new HookConnectResponse(HookVerdict.Relay, IPEndPoint.Parse("127.0.0.1:61000")),
        new HookConnectResponse(HookVerdict.Relay, IPEndPoint.Parse("[::1]:61001")),
        HookResolveResponse.ResolveNormally,
        new HookResolveResponse(IPAddress.Parse("198.18.0.7")),
    ];

    [Theory]
    [MemberData(nameof(Requests))]
    public void Requests_round_trip(HookRequest request)
    {
        var buffer = new byte[HookProtocol.MaxBodyLength];
        var length = HookProtocol.WriteRequest(request, buffer);

        Assert.True(HookProtocol.TryParseRequest(buffer.AsSpan(0, length), out var parsed));
        Assert.Equal(request, parsed);
    }

    [Theory]
    [MemberData(nameof(Responses))]
    public void Responses_round_trip(HookResponse response)
    {
        var buffer = new byte[HookProtocol.MaxBodyLength];
        var length = HookProtocol.WriteResponse(response, buffer);

        Assert.True(HookProtocol.TryParseResponse(buffer.AsSpan(0, length), out var parsed));
        Assert.Equal(response, parsed);
    }

    [Fact]
    public void The_wire_format_matches_the_native_hook()
    {
        // native/windows/hook/src/protocol.h: version, type, protocol, endpoints (family, address, port LE), string.
        var request = new HookConnectRequest(TransportProtocol.Tcp, IPEndPoint.Parse("127.0.0.1:513"), IPEndPoint.Parse("10.0.0.1:443"), "ab");
        var buffer = new byte[64];
        var length = HookProtocol.WriteRequest(request, buffer);

        Assert.Equal(
            new byte[] { 1, 2, 6, 4, 127, 0, 0, 1, 0x01, 0x02, 4, 10, 0, 0, 1, 0xBB, 0x01, 2, 0, (byte)'a', (byte)'b' },
            buffer[..length]);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 2, 1, 64 })] // unknown version
    [InlineData(new byte[] { 1, 9 })] // unknown type
    [InlineData(new byte[] { 1, 1, 16 })] // bad bitness
    [InlineData(new byte[] { 1, 1, 64, 0 })] // trailing data
    [InlineData(new byte[] { 1, 2, 6, 4, 127, 0, 0 })] // truncated endpoint
    [InlineData(new byte[] { 1, 2, 1, 4, 127, 0, 0, 1, 0, 1, 4, 10, 0, 0, 1, 0, 1, 0, 0 })] // unknown protocol
    [InlineData(new byte[] { 1, 3, 0, 0 })] // resolve without a name
    [InlineData(new byte[] { 1, 3, 2, 0, 0xC3, 0x28 })] // invalid UTF-8
    public void Malformed_requests_are_rejected(byte[] body)
    {
        Assert.False(HookProtocol.TryParseRequest(body, out _));
    }

    [Fact]
    public async Task Frames_are_length_prefixed_and_bounded()
    {
        using var stream = new MemoryStream();
        await HookProtocol.WriteFrameAsync(stream, new byte[] { 1, 1, 64 }, TestTimeout.Token());
        stream.Write([0xFF, 0xFF, 0, 0]); // a frame announcing 65535 bytes
        stream.Position = 0;
        var buffer = new byte[HookProtocol.MaxBodyLength];

        Assert.Equal(3, await HookProtocol.ReadFrameAsync(stream, buffer, TestTimeout.Token()));
        Assert.Equal(-1, await HookProtocol.ReadFrameAsync(stream, buffer, TestTimeout.Token()));
        Assert.Equal(0, await HookProtocol.ReadFrameAsync(stream, buffer, TestTimeout.Token()));
    }
}
