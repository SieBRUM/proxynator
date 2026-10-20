using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Proxynator.Core.Configuration;
using Proxynator.Core.Hooking;
using Proxynator.Core.Net;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Hooking;

/// <summary>
/// What the native hook does, end to end over a real session: bind, ask the service, connect to the relay it names.
/// </summary>
public sealed class HookedRelayTests : IAsyncLifetime
{
    private const int HookedPid = 20;

    private readonly EchoServer echo = new();
    private readonly OriginalDestinationTable table = new();
    private readonly CancellationTokenSource stop = new();
    private FakeProxyServer socks = null!;
    private RelayServer relay = null!;
    private HookRequestHandler handler = null!;
    private Socket sessionServer = null!;
    private Socket sessionClient = null!;
    private NetworkStream hookStream = null!;
    private Task session = null!;

    public async ValueTask InitializeAsync()
    {
        socks = new FakeProxyServer(FakeProxyKind.Socks5) { Resolve = _ => echo.Endpoint };
        var config = Configs.Minimal() with
        {
            Proxies = [Configs.Proxy("socks", ProxyType.Socks5, socks.Endpoint.Port)],
            Rules = [Configs.Rule("all", RuleActionType.Proxy, "socks")],
        };
        var store = new ConfigurationStore(config);
        var processes = new StaticProcessInfoProvider(new ProcessInfo(HookedPid, "hooked.exe", null));
        relay = new RelayServer(store, table, processes, new ConnectionTracker(), NullLogger<RelayServer>.Instance);
        relay.Start([new IPEndPoint(IPAddress.Loopback, 0)]);
        handler = new HookRequestHandler(new CaptureContext(store, table, relay.LocalEndpoints, ServiceProcessId: 1), processes, NullLogger.Instance);
        await handler.InitializeAsync(TestTimeout.Token());

        // The transport: any stream works; the Windows backend uses a named pipe.
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();
        sessionClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await sessionClient.ConnectAsync(listener.LocalEndPoint!, TestTimeout.Token());
        sessionServer = await listener.AcceptAsync(TestTimeout.Token());
        session = HookSession.RunAsync(new NetworkStream(sessionServer), HookedPid, handler, NullLogger.Instance, stop.Token);
        hookStream = new NetworkStream(sessionClient);
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        sessionClient.Dispose();
        await session.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        sessionServer.Dispose();
        handler.Dispose();
        await relay.DisposeAsync();
        await socks.DisposeAsync();
        await echo.DisposeAsync();
        stop.Dispose();
    }

    private async Task<HookResponse> AskAsync(HookRequest request, CancellationToken ct)
    {
        var buffer = new byte[HookProtocol.MaxBodyLength];
        var length = HookProtocol.WriteRequest(request, buffer);
        await HookProtocol.WriteFrameAsync(hookStream, buffer.AsMemory(0, length), ct);
        length = await HookProtocol.ReadFrameAsync(hookStream, buffer, ct);
        Assert.True(HookProtocol.TryParseResponse(buffer.AsSpan(0, length), out var response));
        return response;
    }

    /// <summary>Binds to the wildcard address like the hook, reports loopback as the local address, connects where told.</summary>
    private async Task<Socket> HookedConnectAsync(IPEndPoint destination, string? hostname, CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        var local = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)socket.LocalEndPoint!).Port);
        Assert.IsType<HookHelloResponse>(await AskAsync(new HookHelloRequest(64), ct));
        var response = Assert.IsType<HookConnectResponse>(await AskAsync(new HookConnectRequest(TransportProtocol.Tcp, local, destination, hostname), ct));
        Assert.Equal(HookVerdict.Relay, response.Verdict);
        await socket.ConnectAsync(response.RelayEndpoint!, ct);
        return socket;
    }

    [Fact]
    public async Task The_hostname_hint_reaches_the_proxy_when_nothing_can_be_sniffed()
    {
        var ct = TestTimeout.Token();
        using var client = await HookedConnectAsync(IPEndPoint.Parse("203.0.113.5:445"), "dc01.corp.local", ct);

        await client.SendAsync("smb"u8.ToArray(), ct);

        Assert.Equal("smb", await client.ReceiveStringAsync(3, ct));
        var request = Assert.Single(socks.Requests);
        Assert.Equal(("dc01.corp.local", 445), (request.Host, request.Port));
    }

    [Fact]
    public async Task A_sniffed_hostname_overrides_the_hint()
    {
        var ct = TestTimeout.Token();
        using var client = await HookedConnectAsync(IPEndPoint.Parse("203.0.113.5:80"), "other-name-on-this-cdn.example", ct);
        var http = "GET / HTTP/1.1\r\nHost: real.example\r\n\r\n";

        await client.SendAsync(Encoding.ASCII.GetBytes(http), ct);

        Assert.Equal(http, await client.ReceiveStringAsync(http.Length, ct));
        var request = Assert.Single(socks.Requests);
        Assert.Equal(("real.example", 80), (request.Host, request.Port));
    }

    [Fact]
    public async Task A_malformed_message_ends_the_session()
    {
        var ct = TestTimeout.Token();

        await HookProtocol.WriteFrameAsync(hookStream, new byte[] { 9, 9, 9 }, ct);

        await session.WaitAsync(ct); // the transport then closes the connection; the hook fails closed
    }
}
