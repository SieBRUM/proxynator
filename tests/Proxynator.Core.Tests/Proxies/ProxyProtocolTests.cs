using System.Net;
using System.Net.Sockets;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;
using Proxynator.Core.Proxies;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Proxies;

public class ProxyProtocolTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private static ProxyRoute Route(params ProxyHop[] hops) => new(hops[^1].Id, hops);

    private static ProxyHop Hop(string id, ProxyType type, IPEndPoint endpoint, ProxyCredentials? credentials = null) =>
        new(id, type, TargetEndpoint.FromAddress(endpoint.Address, endpoint.Port), credentials);

    private static async Task AssertEchoAsync(Stream stream, CancellationToken ct)
    {
        await stream.WriteAsync("ping"u8.ToArray(), ct);
        var reply = new byte[4];
        await stream.ReadExactlyAsync(reply, ct);
        Assert.Equal("ping"u8.ToArray(), reply);
    }

    [Theory]
    [InlineData(ProxyType.Socks4, FakeProxyKind.Socks4)]
    [InlineData(ProxyType.Socks4a, FakeProxyKind.Socks4)]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5)]
    [InlineData(ProxyType.Http, FakeProxyKind.Http)]
    public async Task Connects_to_an_address_target(ProxyType type, FakeProxyKind kind)
    {
        var ct = TestTimeout.Token();
        await using var echo = new EchoServer();
        await using var proxy = new FakeProxyServer(kind);
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        await using var stream = await dialer.ConnectAsync(Route(Hop("p", type, proxy.Endpoint)), TargetEndpoint.FromAddress(echo.Endpoint.Address, echo.Endpoint.Port), Timeout, ct);
        await AssertEchoAsync(stream, ct);

        var request = Assert.Single(proxy.Requests);
        Assert.Equal(echo.Endpoint.Address, request.Address);
        Assert.Equal(echo.Endpoint.Port, request.Port);
    }

    [Theory]
    [InlineData(ProxyType.Socks4a, FakeProxyKind.Socks4)]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5)]
    [InlineData(ProxyType.Http, FakeProxyKind.Http)]
    public async Task Sends_hostnames_when_the_protocol_supports_them(ProxyType type, FakeProxyKind kind)
    {
        var ct = TestTimeout.Token();
        await using var echo = new EchoServer();
        await using var proxy = new FakeProxyServer(kind) { Resolve = _ => echo.Endpoint };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        await using var stream = await dialer.ConnectAsync(Route(Hop("p", type, proxy.Endpoint)), TargetEndpoint.FromHost("app.example.test", 443, IPAddress.Parse("192.0.2.1")), Timeout, ct);
        await AssertEchoAsync(stream, ct);

        var request = Assert.Single(proxy.Requests);
        Assert.Equal(("app.example.test", 443), (request.Host, request.Port));
    }

    [Fact]
    public async Task Socks4_uses_the_known_address_instead_of_the_hostname()
    {
        var ct = TestTimeout.Token();
        await using var echo = new EchoServer();
        await using var proxy = new FakeProxyServer(FakeProxyKind.Socks4) { Resolve = _ => echo.Endpoint };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        await using var stream = await dialer.ConnectAsync(Route(Hop("p", ProxyType.Socks4, proxy.Endpoint, new ProxyCredentials("me", ""))), TargetEndpoint.FromHost("app.example.test", 443, IPAddress.Parse("192.0.2.1")), Timeout, ct);

        var request = Assert.Single(proxy.Requests);
        Assert.Null(request.Host);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), request.Address);
        Assert.Equal("me", request.UserId);
    }

    [Fact]
    public async Task Socks4_cannot_carry_ipv6()
    {
        var ct = TestTimeout.Token();
        await using var proxy = new FakeProxyServer(FakeProxyKind.Socks4);
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        var ex = await Assert.ThrowsAsync<ProxyException>(async () =>
            await dialer.ConnectAsync(Route(Hop("p", ProxyType.Socks4, proxy.Endpoint)), TargetEndpoint.FromAddress(IPAddress.IPv6Loopback, 80), Timeout, ct));

        Assert.Equal(ProxyFailure.Unsupported, ex.Failure);
    }

    [Theory]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5)]
    [InlineData(ProxyType.Http, FakeProxyKind.Http)]
    public async Task Authenticates_with_credentials(ProxyType type, FakeProxyKind kind)
    {
        var ct = TestTimeout.Token();
        await using var echo = new EchoServer();
        await using var proxy = new FakeProxyServer(kind) { RequiredCredentials = ("user", "p@ss:word") };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        await using var stream = await dialer.ConnectAsync(Route(Hop("p", type, proxy.Endpoint, new ProxyCredentials("user", "p@ss:word"))), TargetEndpoint.FromAddress(echo.Endpoint.Address, echo.Endpoint.Port), Timeout, ct);
        await AssertEchoAsync(stream, ct);
    }

    [Theory]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5, "wrong")]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5, null)]
    [InlineData(ProxyType.Http, FakeProxyKind.Http, "wrong")]
    [InlineData(ProxyType.Http, FakeProxyKind.Http, null)]
    public async Task Wrong_or_missing_credentials_fail_with_authentication_error(ProxyType type, FakeProxyKind kind, string? password)
    {
        var ct = TestTimeout.Token();
        await using var proxy = new FakeProxyServer(kind) { RequiredCredentials = ("user", "right") };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);
        var credentials = password is null ? null : new ProxyCredentials("user", password);

        var ex = await Assert.ThrowsAsync<ProxyException>(async () =>
            await dialer.ConnectAsync(Route(Hop("p", type, proxy.Endpoint, credentials)), TargetEndpoint.FromAddress(IPAddress.Loopback, 9), Timeout, ct));

        Assert.Equal(ProxyFailure.AuthenticationFailed, ex.Failure);
        Assert.Equal("p", ex.HopId);
    }

    [Theory]
    [InlineData(ProxyType.Socks4, FakeProxyKind.Socks4)]
    [InlineData(ProxyType.Socks5, FakeProxyKind.Socks5)]
    [InlineData(ProxyType.Http, FakeProxyKind.Http)]
    public async Task Refusals_are_reported_as_rejected(ProxyType type, FakeProxyKind kind)
    {
        var ct = TestTimeout.Token();
        await using var proxy = new FakeProxyServer(kind) { RejectAll = true };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        var ex = await Assert.ThrowsAsync<ProxyException>(async () =>
            await dialer.ConnectAsync(Route(Hop("p", type, proxy.Endpoint)), TargetEndpoint.FromAddress(IPAddress.Loopback, 9), Timeout, ct));

        Assert.Equal(ProxyFailure.Rejected, ex.Failure);
    }

    [Fact]
    public async Task Unreachable_proxy_fails_with_connect_failed()
    {
        var ct = TestTimeout.Token();
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        var ex = await Assert.ThrowsAsync<ProxyException>(async () =>
            await dialer.ConnectAsync(Route(Hop("down", ProxyType.Socks5, UnusedEndpoint())), TargetEndpoint.FromAddress(IPAddress.Loopback, 9), Timeout, ct));

        Assert.Equal(ProxyFailure.ConnectFailed, ex.Failure);
        Assert.Equal("down", ex.HopId);
    }

    [Fact]
    public async Task Silent_proxy_times_out()
    {
        var ct = TestTimeout.Token();
        await using var proxy = new FakeProxyServer(FakeProxyKind.Socks5) { NeverRespond = true };
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        var ex = await Assert.ThrowsAsync<ProxyException>(async () =>
            await dialer.ConnectAsync(Route(Hop("slow", ProxyType.Socks5, proxy.Endpoint)), TargetEndpoint.FromAddress(IPAddress.Loopback, 9), TimeSpan.FromMilliseconds(300), ct));

        Assert.Equal(ProxyFailure.Timeout, ex.Failure);
        Assert.Equal("slow", ex.HopId);
    }

    [Fact]
    public async Task Chains_tunnel_each_hop_through_the_previous_one()
    {
        var ct = TestTimeout.Token();
        await using var echo = new EchoServer();
        await using var last = new FakeProxyServer(FakeProxyKind.Http) { Resolve = _ => echo.Endpoint };
        await using var middle = new FakeProxyServer(FakeProxyKind.Socks4);
        await using var first = new FakeProxyServer(FakeProxyKind.Socks5);
        var dialer = new ProxyRouteDialer(TcpConnector.Default);
        var route = new ProxyRoute("chain", [Hop("first", ProxyType.Socks5, first.Endpoint), Hop("middle", ProxyType.Socks4a, middle.Endpoint), Hop("last", ProxyType.Http, last.Endpoint)]);

        await using var stream = await dialer.ConnectAsync(route, TargetEndpoint.FromHost("deep.example.test", 8443), Timeout, ct);
        await AssertEchoAsync(stream, ct);

        Assert.Equal(middle.Endpoint.Port, Assert.Single(first.Requests).Port);
        Assert.Equal(last.Endpoint.Port, Assert.Single(middle.Requests).Port);
        Assert.Equal(("deep.example.test", 8443), (Assert.Single(last.Requests).Host, Assert.Single(last.Requests).Port));
    }

    [Fact]
    public async Task Http_connect_does_not_swallow_server_first_bytes()
    {
        var ct = TestTimeout.Token();
        await using var banner = new EchoServer(banner: "SSH-2.0-test\r\n");
        await using var proxy = new FakeProxyServer(FakeProxyKind.Http);
        var dialer = new ProxyRouteDialer(TcpConnector.Default);

        await using var stream = await dialer.ConnectAsync(Route(Hop("p", ProxyType.Http, proxy.Endpoint)), TargetEndpoint.FromAddress(banner.Endpoint.Address, banner.Endpoint.Port), Timeout, ct);
        var received = new byte[14];
        await stream.ReadExactlyAsync(received, ct);

        Assert.Equal("SSH-2.0-test\r\n"u8.ToArray(), received);
    }

    [Fact]
    public void Http_request_includes_basic_auth_and_brackets_ipv6()
    {
        var protocol = new HttpConnectProtocol(new ProxyCredentials("user", "pass"));

        var request = protocol.BuildRequest(TargetEndpoint.FromAddress(IPAddress.IPv6Loopback, 443));

        Assert.StartsWith("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n", request, StringComparison.Ordinal);
        Assert.Contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n", request, StringComparison.Ordinal);
        Assert.EndsWith("\r\n\r\n", request, StringComparison.Ordinal);
    }

    private static IPEndPoint UnusedEndpoint()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }
}
