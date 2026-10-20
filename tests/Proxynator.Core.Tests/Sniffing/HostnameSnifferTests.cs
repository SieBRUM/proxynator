using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Proxynator.Core.Sniffing;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Sniffing;

public class HostnameSnifferTests
{
    [Fact]
    public async Task Finds_sni_in_a_real_client_hello()
    {
        var hello = await CaptureClientHelloAsync("www.Example.test");

        Assert.Equal(SniffStatus.Found, HostnameSniffer.TrySniff(hello, out var host));
        Assert.Equal("www.example.test", host);
    }

    [Fact]
    public async Task Partial_client_hello_needs_more_data()
    {
        var hello = await CaptureClientHelloAsync("partial.example.test");

        Assert.Equal(SniffStatus.NeedMoreData, HostnameSniffer.TrySniff(hello.AsSpan(0, 3), out _));
        Assert.Equal(SniffStatus.NeedMoreData, HostnameSniffer.TrySniff(hello.AsSpan(0, hello.Length - 1), out _));
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n", "example.com")]
    [InlineData("POST /x HTTP/1.1\r\nUser-Agent: t\r\nhost:  Example.COM:8080 \r\n\r\n", "example.com")]
    [InlineData("GET / HTTP/1.1\r\nHost: example.com\r\n", "example.com")]
    public void Finds_http_host(string request, string expected)
    {
        Assert.Equal(SniffStatus.Found, HostnameSniffer.TrySniff(Encoding.ASCII.GetBytes(request), out var host));
        Assert.Equal(expected, host);
    }

    [Theory]
    [InlineData("GE")]
    [InlineData("GET / HTTP/1.1\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: exa")]
    [InlineData("")]
    public void Incomplete_http_needs_more_data(string request)
    {
        Assert.Equal(SniffStatus.NeedMoreData, HostnameSniffer.TrySniff(Encoding.ASCII.GetBytes(request), out _));
    }

    [Theory]
    [InlineData("SSH-2.0-OpenSSH_9.6\r\n")]
    [InlineData("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: bad host\r\n\r\n")]
    public void Non_matching_data_is_not_found(string data)
    {
        Assert.Equal(SniffStatus.NotFound, HostnameSniffer.TrySniff(Encoding.ASCII.GetBytes(data), out var host));
        Assert.Null(host);
    }

    [Fact]
    public void Garbage_tls_record_is_not_found()
    {
        byte[] data = [0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];

        Assert.Equal(SniffStatus.NotFound, HostnameSniffer.TrySniff(data, out _));
    }

    /// <summary>Lets the platform TLS stack produce a genuine ClientHello and captures its first record.</summary>
    private static async Task<byte[]> CaptureClientHelloAsync(string serverName)
    {
        var ct = TestTimeout.Token();
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen();

        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndPoint!, ct);
        using var server = await listener.AcceptAsync(ct);

        var ssl = new SslStream(client.GetStream());
        var handshake = ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName }, ct);

        var buffer = new List<byte>();
        var chunk = new byte[4096];
        while (HostnameSniffer.TrySniff(buffer.ToArray(), out _) == SniffStatus.NeedMoreData)
        {
            var count = await server.ReceiveAsync(chunk, ct);
            Assert.NotEqual(0, count);
            buffer.AddRange(chunk.AsSpan(0, count));
        }

        server.Close();
        await Assert.ThrowsAnyAsync<Exception>(() => handshake);
        await ssl.DisposeAsync();
        return [.. buffer];
    }
}
