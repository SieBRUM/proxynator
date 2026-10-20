using System.Net;
using Proxynator.Core.Net;

namespace Proxynator.Core.Tests.Net;

public class AddressAndPortTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.255.1.2", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("10.1.2.3/8", "10.9.9.9", true)]
    [InlineData("192.168.1.0/25", "192.168.1.127", true)]
    [InlineData("192.168.1.0/25", "192.168.1.128", false)]
    [InlineData("127.0.0.1", "127.0.0.1", true)]
    [InlineData("127.0.0.1", "127.0.0.2", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("10.0.0.0/8", "::ffff:10.1.1.1", true)]
    [InlineData("2001:db8::/32", "2001:db8:1::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("::/0", "10.0.0.1", false)]
    public void AddressRange_contains(string range, string address, bool expected)
    {
        Assert.True(AddressRange.TryParse(range, out var parsed));
        Assert.Equal(expected, parsed.Contains(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("not-an-ip")]
    [InlineData("::/129")]
    public void AddressRange_rejects_invalid(string text)
    {
        Assert.False(AddressRange.TryParse(text, out _));
    }

    [Theory]
    [InlineData("443", 443, 443)]
    [InlineData("8000-8100", 8000, 8100)]
    [InlineData(" 1 - 65535 ", 1, 65535)]
    public void PortRange_parses(string text, int start, int end)
    {
        Assert.True(PortRange.TryParse(text, out var range));
        Assert.Equal(new PortRange(start, end), range);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-50")]
    [InlineData("abc")]
    [InlineData("-5")]
    [InlineData("")]
    public void PortRange_rejects_invalid(string text)
    {
        Assert.False(PortRange.TryParse(text, out _));
    }

    [Fact]
    public void TargetEndpoint_treats_ip_literals_as_addresses()
    {
        Assert.Equal(IPAddress.Parse("10.0.0.1"), TargetEndpoint.FromHost("10.0.0.1", 80).Address);
        Assert.Null(TargetEndpoint.FromHost("10.0.0.1", 80).Host);
        Assert.Equal(IPAddress.IPv6Loopback, TargetEndpoint.FromHost("[::1]", 80).Address);
        Assert.Equal("example.com", TargetEndpoint.FromHost("example.com", 80).Host);
    }

    [Fact]
    public void TargetEndpoint_formats_authority()
    {
        Assert.Equal("[::1]", TargetEndpoint.FromAddress(IPAddress.IPv6Loopback, 1).AuthorityHost);
        Assert.Equal("10.0.0.1", TargetEndpoint.FromAddress(IPAddress.Parse("10.0.0.1"), 1).AuthorityHost);
        Assert.Equal("example.com", TargetEndpoint.FromHost("example.com", 1, IPAddress.Loopback).AuthorityHost);
    }

    [Theory]
    [InlineData("bad host")]
    [InlineData("host\r\nInjected: yes")]
    [InlineData("")]
    [InlineData(".leading")]
    [InlineData("a..b")]
    public void TargetEndpoint_rejects_invalid_hostnames(string host)
    {
        Assert.Throws<ArgumentException>(() => TargetEndpoint.FromHost(host, 80));
    }

    [Fact]
    public void TargetEndpoint_rejects_invalid_ports()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => TargetEndpoint.FromAddress(IPAddress.Loopback, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => TargetEndpoint.FromHost("example.com", 70000));
    }
}
