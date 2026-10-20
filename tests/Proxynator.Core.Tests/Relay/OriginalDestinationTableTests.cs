using System.Net;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;

namespace Proxynator.Core.Tests.Relay;

public class OriginalDestinationTableTests
{
    private static readonly OriginalDestination Destination = new(new IPEndPoint(IPAddress.Parse("93.184.216.34"), 443), 42, "example.com");

    [Fact]
    public void Entries_are_taken_once()
    {
        var table = new OriginalDestinationTable();
        var client = new IPEndPoint(IPAddress.Loopback, 50000);

        table.Register(client, Destination);

        Assert.True(table.TryTake(new IPEndPoint(IPAddress.Loopback, 50000), out var found));
        Assert.Equal(Destination, found);
        Assert.False(table.TryTake(client, out _));
    }

    [Fact]
    public void Mapped_ipv4_endpoints_are_normalized()
    {
        var table = new OriginalDestinationTable();
        table.Register(new IPEndPoint(IPAddress.Parse("::ffff:127.0.0.1"), 50001), Destination);

        Assert.True(table.TryTake(new IPEndPoint(IPAddress.Loopback, 50001), out _));
    }

    [Fact]
    public void Entries_expire()
    {
        var time = new ManualTimeProvider();
        var table = new OriginalDestinationTable(time, TimeSpan.FromSeconds(5));
        var client = new IPEndPoint(IPAddress.Loopback, 50002);

        table.Register(client, Destination);
        time.Advance(TimeSpan.FromSeconds(6));

        Assert.False(table.TryTake(client, out _));

        table.Register(client, Destination);
        time.Advance(TimeSpan.FromSeconds(6));
        table.PurgeExpired();
        Assert.Equal(0, table.Count);
    }
}
