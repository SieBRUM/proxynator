using System.Buffers.Binary;
using Proxynator.Core.Net;
using Proxynator.Platform.Windows.Capture;
using Proxynator.Platform.Windows.Interop;
using static Proxynator.Platform.Windows.Tests.PacketBuilder;

namespace Proxynator.Platform.Windows.Tests;

public class ReflectNatUdpTests
{
    private const int TcpRelayPort = 40000;
    private const int UdpRelayPort = 40001;
    private const string Client = "192.168.1.10";
    private const string Server = "8.8.8.8";

    private readonly ManualTimeProvider time = new();
    private readonly List<ConnectionAttempt> attempts = [];

    private ReflectNat Nat() => new(TcpRelayPort, UdpRelayPort, time);

    private Func<ConnectionAttempt, bool> Decide(bool redirect) => attempt =>
    {
        attempts.Add(attempt);
        return redirect;
    };

    [Fact]
    public void First_datagram_of_a_redirected_flow_goes_to_the_udp_relay()
    {
        var nat = Nat();
        var datagram = Udp(Client, 50000, Server, 53);

        Assert.Equal(NatVerdict.Reflect, nat.Process(datagram, Decide(true)));

        Assert.Equal((Server, 50000, Client, UdpRelayPort), Read(datagram));
        Assert.Equal(TransportProtocol.Udp, Assert.Single(attempts).Protocol);
    }

    [Fact]
    public void Udp_relay_replies_are_reflected_back()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50000, Server, 53), Decide(true));
        var reply = Udp(Client, UdpRelayPort, Server, 50000);

        Assert.Equal(NatVerdict.Reflect, nat.Process(reply, Decide(true)));
        Assert.Equal((Server, 53, Client, 50000), Read(reply));
    }

    [Fact]
    public void Later_datagrams_reuse_the_decision_either_way()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50000, Server, 5000), Decide(true));
        Assert.Equal(NatVerdict.Reflect, nat.Process(Udp(Client, 50000, Server, 5000), Decide(false)));

        Assert.Equal(NatVerdict.PassThrough, nat.Process(Udp(Client, 50001, Server, 5000), Decide(false)));
        Assert.Equal(NatVerdict.PassThrough, nat.Process(Udp(Client, 50001, Server, 5000), Decide(true)));
        Assert.Equal(2, attempts.Count); // one decision per flow, also for flows that are not redirected
        Assert.Equal(1, nat.Count);
    }

    [Fact]
    public void Pass_through_decisions_expire_with_the_flow()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50006, Server, 5000), Decide(false));

        time.Advance(TimeSpan.FromSeconds(61));

        Assert.Equal(NatVerdict.Reflect, nat.Process(Udp(Client, 50006, Server, 5000), Decide(true)));
        Assert.Equal(2, attempts.Count);
    }

    [Fact]
    public void Relay_replies_never_match_pass_through_entries()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50007, Server, 5000), Decide(false));

        Assert.Equal(NatVerdict.Drop, nat.Process(Udp(Client, UdpRelayPort, Server, 50007), Decide(true)));
    }

    [Fact]
    public void Tcp_and_udp_flows_with_the_same_ports_are_independent()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50002, Server, 443, Syn), Decide(true));

        Assert.Equal(NatVerdict.PassThrough, nat.Process(Udp(Client, 50002, Server, 443), Decide(false)));
        Assert.Equal(NatVerdict.Drop, nat.Process(Udp(Client, UdpRelayPort, Server, 50002), Decide(true)));
    }

    [Fact]
    public void Dns_mappings_expire_exactly_after_ten_seconds()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50003, Server, 53), Decide(true));

        time.Advance(TimeSpan.FromSeconds(11));

        Assert.Equal(NatVerdict.Drop, nat.Process(Udp(Client, UdpRelayPort, Server, 50003), Decide(true)));
        Assert.Equal(0, nat.Count);
    }

    [Fact]
    public void Other_udp_mappings_expire_after_a_minute()
    {
        var nat = Nat();
        nat.Process(Udp(Client, 50004, Server, 3478), Decide(true));

        time.Advance(TimeSpan.FromSeconds(30));
        Assert.Equal(NatVerdict.Reflect, nat.Process(Udp(Client, UdpRelayPort, Server, 50004), Decide(true)));
        time.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(NatVerdict.Drop, nat.Process(Udp(Client, UdpRelayPort, Server, 50004), Decide(true)));
    }

    [Fact]
    public void Udp_passes_through_when_no_udp_relay_is_configured()
    {
        var nat = new ReflectNat(TcpRelayPort, time);

        Assert.Equal(NatVerdict.PassThrough, nat.Process(Udp(Client, 50005, Server, 53), Decide(true)));
        Assert.Empty(attempts);
    }

    [Fact]
    public void Udp_table_lookup_finds_the_owner_by_local_port()
    {
        var v4 = new byte[4 + (2 * TcpTableParser.UdpIPv4RowSize)];
        BinaryPrimitives.WriteUInt32LittleEndian(v4, 2);
        BinaryPrimitives.WriteUInt16BigEndian(v4.AsSpan(4 + 4), 53000);
        BinaryPrimitives.WriteUInt32LittleEndian(v4.AsSpan(4 + 8), 11);
        BinaryPrimitives.WriteUInt16BigEndian(v4.AsSpan(4 + TcpTableParser.UdpIPv4RowSize + 4), 53001);
        BinaryPrimitives.WriteUInt32LittleEndian(v4.AsSpan(4 + TcpTableParser.UdpIPv4RowSize + 8), 22);

        var v6 = new byte[4 + TcpTableParser.UdpIPv6RowSize];
        BinaryPrimitives.WriteUInt32LittleEndian(v6, 1);
        BinaryPrimitives.WriteUInt16BigEndian(v6.AsSpan(4 + 20), 53002);
        BinaryPrimitives.WriteUInt32LittleEndian(v6.AsSpan(4 + 24), 33);

        Assert.Equal(22, TcpTableParser.FindUdpOwner(v4, false, 53001));
        Assert.Equal(-1, TcpTableParser.FindUdpOwner(v4, false, 9));
        Assert.Equal(33, TcpTableParser.FindUdpOwner(v6, true, 53002));
    }
}
