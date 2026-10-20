using System.Net;
using Proxynator.Platform.Windows.Capture;
using Proxynator.Platform.Windows.Interop;
using static Proxynator.Platform.Windows.Tests.PacketBuilder;

namespace Proxynator.Platform.Windows.Tests;

public class ReflectNatTests
{
    private const int RelayPort = 40000;
    private const string Client = "192.168.1.10";
    private const string Server = "93.184.216.34";

    private readonly ManualTimeProvider time = new();
    private readonly List<ConnectionAttempt> attempts = [];

    private ReflectNat Nat() => new(RelayPort, time);

    private Func<ConnectionAttempt, bool> Decide(bool redirect) => attempt =>
    {
        attempts.Add(attempt);
        return redirect;
    };

    [Fact]
    public void Redirected_syn_is_reflected_to_the_relay()
    {
        var nat = Nat();
        var syn = Tcp(Client, 50000, Server, 443, Syn);

        Assert.Equal(NatVerdict.Reflect, nat.Process(syn, Decide(true)));

        // A:pa -> B:pb becomes B:pa -> A:relay
        Assert.Equal((Server, 50000, Client, RelayPort), Read(syn));
        var attempt = Assert.Single(attempts);
        Assert.Equal((IPAddress.Parse(Client), 50000, IPAddress.Parse(Server), 443), (attempt.LocalIPAddress, attempt.LocalPort, attempt.RemoteIPAddress, attempt.RemotePort));
        Assert.Equal(1, nat.Count);
    }

    [Fact]
    public void Relay_replies_are_reflected_back_to_the_client()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50000, Server, 443, Syn), Decide(true));
        var synAck = Tcp(Client, RelayPort, Server, 50000, Syn | Ack);

        Assert.Equal(NatVerdict.Reflect, nat.Process(synAck, Decide(true)));

        // A:relay -> B:pa becomes B:pb -> A:pa
        Assert.Equal((Server, 443, Client, 50000), Read(synAck));
    }

    [Fact]
    public void Later_client_packets_of_a_redirected_connection_are_reflected_without_a_new_decision()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50000, Server, 443, Syn), Decide(true));
        var data = Tcp(Client, 50000, Server, 443, Ack, payload: 100);

        Assert.Equal(NatVerdict.Reflect, nat.Process(data, Decide(false)));
        Assert.Equal((Server, 50000, Client, RelayPort), Read(data));
        Assert.Single(attempts);
    }

    [Fact]
    public void Connections_that_are_not_redirected_pass_through_unchanged()
    {
        var nat = Nat();
        var syn = Tcp(Client, 50001, Server, 443, Syn);
        var data = Tcp(Client, 50001, Server, 443, Ack, payload: 10);
        var original = (byte[])data.Clone();

        Assert.Equal(NatVerdict.PassThrough, nat.Process(syn, Decide(false)));
        Assert.Equal(NatVerdict.PassThrough, nat.Process(data, Decide(true)));

        Assert.Equal(original, data);
        Assert.Single(attempts); // only the SYN is offered for a decision
        Assert.Equal(0, nat.Count);
    }

    [Fact]
    public void Relay_packets_for_unknown_connections_are_dropped()
    {
        Assert.Equal(NatVerdict.Drop, Nat().Process(Tcp(Client, RelayPort, Server, 50002, Ack), Decide(true)));
    }

    [Fact]
    public void Rst_ends_the_mapping()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50003, Server, 443, Syn), Decide(true));

        Assert.Equal(NatVerdict.Reflect, nat.Process(Tcp(Client, 50003, Server, 443, Rst), Decide(true)));
        Assert.Equal(0, nat.Count);
        Assert.Equal(NatVerdict.Drop, nat.Process(Tcp(Client, RelayPort, Server, 50003, Ack), Decide(true)));
    }

    [Fact]
    public void Closed_mappings_linger_then_expire()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50004, Server, 443, Syn), Decide(true));
        nat.Process(Tcp(Client, 50004, Server, 443, Fin | Ack), Decide(true));
        nat.Process(Tcp(Client, RelayPort, Server, 50004, Fin | Ack), Decide(true));

        // The final ACK still gets through.
        Assert.Equal(NatVerdict.Reflect, nat.Process(Tcp(Client, 50004, Server, 443, Ack), Decide(true)));

        time.Advance(TimeSpan.FromMinutes(2));
        nat.Process(Tcp(Client, 1, Server, 1, Ack), Decide(false)); // any packet triggers the sweep
        Assert.Equal(0, nat.Count);
    }

    [Fact]
    public void Idle_mappings_expire()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50005, Server, 443, Syn), Decide(true));

        time.Advance(TimeSpan.FromHours(5));
        nat.Process(Tcp(Client, 1, Server, 1, Ack), Decide(false));

        Assert.Equal(0, nat.Count);
    }

    [Fact]
    public void Reusing_a_port_after_close_asks_again()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50006, Server, 443, Syn), Decide(true));
        nat.Process(Tcp(Client, 50006, Server, 443, Fin | Ack), Decide(true));
        nat.Process(Tcp(Client, RelayPort, Server, 50006, Fin | Ack), Decide(true));

        Assert.Equal(NatVerdict.PassThrough, nat.Process(Tcp(Client, 50006, Server, 443, Syn), Decide(false)));
        Assert.Equal(2, attempts.Count);
    }

    [Fact]
    public void A_second_connection_on_the_same_client_port_and_server_is_not_hijacked()
    {
        var nat = Nat();
        nat.Process(Tcp(Client, 50007, Server, 443, Syn), Decide(true));

        Assert.Equal(NatVerdict.PassThrough, nat.Process(Tcp(Client, 50007, Server, 8443, Syn), Decide(true)));
        Assert.Single(attempts);
    }

    [Fact]
    public void Ipv6_connections_are_reflected()
    {
        var nat = Nat();
        var syn = Tcp("2001:db8::10", 50008, "2001:db8::1", 443, Syn);

        Assert.Equal(NatVerdict.Reflect, nat.Process(syn, Decide(true)));

        Assert.Equal(("2001:db8::1", 50008, "2001:db8::10", RelayPort), Read(syn));
        Assert.True(Assert.Single(attempts).IsIPv6);
    }

    [Fact]
    public void Other_protocols_and_fragments_pass_through()
    {
        var nat = Nat();
        var icmp = Tcp(Client, 1, Server, 53, 0);
        icmp[9] = 1;
        var fragment = Tcp(Client, 50009, Server, 443, Syn);
        fragment[6] = 0x20; // more fragments

        Assert.Equal(NatVerdict.PassThrough, nat.Process(icmp, Decide(true)));
        Assert.Equal(NatVerdict.PassThrough, nat.Process(fragment, Decide(true)));
        Assert.Equal(NatVerdict.PassThrough, nat.Process(new byte[10], Decide(true)));
        Assert.Empty(attempts);
    }

    [Fact]
    public void Address_keys_round_trip()
    {
        foreach (var text in new[] { "10.1.2.3", "2001:db8::1", "::1" })
        {
            var address = IPAddress.Parse(text);
            Assert.Equal(address, AddressKey.ToIPAddress(AddressKey.FromIPAddress(address)));
        }
    }
}
