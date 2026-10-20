using Proxynator.Core.Net;
using Proxynator.Platform.Windows.Packets;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// The "reflect" NAT used to hand outbound connections to the local relays without changing the client.
/// <para>
/// A client flow <c>A:pa → B:pb</c> is redirected by rewriting its outbound packets to <c>B:pa → A:relay</c> and
/// injecting them inbound, so the relay (listening on all addresses) sees a peer <c>B:pa</c>. The relay's replies
/// <c>A:relay → B:pa</c> are rewritten back to <c>B:pb → A:pa</c> and injected inbound to the client. The NAT remembers
/// <c>pb</c> per protocol and <c>(B, pa)</c>; that pair is also the key under which the original destination is
/// registered for the relay. TCP and UDP use separate relay ports. A TCP flow starts with a SYN and ends with RST or
/// FIN in both directions; a UDP flow starts with any datagram and ends when idle.
/// </para>
/// <para>
/// UDP has no SYN, so "do not redirect" decisions are remembered too (pass-through entries, until idle); otherwise
/// every datagram of an ordinary UDP flow would go through owner lookup and rule evaluation again.
/// </para>
/// <para>Not thread-safe: all packets are processed on the capture thread.</para>
/// </summary>
internal sealed class ReflectNat(int tcpRelayPort, int udpRelayPort, TimeProvider? timeProvider = null)
{
    private static readonly TimeSpan TcpIdleTimeout = TimeSpan.FromHours(4);
    // Shorter than the UDP relay's session timeouts (2 min, DNS 15 s): when a NAT entry outlives the relay session, a
    // late datagram would reach the relay with no session and no registration and be dropped.
    private static readonly TimeSpan UdpIdleTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan DnsIdleTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ClosedLinger = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

    private readonly Dictionary<NatKey, NatEntry> entries = [];
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;
    private DateTimeOffset nextSweep = DateTimeOffset.MinValue;
    private int count;

    /// <summary>Creates a TCP-only NAT (no UDP relay).</summary>
    public ReflectNat(int tcpRelayPort, TimeProvider? timeProvider = null)
        : this(tcpRelayPort, 0, timeProvider)
    {
    }

    public int TcpRelayPort { get; } = tcpRelayPort;

    public int UdpRelayPort { get; } = udpRelayPort;

    /// <summary>The number of redirected flows (pass-through entries are not counted). Safe to read from any thread.</summary>
    public int Count => Volatile.Read(ref count);

    /// <summary>
    /// Processes an outbound TCP or UDP packet, rewriting it in place when it belongs to a redirected flow.
    /// <paramref name="shouldRedirect"/> is called once per new flow to decide whether to redirect it.
    /// </summary>
    public NatVerdict Process(Span<byte> packet, Func<ConnectionAttempt, bool> shouldRedirect)
    {
        var now = time.GetUtcNow();
        if (now >= nextSweep)
        {
            Sweep(now);
        }

        if (!TransportPacket.TryParse(packet, out var transport) || (transport.IsUdp && UdpRelayPort == 0))
        {
            return NatVerdict.PassThrough;
        }

        var relayPort = transport.IsUdp ? UdpRelayPort : TcpRelayPort;
        if (transport.SourcePort == relayPort)
        {
            return ProcessFromRelay(ref transport, now);
        }

        var key = new NatKey(transport.IsUdp, transport.DestinationAddress, (ushort)transport.SourcePort);
        var startsFlow = transport.IsUdp || transport.IsConnectionAttempt;
        var entry = Lookup(key, now);
        if (entry is not null && entry.OriginalPort == transport.DestinationPort &&
            !(entry.IsClosed && transport.IsConnectionAttempt))
        {
            entry.Touch(now, fin: transport.IsFin, fromClient: true);
            if (!entry.Redirected)
            {
                return NatVerdict.PassThrough;
            }
        }
        else if (startsFlow && (entry is null || entry.IsClosed))
        {
            var redirect = shouldRedirect(new ConnectionAttempt(
                transport.IsUdp ? TransportProtocol.Udp : TransportProtocol.Tcp,
                transport.IsIPv6, transport.SourceAddress, transport.SourcePort, transport.DestinationAddress, transport.DestinationPort));
            if (!redirect && !transport.IsUdp)
            {
                return NatVerdict.PassThrough; // TCP: later packets have no SYN and pass through on their own
            }

            Remove(key);
            entry = new NatEntry(transport.IsUdp, transport.DestinationPort, now, redirect);
            entries[key] = entry;
            if (!redirect)
            {
                return NatVerdict.PassThrough;
            }

            Interlocked.Increment(ref count);
        }
        else
        {
            return NatVerdict.PassThrough;
        }

        if (transport.IsRst)
        {
            Remove(key);
        }

        // A:pa -> B:pb  becomes  B:pa -> A:relay
        transport.SwapAddresses();
        transport.DestinationPort = relayPort;
        return NatVerdict.Reflect;
    }

    private NatVerdict ProcessFromRelay(ref TransportPacket transport, DateTimeOffset now)
    {
        var key = new NatKey(transport.IsUdp, transport.DestinationAddress, (ushort)transport.DestinationPort);
        if (Lookup(key, now) is not { Redirected: true } entry)
        {
            // A reply for a flow we no longer track; never let relay packets leak onto the network.
            return NatVerdict.Drop;
        }

        entry.Touch(now, fin: transport.IsFin, fromClient: false);
        if (transport.IsRst)
        {
            Remove(key);
        }

        // A:relay -> B:pa  becomes  B:pb -> A:pa
        transport.SwapAddresses();
        transport.SourcePort = entry.OriginalPort;
        return NatVerdict.Reflect;
    }

    /// <summary>Finds an entry, treating expired ones as gone (timeouts hold exactly, not just at sweep time).</summary>
    private NatEntry? Lookup(NatKey key, DateTimeOffset now)
    {
        if (!entries.TryGetValue(key, out var entry))
        {
            return null;
        }

        if (IsExpired(entry, now))
        {
            Remove(key);
            return null;
        }

        return entry;
    }

    private static bool IsExpired(NatEntry entry, DateTimeOffset now)
    {
        var idleTimeout = !entry.IsUdp ? TcpIdleTimeout : entry.OriginalPort == 53 ? DnsIdleTimeout : UdpIdleTimeout;
        return now - entry.LastSeen > idleTimeout || (entry.ClosedAt is { } closedAt && now - closedAt > ClosedLinger);
    }

    private void Remove(NatKey key)
    {
        if (entries.Remove(key, out var removed) && removed.Redirected)
        {
            Interlocked.Decrement(ref count);
        }
    }

    private void Sweep(DateTimeOffset now)
    {
        nextSweep = now + SweepInterval;
        foreach (var (key, entry) in entries)
        {
            if (IsExpired(entry, now))
            {
                Remove(key);
            }
        }
    }

    private readonly record struct NatKey(bool IsUdp, UInt128 RemoteAddress, ushort ClientPort);

    private sealed class NatEntry(bool isUdp, int originalPort, DateTimeOffset now, bool redirected = true)
    {
        private bool clientFin;
        private bool relayFin;

        public bool IsUdp { get; } = isUdp;

        /// <summary>False for remembered "pass through" decisions (UDP only).</summary>
        public bool Redirected { get; } = redirected;

        public int OriginalPort { get; } = originalPort;

        public DateTimeOffset LastSeen { get; private set; } = now;

        public DateTimeOffset? ClosedAt { get; private set; }

        public bool IsClosed => ClosedAt is not null;

        public void Touch(DateTimeOffset now, bool fin, bool fromClient)
        {
            LastSeen = now;
            if (fin)
            {
                if (fromClient)
                {
                    clientFin = true;
                }
                else
                {
                    relayFin = true;
                }

                if (clientFin && relayFin)
                {
                    ClosedAt ??= now;
                }
            }
        }
    }
}
