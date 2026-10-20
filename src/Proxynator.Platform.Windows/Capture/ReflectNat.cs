using Proxynator.Platform.Windows.Packets;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// The "reflect" NAT used to hand outbound connections to the local relay without changing the client.
/// <para>
/// A client connection <c>A:pa → B:pb</c> is redirected by rewriting its outbound packets to <c>B:pa → A:relay</c> and
/// injecting them inbound, so the relay (listening on all addresses) accepts a connection whose peer is
/// <c>B:pa</c>. The relay's replies <c>A:relay → B:pa</c> are rewritten back to <c>B:pb → A:pa</c> and injected
/// inbound to the client. The NAT remembers <c>pb</c> per <c>(B, pa)</c>; that pair is also the key under which the
/// original destination is registered for the relay.
/// </para>
/// <para>Not thread-safe: all packets are processed on the capture thread.</para>
/// </summary>
internal sealed class ReflectNat(int relayPort, TimeProvider? timeProvider = null)
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromHours(4);
    private static readonly TimeSpan ClosedLinger = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

    private readonly Dictionary<NatKey, NatEntry> entries = [];
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;
    private DateTimeOffset nextSweep = DateTimeOffset.MinValue;
    private int count;

    public int RelayPort { get; } = relayPort;

    /// <summary>The number of tracked redirected connections. Safe to read from any thread.</summary>
    public int Count => Volatile.Read(ref count);

    /// <summary>
    /// Processes an outbound TCP packet, rewriting it in place when it belongs to a redirected connection.
    /// <paramref name="shouldRedirect"/> is called once per new connection (SYN) to decide whether to redirect it.
    /// </summary>
    public NatVerdict Process(Span<byte> packet, Func<ConnectionAttempt, bool> shouldRedirect)
    {
        var now = time.GetUtcNow();
        if (now >= nextSweep)
        {
            Sweep(now);
        }

        if (!TcpPacket.TryParse(packet, out var tcp))
        {
            return NatVerdict.PassThrough;
        }

        if (tcp.SourcePort == RelayPort)
        {
            return ProcessFromRelay(ref tcp, now);
        }

        var key = new NatKey(tcp.DestinationAddress, (ushort)tcp.SourcePort);
        if (entries.TryGetValue(key, out var entry) && entry.OriginalPort == tcp.DestinationPort &&
            !(entry.IsClosed && tcp.IsConnectionAttempt))
        {
            entry.Touch(now, fin: tcp.IsFin, fromClient: true);
        }
        else if (tcp.IsConnectionAttempt &&
                 (entry is null || entry.IsClosed) &&
                 shouldRedirect(new ConnectionAttempt(tcp.IsIPv6, tcp.SourceAddress, tcp.SourcePort, tcp.DestinationAddress, tcp.DestinationPort)))
        {
            entry = new NatEntry(tcp.DestinationPort, now);
            if (entries.TryAdd(key, entry))
            {
                Interlocked.Increment(ref count);
            }
            else
            {
                entries[key] = entry;
            }
        }
        else
        {
            return NatVerdict.PassThrough;
        }

        if (tcp.IsRst)
        {
            Remove(key);
        }

        // A:pa -> B:pb  becomes  B:pa -> A:relay
        tcp.SwapAddresses();
        tcp.DestinationPort = RelayPort;
        return NatVerdict.Reflect;
    }

    private NatVerdict ProcessFromRelay(ref TcpPacket tcp, DateTimeOffset now)
    {
        var key = new NatKey(tcp.DestinationAddress, (ushort)tcp.DestinationPort);
        if (!entries.TryGetValue(key, out var entry))
        {
            // A reply for a connection we no longer track; never let relay packets leak onto the network.
            return NatVerdict.Drop;
        }

        entry.Touch(now, fin: tcp.IsFin, fromClient: false);
        if (tcp.IsRst)
        {
            Remove(key);
        }

        // A:relay -> B:pa  becomes  B:pb -> A:pa
        tcp.SwapAddresses();
        tcp.SourcePort = entry.OriginalPort;
        return NatVerdict.Reflect;
    }

    private void Remove(NatKey key)
    {
        if (entries.Remove(key))
        {
            Interlocked.Decrement(ref count);
        }
    }

    private void Sweep(DateTimeOffset now)
    {
        nextSweep = now + SweepInterval;
        foreach (var (key, entry) in entries)
        {
            if (now - entry.LastSeen > IdleTimeout || (entry.ClosedAt is { } closedAt && now - closedAt > ClosedLinger))
            {
                Remove(key);
            }
        }
    }

    private readonly record struct NatKey(UInt128 RemoteAddress, ushort ClientPort);

    private sealed class NatEntry(int originalPort, DateTimeOffset now)
    {
        private bool clientFin;
        private bool relayFin;

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
