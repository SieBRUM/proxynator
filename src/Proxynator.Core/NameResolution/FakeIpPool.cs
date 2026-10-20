using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using Proxynator.Core.Net;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// Hands out addresses from a reserved IPv4 range (default <c>198.18.0.0/15</c>) as DNS answers, one per hostname,
/// and maps them back when a connection to such an address arrives. When the range is exhausted the oldest
/// allocation is reused (first in, first out). Thread-safe.
/// </summary>
public sealed class FakeIpPool
{
    private readonly Lock sync = new();
    private readonly uint network;
    private readonly uint usable;
    private readonly Dictionary<string, uint> byName = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<uint, string> byOffset = [];
    private uint next;

    /// <summary>Creates a pool over <paramref name="range"/> (IPv4, at least a /30).</summary>
    public FakeIpPool(AddressRange range)
    {
        ArgumentNullException.ThrowIfNull(range);
        if (range.AddressFamily != AddressFamily.InterNetwork || range.PrefixLength > 30)
        {
            throw new ArgumentException("The fake-IP range must be an IPv4 range of at least 4 addresses.", nameof(range));
        }

        Range = range;
        network = BinaryPrimitives.ReadUInt32BigEndian(range.NetworkAddress.GetAddressBytes());
        usable = (uint)((1L << (32 - range.PrefixLength)) - 2); // without the network and broadcast addresses
    }

    /// <summary>The range addresses are taken from.</summary>
    public AddressRange Range { get; }

    /// <summary>The number of hostnames that currently have an address.</summary>
    public int Count
    {
        get
        {
            lock (sync)
            {
                return byName.Count;
            }
        }
    }

    /// <summary>Whether <paramref name="address"/> is in the fake range.</summary>
    public bool Contains(IPAddress address) => Range.Contains(address);

    /// <summary>Returns the address for <paramref name="hostname"/>, allocating one if needed.</summary>
    public IPAddress GetOrAllocate(string hostname)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostname);
        hostname = hostname.ToLowerInvariant();
        lock (sync)
        {
            if (!byName.TryGetValue(hostname, out var offset))
            {
                offset = 1 + next;
                next = (next + 1) % usable;
                if (byOffset.Remove(offset, out var previous))
                {
                    byName.Remove(previous);
                }

                byName[hostname] = offset;
                byOffset[offset] = hostname;
            }

            return ToAddress(offset);
        }
    }

    /// <summary>Maps a fake address back to its hostname.</summary>
    public bool TryGetHostname(IPAddress address, [NotNullWhen(true)] out string? hostname)
    {
        ArgumentNullException.ThrowIfNull(address);
        hostname = null;
        address = address.Normalize();
        if (!Contains(address))
        {
            return false;
        }

        var offset = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()) - network;
        lock (sync)
        {
            return byOffset.TryGetValue(offset, out hostname);
        }
    }

    private IPAddress ToAddress(uint offset)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, network + offset);
        return new IPAddress(bytes);
    }
}
