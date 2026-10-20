using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using Proxynator.Core.Net;

namespace Proxynator.Core.Relay;

/// <summary>
/// Thread-safe <see cref="IOriginalDestinationTable"/>. Entries that are never taken (the client gave up before
/// reaching the relay) expire after <c>entryLifetime</c>.
/// </summary>
public sealed class OriginalDestinationTable(TimeProvider? timeProvider = null, TimeSpan? entryLifetime = null) : IOriginalDestinationTable
{
    private const int PurgeInterval = 256;

    private readonly ConcurrentDictionary<IPEndPoint, Entry> entries = new();
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;
    private readonly TimeSpan lifetime = entryLifetime ?? TimeSpan.FromSeconds(60);
    private int registrations;

    /// <inheritdoc />
    public IOriginalDestinationSource? ExternalSource { get; set; }

    /// <summary>The number of pending entries.</summary>
    public int Count => entries.Count;

    /// <inheritdoc />
    public void Register(IPEndPoint clientEndpoint, OriginalDestination destination)
    {
        ArgumentNullException.ThrowIfNull(clientEndpoint);
        ArgumentNullException.ThrowIfNull(destination);
        entries[clientEndpoint.Normalize()] = new Entry(destination, time.GetUtcNow() + lifetime);
        if (Interlocked.Increment(ref registrations) % PurgeInterval == 0)
        {
            PurgeExpired();
        }
    }

    /// <inheritdoc />
    public bool TryTake(IPEndPoint clientEndpoint, [NotNullWhen(true)] out OriginalDestination? destination)
    {
        ArgumentNullException.ThrowIfNull(clientEndpoint);
        if (entries.TryRemove(clientEndpoint.Normalize(), out var entry) && entry.ExpiresAt > time.GetUtcNow())
        {
            destination = entry.Destination;
            return true;
        }

        if (ExternalSource is { } source)
        {
            return source.TryTake(clientEndpoint.Normalize(), out destination);
        }

        destination = null;
        return false;
    }

    /// <inheritdoc />
    public bool Remove(IPEndPoint clientEndpoint)
    {
        ArgumentNullException.ThrowIfNull(clientEndpoint);
        return entries.TryRemove(clientEndpoint.Normalize(), out _);
    }

    /// <summary>Drops all expired entries.</summary>
    public void PurgeExpired()
    {
        var now = time.GetUtcNow();
        foreach (var pair in entries)
        {
            if (pair.Value.ExpiresAt <= now)
            {
                entries.TryRemove(pair);
            }
        }
    }

    private readonly record struct Entry(OriginalDestination Destination, DateTimeOffset ExpiresAt);
}
