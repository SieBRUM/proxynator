using System.Collections.Concurrent;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// The answers Proxynator itself resolved: addresses from the remote DNS server (<c>resolveNames</c>), its responses
/// to SRV/TXT/... lookups, and the service's own lookups (direct connections to remote-DNS names, proxy hostnames).
/// One instance is shared by the relays and the resolver, so <see cref="Clear"/> empties all of them.
/// <para>
/// How long an entry is used is decided when it is read (<see cref="DnsSettings.CacheSeconds"/>), not when it is
/// stored, so a configuration change applies to entries already cached. Failures are never cached.
/// </para>
/// </summary>
public sealed class DnsCache(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, (object Value, DateTimeOffset Stored)> entries = new(StringComparer.Ordinal);

    /// <summary>The number of cached answers (including expired ones not looked up since).</summary>
    public int Count => entries.Count;

    /// <summary>
    /// How long answers are used under <paramref name="settings"/>: <see langword="null"/> means until cleared (or
    /// the service stops), <see cref="TimeSpan.Zero"/> means no caching.
    /// </summary>
    public static TimeSpan? Lifetime(DnsSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings.CacheSeconds switch
        {
            DnsSettings.CacheUntilCleared => null,
            <= 0 => TimeSpan.Zero,
            var seconds => TimeSpan.FromSeconds(seconds),
        };
    }

    /// <summary>The cached value for <paramref name="key"/> if it is younger than <paramref name="lifetime"/>.</summary>
    public bool TryGet<T>(string key, TimeSpan? lifetime, out T value)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(key);
        value = null!;
        if (lifetime == TimeSpan.Zero || !entries.TryGetValue(key, out var entry))
        {
            return false;
        }

        if (lifetime is { } limit && clock.GetUtcNow() - entry.Stored >= limit)
        {
            entries.TryRemove(new KeyValuePair<string, (object, DateTimeOffset)>(key, entry));
            return false;
        }

        if (entry.Value is not T typed)
        {
            return false;
        }

        value = typed;
        return true;
    }

    /// <summary>Stores <paramref name="value"/> unless caching is off (<paramref name="lifetime"/> zero).</summary>
    public void Set(string key, object value, TimeSpan? lifetime)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        if (lifetime != TimeSpan.Zero)
        {
            entries[key] = (value, clock.GetUtcNow());
        }
    }

    /// <summary>Forgets every answer; returns how many there were.</summary>
    public int Clear()
    {
        var count = 0;
        foreach (var key in entries.Keys)
        {
            if (entries.TryRemove(key, out _))
            {
                count++;
            }
        }

        return count;
    }
}
