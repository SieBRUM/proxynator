using System.Net;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// The resolver the service uses for its own lookups (proxy hostnames, direct connections to fake-IP names): the
/// upstream resolver while <see cref="DnsMode.Remote"/> is active (the system resolver would return fake answers),
/// the system resolver otherwise. Answers are kept in <paramref name="cache"/> for
/// <see cref="DnsSettings.CacheSeconds"/>; failures are not cached.
/// </summary>
public sealed class ModeAwareResolver(ConfigurationStore configuration, UpstreamDnsResolver upstream, DnsCache? cache = null) : IHostResolver
{
    private readonly DnsCache cache = cache ?? new DnsCache();

    /// <summary>The upstream resolver used in remote mode.</summary>
    public UpstreamDnsResolver Upstream => upstream;

    /// <summary>The cache answers are kept in.</summary>
    public DnsCache Cache => cache;

    /// <inheritdoc />
    public async ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (IPAddress.TryParse(host, out var literal))
        {
            return [literal];
        }

        var dns = configuration.Current.Settings.Dns;
        var useUpstream = dns.Mode == DnsMode.Remote && upstream.Servers.Count > 0;
        var lifetime = DnsCache.Lifetime(dns);
        var key = $"{(useUpstream ? "upstream" : "system")} {host.TrimEnd('.').ToUpperInvariant()}";
        if (cache.TryGet<IPAddress[]>(key, lifetime, out var cached))
        {
            return [.. cached];
        }

        var addresses = useUpstream
            ? await upstream.ResolveAsync(host, cancellationToken).ConfigureAwait(false)
            : await SystemHostResolver.Instance.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        if (addresses.Length > 0)
        {
            cache.Set(key, addresses.ToArray(), lifetime);
        }

        return addresses;
    }
}
