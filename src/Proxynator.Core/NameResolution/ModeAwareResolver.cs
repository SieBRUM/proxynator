using System.Net;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.NameResolution;

/// <summary>
/// The resolver the service uses for its own lookups (proxy hostnames, direct connections to fake-IP names): the
/// upstream resolver while <see cref="DnsMode.Remote"/> is active (the system resolver would return fake answers),
/// the system resolver otherwise.
/// </summary>
public sealed class ModeAwareResolver(ConfigurationStore configuration, UpstreamDnsResolver upstream) : IHostResolver
{
    /// <summary>The upstream resolver used in remote mode.</summary>
    public UpstreamDnsResolver Upstream => upstream;

    /// <inheritdoc />
    public ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        configuration.Current.Settings.Dns.Mode == DnsMode.Remote && upstream.Servers.Count > 0
            ? upstream.ResolveAsync(host, cancellationToken)
            : SystemHostResolver.Instance.ResolveAsync(host, cancellationToken);
}
