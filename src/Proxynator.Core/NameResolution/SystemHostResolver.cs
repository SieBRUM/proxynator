using System.Net;

namespace Proxynator.Core.NameResolution;

/// <summary>The operating system's resolver (hosts file, DNS client cache, configured servers).</summary>
public sealed class SystemHostResolver : IHostResolver
{
    /// <summary>The shared instance.</summary>
    public static SystemHostResolver Instance { get; } = new();

    /// <inheritdoc />
    public async ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
        await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
}
