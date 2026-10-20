using System.Net;

namespace Proxynator.Core.NameResolution;

/// <summary>Resolves hostnames to addresses.</summary>
public interface IHostResolver
{
    /// <summary>Resolves <paramref name="host"/>; throws <see cref="System.Net.Sockets.SocketException"/> when it does not exist.</summary>
    ValueTask<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}
