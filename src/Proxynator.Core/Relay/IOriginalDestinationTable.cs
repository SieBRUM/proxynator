using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace Proxynator.Core.Relay;

/// <summary>
/// The hand-over point between capture backends and the relay. A backend registers a redirected connection under
/// the client endpoint the relay will see as the peer of the accepted socket; the relay takes it on accept.
/// </summary>
public interface IOriginalDestinationTable
{
    /// <summary>Records the original destination of a connection from <paramref name="clientEndpoint"/>.</summary>
    void Register(IPEndPoint clientEndpoint, OriginalDestination destination);

    /// <summary>Removes and returns the entry for <paramref name="clientEndpoint"/>.</summary>
    bool TryTake(IPEndPoint clientEndpoint, [NotNullWhen(true)] out OriginalDestination? destination);

    /// <summary>Removes the entry for <paramref name="clientEndpoint"/> without using it (e.g. the connect failed).</summary>
    bool Remove(IPEndPoint clientEndpoint);

    /// <summary>
    /// Consulted by <see cref="TryTake"/> for connections nobody registered: kernel-level backends that record
    /// original destinations themselves (e.g. in a BPF map) plug in here.
    /// </summary>
    IOriginalDestinationSource? ExternalSource { get; set; }
}
