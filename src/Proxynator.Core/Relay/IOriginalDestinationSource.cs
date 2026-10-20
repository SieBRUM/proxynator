using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace Proxynator.Core.Relay;

/// <summary>Original destinations recorded outside the <see cref="OriginalDestinationTable"/> (e.g. by the kernel).</summary>
public interface IOriginalDestinationSource
{
    /// <summary>Removes and returns the original destination of the connection from <paramref name="clientEndpoint"/>.</summary>
    bool TryTake(IPEndPoint clientEndpoint, [NotNullWhen(true)] out OriginalDestination? destination);
}
