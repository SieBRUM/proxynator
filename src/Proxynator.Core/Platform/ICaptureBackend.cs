using System.Net;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.Platform;

/// <summary>
/// Captures outbound connections and redirects those that need the relay (see
/// <see cref="Rules.RuleEngine.RequiresRelay"/>), registering each in <see cref="CaptureContext.Destinations"/>.
/// Stopping or disposing a backend must restore normal networking.
/// </summary>
public interface ICaptureBackend : IAsyncDisposable
{
    /// <summary>The capture mode this backend implements.</summary>
    CaptureMode Mode { get; }

    /// <summary>
    /// Where the relay must listen for this backend (port 0 for any free port). The actual endpoints are passed back
    /// in <see cref="CaptureContext.RelayEndpoints"/>.
    /// </summary>
    IReadOnlyList<IPEndPoint> RelayListenEndpoints { get; }

    /// <summary>Starts capturing.</summary>
    Task StartAsync(CaptureContext context, CancellationToken cancellationToken);

    /// <summary>Stops capturing and removes all redirections.</summary>
    Task StopAsync(CancellationToken cancellationToken);
}
