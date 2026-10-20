using System.Net;
using Proxynator.Core.Configuration;
using Proxynator.Core.Relay;

namespace Proxynator.Core.Platform;

/// <summary>What a capture backend needs from the service.</summary>
/// <param name="Configuration">The active configuration (rules, proxy endpoints to exclude).</param>
/// <param name="Destinations">Where redirected connections are registered for the relay.</param>
/// <param name="RelayEndpoints">The relay listener endpoints to redirect to.</param>
/// <param name="ServiceProcessId">The service's own PID; its traffic must never be redirected.</param>
public sealed record CaptureContext(
    ConfigurationStore Configuration,
    IOriginalDestinationTable Destinations,
    IReadOnlyList<IPEndPoint> RelayEndpoints,
    int ServiceProcessId);
