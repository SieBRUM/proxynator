using System.Net;
using Proxynator.Core.Configuration;
using Proxynator.Core.NameResolution;
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
    int ServiceProcessId)
{
    /// <summary>Where redirected UDP flows are registered for the UDP relay; null when UDP is not relayed.</summary>
    public IOriginalDestinationTable? UdpDestinations { get; init; }

    /// <summary>The UDP relay endpoints to redirect UDP flows to.</summary>
    public IReadOnlyList<IPEndPoint> UdpRelayEndpoints { get; init; } = [];

    /// <summary>The fake-IP pool: connections to its addresses always go to the relay, which knows the real hostname.</summary>
    public FakeIpPool? FakeIps { get; init; }

    /// <summary>
    /// Where user-mode hooks (injected DLL, preload library) register connections: a pipe name on Windows, a socket
    /// path elsewhere. Null when the service has no hook endpoint.
    /// </summary>
    public string? HookEndpoint { get; init; }
}
