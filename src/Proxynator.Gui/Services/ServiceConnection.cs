using Grpc.Core;
using Grpc.Net.Client;
using Proxynator.Client;
using Proxynator.Ipc;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.Services;

/// <summary>The GUI's connection to proxynatord: one channel for the whole session, reconnecting on demand.</summary>
internal sealed class ServiceConnection : IDisposable
{
    /// <summary>The deadline for request/response calls, so the UI never waits on a stuck service.</summary>
    public static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(10);

    private readonly GrpcChannel channel;

    public ServiceConnection(string endpoint)
    {
        Endpoint = endpoint;
        channel = ControlClientFactory.CreateChannel(endpoint);
        Client = ControlClientFactory.CreateClient(channel);
        Launcher = new ProgramLauncher(endpoint);
    }

    /// <summary>The control endpoint (pipe name or socket path).</summary>
    public string Endpoint { get; }

    /// <summary>A human-readable form of <see cref="Endpoint"/>.</summary>
    public string EndpointDescription => IpcEndpoint.Describe(Endpoint);

    public Control.ControlClient Client { get; }

    public ProgramLauncher Launcher { get; }

    /// <summary>Call options with <see cref="CallTimeout"/>.</summary>
    public static CallOptions Options(CancellationToken cancellationToken = default) =>
        new(deadline: DateTime.UtcNow + CallTimeout, cancellationToken: cancellationToken);

    /// <summary>Whether <paramref name="exception"/> means the service is not running or not reachable.</summary>
    public static bool IsUnavailable(RpcException exception) =>
        exception.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded;

    /// <summary>A one-line description of a failed call.</summary>
    public string Describe(RpcException exception) => IsUnavailable(exception)
        ? ServiceHints.Unreachable(Endpoint)[0]
        : $"proxynatord returned an error: {exception.Status.Detail} ({exception.StatusCode})";

    public void Dispose() => channel.Dispose();
}
