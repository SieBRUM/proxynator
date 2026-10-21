using CommunityToolkit.Mvvm.ComponentModel;
using Grpc.Core;
using Proxynator.Client;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>What the GUI knows about the service: refreshed on every tick, shown on every page.</summary>
internal sealed partial class ServiceState(ServiceConnection service) : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDisconnected), nameof(CaptureFailed), nameof(Headline), nameof(CaptureMode))]
    public partial GetStatusResponse? Status { get; private set; }

    /// <summary>Why the service is not reachable, with what to do about it.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Headline))]
    public partial string Problem { get; private set; } = string.Empty;

    [ObservableProperty]
    public partial string Hint { get; private set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDisconnected))]
    public partial bool IsConnected { get; private set; }

    public bool IsDisconnected => !IsConnected;

    public bool CaptureFailed => Status?.Capture.State == CaptureState.Failed;

    /// <summary>The capture mode the service runs in, e.g. "windivert", or empty.</summary>
    public string CaptureMode => Status?.Capture.Mode ?? string.Empty;

    public string Endpoint => service.EndpointDescription;

    /// <summary>One line for the status bar.</summary>
    public string Headline => Status is { } status && IsConnected
        ? $"proxynatord {status.Version} · capture {status.Capture.Mode}: {Describe(status.Capture.State)} · {status.ActiveConnections} connection(s)"
        : Problem.Length > 0 ? Problem : "Connecting…";

    public static string Describe(CaptureState state) => state switch
    {
        CaptureState.Running => "running",
        CaptureState.Disabled => "disabled",
        CaptureState.Failed => "FAILED",
        CaptureState.Stopped => "stopped",
        _ => "unknown",
    };

    /// <summary>Asks the service for its status; returns whether it answered.</summary>
    public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            Status = await service.Client.GetStatusAsync(new GetStatusRequest(), ServiceConnection.Options(cancellationToken));
            IsConnected = true;
            Problem = string.Empty;
            Hint = string.Empty;
        }
        catch (RpcException ex)
        {
            IsConnected = false;
            Problem = service.Describe(ex);
            Hint = ServiceConnection.IsUnavailable(ex) ? ServiceHints.Unreachable(service.Endpoint)[1] : string.Empty;
        }

        OnPropertyChanged(nameof(Headline));
        OnPropertyChanged(nameof(CaptureFailed));
        return IsConnected;
    }
}
