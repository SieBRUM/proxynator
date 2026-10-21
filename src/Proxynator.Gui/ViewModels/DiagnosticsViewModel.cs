using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>Health checks (<c>proxynator doctor</c>): privileges, driver files, capture, relay, proxy reachability.</summary>
internal sealed partial class DiagnosticsViewModel(ServiceConnection service) : PageViewModel
{
    public override string Title => "Diagnostics";

    public override string Icon => "DiagnosticsIcon";

    public ObservableCollection<DiagnosticItem> Results { get; } = [];

    [ObservableProperty]
    public partial bool IsRunning { get; private set; }

    [ObservableProperty]
    public partial string Summary { get; private set; } = string.Empty;

    public override Task ActivateAsync() => Results.Count == 0 ? RunCommand.ExecuteAsync(null) : Task.CompletedTask;

    [RelayCommand]
    private async Task RunAsync()
    {
        IsRunning = true;
        Results.Clear();
        try
        {
            var response = await service.Client.RunDiagnosticsAsync(new RunDiagnosticsRequest(), ServiceConnection.Options());
            Results.Add(new DiagnosticItem("Service", DiagnosticStatus.Ok, $"proxynatord is reachable at {service.EndpointDescription}."));
            foreach (var result in response.Results)
            {
                Results.Add(new DiagnosticItem(result.Name, result.Status, result.Detail));
            }
        }
        catch (RpcException ex)
        {
            Results.Add(new DiagnosticItem("Service", DiagnosticStatus.Error, service.Describe(ex)));
        }
        finally
        {
            IsRunning = false;
        }

        var errors = Results.Count(r => r.Status == DiagnosticStatus.Error);
        var warnings = Results.Count(r => r.Status == DiagnosticStatus.Warning);
        Summary = errors + warnings == 0 ? "Everything looks fine." : $"{errors} error(s), {warnings} warning(s).";
    }
}
