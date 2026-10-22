using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using Proxynator.Gui.Services;

namespace Proxynator.Gui.ViewModels;

/// <summary>The main window: navigation, the service status line and the bar for applying configuration changes.</summary>
internal sealed partial class MainWindowViewModel : ObservableObject, IDisposable
{
    /// <summary>How often status, connection counters and the configuration are refreshed.</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    private readonly ServiceConnection service;
    private readonly IServiceLauncher launcher;
    private DispatcherTimer? timer;
    private bool refreshing;

    public MainWindowViewModel(ServiceConnection service, IFileDialogs dialogs, IServiceLauncher? launcher = null)
    {
        this.service = service;
        this.launcher = launcher ?? new ServiceLauncher();
        State = new ServiceState(service);
        Workspace = new ConfigWorkspace(service);
        Overview = new OverviewViewModel(service, State);
        Connections = new ConnectionsViewModel(service);
        Rules = new RulesViewModel(Workspace);
        Proxies = new ProxiesViewModel(Workspace);
        Settings = new SettingsViewModel(Workspace);
        Json = new JsonViewModel(Workspace, dialogs);
        Launch = new LaunchViewModel(service, State, dialogs);
        Diagnostics = new DiagnosticsViewModel(service);
        Pages = [Overview, Connections, Rules, Proxies, Settings, Json, Launch, Diagnostics];
        SelectedPage = Overview;
    }

    public ServiceState State { get; }

    public ConfigWorkspace Workspace { get; }

    public OverviewViewModel Overview { get; }

    public ConnectionsViewModel Connections { get; }

    public RulesViewModel Rules { get; }

    public ProxiesViewModel Proxies { get; }

    public SettingsViewModel Settings { get; }

    public JsonViewModel Json { get; }

    public LaunchViewModel Launch { get; }

    public DiagnosticsViewModel Diagnostics { get; }

    public IReadOnlyList<PageViewModel> Pages { get; }

    [ObservableProperty]
    public partial PageViewModel SelectedPage { get; set; }

    public string Title => $"Proxynator — {service.EndpointDescription}";

    /// <summary>Starts the refresh timer and the connection watch; call once the window is shown.</summary>
    public void Start()
    {
        Connections.Start();
        timer = new DispatcherTimer(RefreshInterval, DispatcherPriority.Background, async (_, _) => await TickAsync());
        timer.Start();
        _ = TickAsync();
    }

    /// <summary>
    /// Refreshes the status, then (when the service answers) picks up outside configuration changes and refreshes
    /// the visible page. Overlapping ticks are skipped.
    /// </summary>
    public async Task TickAsync()
    {
        if (refreshing)
        {
            return;
        }

        refreshing = true;
        try
        {
            if (!await State.RefreshAsync())
            {
                return;
            }

            if (!Workspace.IsLoaded)
            {
                await Workspace.ReloadAsync();
            }
            else
            {
                await Workspace.RefreshIfUnchangedAsync();
            }

            await SelectedPage.RefreshAsync();
        }
        catch (RpcException)
        {
            // Reported by the next status refresh.
        }
        finally
        {
            refreshing = false;
        }
    }

    /// <summary>The result of the last "Start proxynatord" (or why it cannot be started from here).</summary>
    [ObservableProperty]
    public partial string StartServiceMessage { get; private set; } = string.Empty;

    /// <summary>
    /// Starts proxynatord elevated (UAC / polkit prompt): the installed service, or the executable next to the GUI.
    /// The next refresh picks it up once it accepts connections.
    /// </summary>
    [RelayCommand]
    private async Task StartServiceAsync()
    {
        if (launcher.Plan(service.Endpoint, out var problem) is not { } plan)
        {
            StartServiceMessage = problem;
            return;
        }

        if (launcher.Start(plan) is { } failure)
        {
            StartServiceMessage = failure;
            return;
        }

        StartServiceMessage = $"Started: {plan.Description}. Waiting for it to accept connections…";
        for (var attempt = 0; attempt < 20 && !await State.RefreshAsync(); attempt++)
        {
            await Task.Delay(500);
        }

        StartServiceMessage = State.IsConnected ? string.Empty : $"{plan.Description} was started, but proxynatord is not answering yet. Check its window or 'journalctl -u proxynatord'.";
        if (State.IsConnected)
        {
            await TickAsync();
        }
    }

    [RelayCommand]
    private async Task ApplyAsync() => await Workspace.ApplyAsync(persist: false);

    [RelayCommand]
    private async Task ApplyAndSaveAsync() => await Workspace.ApplyAsync(persist: true);

    [RelayCommand]
    private async Task DiscardAsync() => await Workspace.DiscardAsync();

    partial void OnSelectedPageChanged(PageViewModel value) => _ = ActivateAsync(value);

    private static async Task ActivateAsync(PageViewModel page)
    {
        try
        {
            await page.ActivateAsync();
        }
        catch (RpcException)
        {
            // The page shows the service as unreachable through ServiceState.
        }
    }

    public void Dispose()
    {
        timer?.Stop();
        Connections.Dispose();
        service.Dispose();
    }
}
