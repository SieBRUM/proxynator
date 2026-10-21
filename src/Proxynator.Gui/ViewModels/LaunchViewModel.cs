using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Proxynator.Client;
using Proxynator.Gui.Services;

namespace Proxynator.Gui.ViewModels;

/// <summary>
/// Starts programs with Proxynator's hook, opens hooked terminals and attaches to running processes: the GUI side of
/// <c>proxynator run|attach</c>, for the user-mode capture modes (Windows injection, Linux preload). In the
/// kernel-level modes nothing needs launching: rules match programs by name.
/// </summary>
internal sealed partial class LaunchViewModel : PageViewModel
{
    private readonly ServiceConnection service;
    private readonly IFileDialogs dialogs;

    public LaunchViewModel(ServiceConnection service, ServiceState state, IFileDialogs dialogs)
    {
        this.service = service;
        this.dialogs = dialogs;
        State = state;
        state.PropertyChanged += OnStateChanged;
    }

    public override string Title => "Launch";

    public override string Icon => "LaunchIcon";

    public ServiceState State { get; }

    public static bool CanAttach => ProgramLauncher.CanAttach;

    public static string RequiredMode => ProgramLauncher.RequiredCaptureMode;

    public static string TerminalDescription => OperatingSystem.IsWindows()
        ? "PowerShell in a new console window; every program started from it is hooked."
        : "Your shell in the desktop's terminal emulator; every program started from it is preloaded.";

    /// <summary>What to do in the service's current capture mode.</summary>
    public string ModeAdvice => State.CaptureMode switch
    {
        "" => "proxynatord is not reachable.",
        _ when State.Status?.Capture.State == Ipc.V1.CaptureState.Disabled => "proxynatord runs without capture (--no-capture): nothing is redirected.",
        var mode when mode == RequiredMode => $"proxynatord runs in {mode} mode: programs started here (and their children) follow the rules.",
        var mode => $"proxynatord runs in {mode} mode, which captures programs by name machine-wide: just start them as usual. " +
                    $"Launching here needs the {RequiredMode} mode (Settings → Capture mode, then restart proxynatord).",
    };

    /// <summary>Why launching does not work right now, or empty.</summary>
    [ObservableProperty]
    public partial string NotReady { get; private set; } = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(LaunchCommand))]
    public partial string Program { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Arguments { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string WorkingDirectory { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string ProcessFilter { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AttachCommand))]
    public partial ProcessEntry? SelectedProcess { get; set; }

    [ObservableProperty]
    public partial string Message { get; private set; } = string.Empty;

    [ObservableProperty]
    public partial bool MessageIsError { get; private set; }

    public ObservableCollection<LaunchedItem> Launched { get; } = [];

    public ObservableCollection<ProcessEntry> Processes { get; } = [];

    public override Task ActivateAsync()
    {
        CheckReady();
        if (CanAttach && Processes.Count == 0)
        {
            RefreshProcesses();
        }

        return Task.CompletedTask;
    }

    public override Task RefreshAsync()
    {
        CheckReady();
        return Task.CompletedTask;
    }

    [RelayCommand(CanExecute = nameof(HasProgram))]
    private void Launch()
    {
        var workingDirectory = WorkingDirectory.Trim().Length > 0 ? WorkingDirectory.Trim() : null;
        Run(() => service.Launcher.Start(Program.Trim(), ArgumentSplitter.Split(Arguments), workingDirectory), "started");
    }

    [RelayCommand]
    private void OpenTerminal() => Run(service.Launcher.OpenTerminal, "terminal");

    [RelayCommand(CanExecute = nameof(HasSelectedProcess))]
    private void Attach()
    {
        var process = SelectedProcess!;
        try
        {
            service.Launcher.Attach(process.ProcessId);
            Launched.Insert(0, new LaunchedItem(process.Name, process.ProcessId, "attached") { State = "hooked (new connections)" });
            Report($"Hook loaded into {process.Display}: its new connections, and those of processes it starts, follow the rules.", error: false);
        }
        catch (LaunchException ex)
        {
            Report(ex.Message, error: true);
        }
    }

    [RelayCommand]
    private void RefreshProcesses()
    {
        var own = Environment.ProcessId;
        var entries = new List<ProcessEntry>();
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id is 0 or 4 || process.Id == own)
                {
                    continue;
                }

                try
                {
                    entries.Add(new ProcessEntry(process.Id, process.ProcessName));
                }
                catch (InvalidOperationException)
                {
                    // Exited while listing.
                }
            }
        }

        Processes.Clear();
        foreach (var entry in entries.Where(e => e.Display.Contains(ProcessFilter.Trim(), StringComparison.OrdinalIgnoreCase)).OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.ProcessId))
        {
            Processes.Add(entry);
        }
    }

    [RelayCommand]
    private async Task BrowseProgramAsync()
    {
        var path = await dialogs.PickFileToOpenAsync(
            "Choose a program",
            OperatingSystem.IsWindows() ? "Programs" : null,
            OperatingSystem.IsWindows() ? ["*.exe", "*.bat", "*.cmd"] : null);
        if (path is not null)
        {
            Program = path;
        }
    }

    [RelayCommand]
    private async Task BrowseWorkingDirectoryAsync()
    {
        if (await dialogs.PickFolderAsync("Choose the working directory") is { } path)
        {
            WorkingDirectory = path;
        }
    }

    partial void OnProcessFilterChanged(string value) => RefreshProcesses();

    private bool HasProgram() => Program.Trim().Length > 0;

    private bool HasSelectedProcess() => SelectedProcess is not null;

    private void Run(Func<LaunchedProgram> start, string how)
    {
        LaunchedProgram program;
        try
        {
            program = start();
        }
        catch (LaunchException ex)
        {
            Report(ex.Message, error: true);
            return;
        }

        var item = new LaunchedItem(program.Name, program.ProcessId, how);
        Launched.Insert(0, item);
        Report($"Started {program.Name} (pid {program.ProcessId}); its connections follow the proxynatord rules.", error: false);
        _ = WaitAsync(program, item);
    }

    private static async Task WaitAsync(LaunchedProgram program, LaunchedItem item)
    {
        using (program)
        {
            try
            {
                var exitCode = await program.WaitForExitAsync(CancellationToken.None);
                item.State = $"exited ({exitCode})";
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                item.State = "unknown";
            }
        }
    }

    private void CheckReady() => NotReady = ProgramLauncher.IsSupported ? service.Launcher.CheckReady() ?? string.Empty : "Not available on this OS.";

    private void Report(string message, bool error)
    {
        Message = message;
        MessageIsError = error;
    }

    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ServiceState.Status) or nameof(ServiceState.IsConnected))
        {
            OnPropertyChanged(nameof(ModeAdvice));
        }
    }
}
