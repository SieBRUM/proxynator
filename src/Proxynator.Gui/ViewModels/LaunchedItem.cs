using CommunityToolkit.Mvvm.ComponentModel;

namespace Proxynator.Gui.ViewModels;

/// <summary>A program started (or attached to) from the Launch page.</summary>
internal sealed partial class LaunchedItem(string name, int processId, string how) : ObservableObject
{
    public string Name { get; } = name;

    public int ProcessId { get; } = processId;

    /// <summary>"started", "terminal" or "attached".</summary>
    public string How { get; } = how;

    public string Started { get; } = DateTime.Now.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

    [ObservableProperty]
    public partial string State { get; set; } = "running";
}
