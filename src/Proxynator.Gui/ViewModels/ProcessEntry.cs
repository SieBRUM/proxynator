namespace Proxynator.Gui.ViewModels;

/// <summary>A running process the hook can be attached to.</summary>
internal sealed record ProcessEntry(int ProcessId, string Name)
{
    public string Display => $"{Name} ({ProcessId})";
}
