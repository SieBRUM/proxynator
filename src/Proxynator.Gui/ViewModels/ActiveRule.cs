namespace Proxynator.Gui.ViewModels;

/// <summary>A row of the active rules table on the overview.</summary>
internal sealed record ActiveRule(int Number, string Name, bool Enabled, string Match, string Action)
{
    public string State => Enabled ? string.Empty : "disabled";
}
