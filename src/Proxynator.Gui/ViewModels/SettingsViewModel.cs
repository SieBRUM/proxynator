using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>Edits the global settings of the <see cref="ConfigWorkspace"/> (capture mode, DNS, UDP, relay).</summary>
internal sealed class SettingsViewModel(ConfigWorkspace workspace) : PageViewModel
{
    public override string Title => "Settings";

    public override string Icon => "SettingsIcon";

    public ConfigWorkspace Workspace { get; } = workspace;

    public static IReadOnlyList<CaptureMode> CaptureModes { get; } = Enum.GetValues<CaptureMode>();

    public static IReadOnlyList<DnsMode> DnsModes { get; } = Enum.GetValues<DnsMode>();

    public override Task ActivateAsync() => Workspace.IsLoaded ? Task.CompletedTask : Workspace.ReloadAsync();
}
