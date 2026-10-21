using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Proxynator.Gui.ViewModels;
using Proxynator.Gui.Views;

namespace Proxynator.Gui;

/// <summary>Creates the view for a page view model (no reflection, so it stays trim-friendly).</summary>
internal sealed class ViewLocator : IDataTemplate
{
    public Control? Build(object? param) => param switch
    {
        OverviewViewModel => new OverviewView(),
        ConnectionsViewModel => new ConnectionsView(),
        RulesViewModel => new RulesView(),
        ProxiesViewModel => new ProxiesView(),
        SettingsViewModel => new SettingsView(),
        JsonViewModel => new JsonView(),
        LaunchViewModel => new LaunchView(),
        DiagnosticsViewModel => new DiagnosticsView(),
        _ => new TextBlock { Text = $"No view for {param?.GetType().Name}" },
    };

    public bool Match(object? data) => data is PageViewModel;
}
