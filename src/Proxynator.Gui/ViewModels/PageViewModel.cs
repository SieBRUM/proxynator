using CommunityToolkit.Mvvm.ComponentModel;

namespace Proxynator.Gui.ViewModels;

/// <summary>A page of the main window.</summary>
internal abstract class PageViewModel : ObservableObject
{
    /// <summary>The title in the navigation list.</summary>
    public abstract string Title { get; }

    /// <summary>The key of the icon geometry in the application resources.</summary>
    public abstract string Icon { get; }

    /// <summary>Called when the page is shown.</summary>
    public virtual Task ActivateAsync() => Task.CompletedTask;

    /// <summary>Called on every refresh tick while the page is shown and the service is reachable.</summary>
    public virtual Task RefreshAsync() => Task.CompletedTask;
}
