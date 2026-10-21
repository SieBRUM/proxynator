using CommunityToolkit.Mvvm.ComponentModel;
using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>An editable chain: proxy IDs in order, the first hop is connected to directly.</summary>
internal sealed partial class ChainItem : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Id { get; set; } = "chain";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Hops { get; set; } = string.Empty;

    public string Summary => string.Join(" → ", ListText.Parse(Hops));

    public static ChainItem From(ChainDefinition chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        return new ChainItem { Id = chain.Id, Hops = ListText.Format(chain.Hops) };
    }

    public ChainDefinition ToDefinition() => new() { Id = Id.Trim(), Hops = ListText.Parse(Hops) };
}
