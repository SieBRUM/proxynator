using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>Edits the ordered rule list of the <see cref="ConfigWorkspace"/>.</summary>
internal sealed partial class RulesViewModel(ConfigWorkspace workspace) : PageViewModel
{
    public override string Title => "Rules";

    public override string Icon => "RulesIcon";

    public ConfigWorkspace Workspace { get; } = workspace;

    public static IReadOnlyList<RuleActionType> Actions { get; } = Enum.GetValues<RuleActionType>();

    public static IReadOnlyList<UdpFallback> UdpFallbacks { get; } = Enum.GetValues<UdpFallback>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyCanExecuteChangedFor(nameof(DuplicateCommand), nameof(DeleteCommand), nameof(MoveUpCommand), nameof(MoveDownCommand))]
    public partial RuleItem? SelectedRule { get; set; }

    public bool HasSelection => SelectedRule is not null;

    public override Task ActivateAsync() => Workspace.IsLoaded ? Task.CompletedTask : Workspace.ReloadAsync();

    [RelayCommand]
    private void Add()
    {
        var rule = new RuleItem
        {
            Name = UniqueName("New rule"),
            Target = Workspace.TargetIds.FirstOrDefault() ?? string.Empty,
            Action = Workspace.TargetIds.Count > 0 ? RuleActionType.Proxy : RuleActionType.Direct,
        };

        // New rules go above the selected one (or at the end), so they are not shadowed by a catch-all.
        var index = SelectedRule is null ? Workspace.Rules.Count : Workspace.Rules.IndexOf(SelectedRule);
        Workspace.Rules.Insert(index, rule);
        SelectedRule = rule;
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void Duplicate()
    {
        var copy = SelectedRule!.Clone();
        copy.Name = UniqueName(SelectedRule.Name);
        Workspace.Rules.Insert(Workspace.Rules.IndexOf(SelectedRule) + 1, copy);
        SelectedRule = copy;
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void Delete()
    {
        var index = Workspace.Rules.IndexOf(SelectedRule!);
        Workspace.Rules.RemoveAt(index);
        SelectedRule = Workspace.Rules.Count == 0 ? null : Workspace.Rules[Math.Min(index, Workspace.Rules.Count - 1)];
    }

    [RelayCommand(CanExecute = nameof(CanMoveUp))]
    private void MoveUp() => Move(-1);

    [RelayCommand(CanExecute = nameof(CanMoveDown))]
    private void MoveDown() => Move(1);

    private bool CanMoveUp() => SelectedRule is not null && Workspace.Rules.IndexOf(SelectedRule) > 0;

    private bool CanMoveDown() => SelectedRule is not null && Workspace.Rules.IndexOf(SelectedRule) < Workspace.Rules.Count - 1;

    private void Move(int offset)
    {
        var rule = SelectedRule!;
        var index = Workspace.Rules.IndexOf(rule);
        Workspace.Rules.Move(index, index + offset);
        SelectedRule = rule;
        MoveUpCommand.NotifyCanExecuteChanged();
        MoveDownCommand.NotifyCanExecuteChanged();
    }

    private string UniqueName(string name)
    {
        var baseName = name;
        for (var n = 2; Workspace.Rules.Any(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)); n++)
        {
            name = $"{baseName} ({n})";
        }

        return name;
    }
}
