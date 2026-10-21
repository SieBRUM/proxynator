using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Proxynator.Core.Configuration;
using Proxynator.Gui.Services;

namespace Proxynator.Gui.ViewModels;

/// <summary>
/// The working copy as configuration JSON: for settings the forms do not cover, pasting a configuration, and
/// opening or saving files (the format of <c>config.json</c> and <c>proxynator config load</c>).
/// </summary>
internal sealed partial class JsonViewModel(ConfigWorkspace workspace, IFileDialogs dialogs) : PageViewModel
{
    private bool updatingText;

    public override string Title => "JSON";

    public override string Icon => "JsonIcon";

    public ConfigWorkspace Workspace { get; } = workspace;

    [ObservableProperty]
    public partial string Text { get; set; } = string.Empty;

    /// <summary>The text was edited and not yet taken over into the working copy.</summary>
    [ObservableProperty]
    public partial bool IsModified { get; private set; }

    public ObservableCollection<string> Messages { get; } = [];

    public override async Task ActivateAsync()
    {
        if (!Workspace.IsLoaded)
        {
            await Workspace.ReloadAsync();
        }

        if (!IsModified)
        {
            ShowWorkingCopy();
        }
    }

    partial void OnTextChanged(string value)
    {
        if (!updatingText)
        {
            IsModified = true;
        }
    }

    /// <summary>Checks the text like <c>proxynator config validate</c>.</summary>
    [RelayCommand]
    private void Validate()
    {
        var result = ConfigLoader.Parse(Text);
        SetMessages(result.Success
            ? [$"Valid: {result.Config.Proxies.Count} prox(ies), {result.Config.Chains.Count} chain(s), {result.Config.Rules.Count} rule(s)."]
            : result.Errors.Select(e => e.ToString()));
    }

    /// <summary>Makes the text the working copy (then Apply sends it to the service).</summary>
    [RelayCommand]
    private void UseText()
    {
        var errors = Workspace.Import(Text);
        if (errors.Count > 0)
        {
            SetMessages(["Not taken over: the JSON is invalid.", .. errors.Select(e => e.ToString())]);
            return;
        }

        ShowWorkingCopy();
        SetMessages(["Taken over into the working copy. Apply it to send it to proxynatord."]);
    }

    /// <summary>Throws away edits to the text.</summary>
    [RelayCommand]
    private void Reset()
    {
        ShowWorkingCopy();
        Messages.Clear();
    }

    [RelayCommand]
    private async Task OpenAsync()
    {
        var path = await dialogs.PickFileToOpenAsync("Open a Proxynator configuration", "Configuration", ["*.json"]);
        if (path is null)
        {
            return;
        }

        try
        {
            Text = await File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SetMessages([$"Cannot read {path}: {ex.Message}"]);
            return;
        }

        Validate();
        Messages.Insert(0, $"Opened {path}. Use it to take it over into the working copy.");
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        var path = await dialogs.PickFileToSaveAsync("Save the configuration", "config.json");
        if (path is null)
        {
            return;
        }

        try
        {
            await File.WriteAllTextAsync(path, Text);
            SetMessages([$"Saved to {path}. It may contain proxy passwords: keep it private."]);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SetMessages([$"Cannot write {path}: {ex.Message}"]);
        }
    }

    private void ShowWorkingCopy()
    {
        updatingText = true;
        try
        {
            Text = Workspace.ToJson();
        }
        finally
        {
            updatingText = false;
        }

        IsModified = false;
    }

    private void SetMessages(IEnumerable<string> messages)
    {
        Messages.Clear();
        foreach (var message in messages)
        {
            Messages.Add(message);
        }
    }
}
