using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using Grpc.Core;
using Proxynator.Core.Configuration;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>
/// The configuration being edited: a working copy of the service's configuration shared by the Rules, Proxies,
/// Settings and JSON pages. Changes are validated as they are made and only reach the service on
/// <see cref="ApplyAsync"/>, which validates again and swaps the configuration atomically (like
/// <c>proxynator config load</c>). Settings the editors do not show are kept as they were.
/// </summary>
internal sealed partial class ConfigWorkspace : ObservableObject
{
    private readonly ServiceConnection service;
    private ProxynatorConfig baseConfig = new() { Version = ConfigVersion.Current };
    private string loadedJson = string.Empty;
    private bool suspendTracking;

    public ConfigWorkspace(ServiceConnection service)
    {
        this.service = service;
        Rules.CollectionChanged += OnCollectionChanged;
        Proxies.CollectionChanged += OnCollectionChanged;
        Chains.CollectionChanged += OnCollectionChanged;
        Settings.PropertyChanged += OnItemChanged;
    }

    public ObservableCollection<RuleItem> Rules { get; } = [];

    public ObservableCollection<ProxyItem> Proxies { get; } = [];

    public ObservableCollection<ChainItem> Chains { get; } = [];

    /// <summary>Proxy and chain IDs, the possible rule targets.</summary>
    public ObservableCollection<string> TargetIds { get; } = [];

    /// <summary>Validation problems of the working copy, in words (e.g. "Rule 'burp': ...").</summary>
    public ObservableCollection<string> Problems { get; } = [];

    [ObservableProperty]
    public partial SettingsItem Settings { get; private set; } = new();

    /// <summary>The working copy differs from what was loaded from the service.</summary>
    [ObservableProperty]
    public partial bool IsDirty { get; private set; }

    /// <summary>Whether the configuration has been loaded from the service at least once.</summary>
    [ObservableProperty]
    public partial bool IsLoaded { get; private set; }

    [ObservableProperty]
    public partial bool IsBusy { get; private set; }

    /// <summary>The result of the last load or apply.</summary>
    [ObservableProperty]
    public partial string StatusMessage { get; set; } = string.Empty;

    /// <summary>The service's configuration file.</summary>
    [ObservableProperty]
    public partial string ConfigPath { get; private set; } = string.Empty;

    /// <summary>Loads the service's active configuration, discarding changes.</summary>
    public async Task<bool> ReloadAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await service.Client.GetConfigAsync(new GetConfigRequest(), ServiceConnection.Options(cancellationToken));
            return LoadFromService(response);
        }
        catch (RpcException ex)
        {
            StatusMessage = service.Describe(ex);
            return false;
        }
    }

    /// <summary>Picks up configuration changes made elsewhere (CLI, another GUI) while nothing is being edited.</summary>
    public async Task RefreshIfUnchangedAsync(CancellationToken cancellationToken = default)
    {
        if (IsDirty || IsBusy)
        {
            return;
        }

        var response = await service.Client.GetConfigAsync(new GetConfigRequest(), ServiceConnection.Options(cancellationToken));
        if (!IsDirty && response.Json != loadedJson)
        {
            LoadFromService(response);
        }
    }

    /// <summary>Discards the changes.</summary>
    public Task<bool> DiscardAsync() => ReloadAsync();

    /// <summary>
    /// Sends the working copy to the service, which validates and applies it atomically, and with
    /// <paramref name="persist"/> saves it as its configuration file.
    /// </summary>
    public async Task<bool> ApplyAsync(bool persist, CancellationToken cancellationToken = default)
    {
        Revalidate();
        if (Problems.Count > 0)
        {
            StatusMessage = "Fix the problems first; nothing was applied.";
            return false;
        }

        IsBusy = true;
        try
        {
            var json = ConfigLoader.Serialize(Build(out _));
            var response = await service.Client.ApplyConfigAsync(new ApplyConfigRequest { Json = json, Persist = persist }, ServiceConnection.Options(cancellationToken));
            if (!response.Applied)
            {
                SetProblems(response.Errors.Select(e => new Core.Configuration.ConfigError(e.Path, e.Message)));
                StatusMessage = "The service rejected the configuration; the previous one is still active.";
                return false;
            }

            var message = persist switch
            {
                true when response.Persisted => "Applied and saved. New connections use it; open connections are not affected.",
                true => $"Applied, but NOT saved: {response.PersistError}",
                false => "Applied until the service restarts (not saved). New connections use it.",
            };
            if (response.RestartRequiredReason.Length > 0)
            {
                message += " " + response.RestartRequiredReason;
            }

            await ReloadAsync(cancellationToken);
            StatusMessage = message;
            return true;
        }
        catch (RpcException ex)
        {
            StatusMessage = service.Describe(ex);
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Replaces the working copy with <paramref name="json"/> (a whole configuration file) when it is valid.</summary>
    public IReadOnlyList<Core.Configuration.ConfigError> Import(string json)
    {
        var result = ConfigLoader.Parse(json);
        if (!result.Success)
        {
            return result.Errors;
        }

        Load(result.Config, dirty: true);
        return [];
    }

    /// <summary>The working copy as configuration JSON (what <see cref="ApplyAsync"/> would send).</summary>
    public string ToJson() => ConfigLoader.Serialize(Build(out _));

    /// <summary>Re-checks the working copy and updates <see cref="Problems"/>.</summary>
    public void Revalidate()
    {
        var config = Build(out var problems);

        // A value the editor could not convert is reported once, in the editor's words.
        var reported = problems.Select(p => p.Path).ToHashSet(StringComparer.Ordinal);
        SetProblems([.. problems, .. ConfigValidator.Validate(config).Where(e => !reported.Contains(e.Path))]);
    }

    /// <summary>
    /// The working copy as configuration. Values the editor cannot convert (a port that is not a number) are
    /// reported in <paramref name="problems"/>; validation itself is <see cref="ConfigValidator"/>'s job.
    /// </summary>
    public ProxynatorConfig Build(out List<Core.Configuration.ConfigError> problems)
    {
        problems = [];
        for (var i = 0; i < Proxies.Count; i++)
        {
            if (!Proxies[i].HasNumericPort)
            {
                problems.Add(new($"$.proxies[{i}].port", "Enter a port number."));
            }
        }

        for (var i = 0; i < Rules.Count; i++)
        {
            if (!Rules[i].Tcp && !Rules[i].Udp)
            {
                problems.Add(new($"$.rules[{i}].match.protocols", "Select TCP, UDP or both."));
            }
        }

        return baseConfig with
        {
            Version = ConfigVersion.Current,
            Settings = Settings.ToSettings(baseConfig.Settings, problems),
            Proxies = [.. Proxies.Select(p => p.ToDefinition())],
            Chains = [.. Chains.Select(c => c.ToDefinition())],
            Rules = [.. Rules.Select(r => r.ToDefinition())],
        };
    }

    /// <summary>Turns a JSON path into words: <c>$.rules[1].action.target</c> → <c>Rule 'burp' (action.target)</c>.</summary>
    public string Describe(Core.Configuration.ConfigError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        var match = ItemPath().Match(error.Path);
        if (!match.Success)
        {
            return error.Path is "$" ? error.Message : $"{error.Path.TrimStart('$', '.')}: {error.Message}";
        }

        var index = int.Parse(match.Groups["index"].Value, CultureInfo.InvariantCulture);
        var rest = match.Groups["rest"].Value.TrimStart('.');
        var item = match.Groups["kind"].Value switch
        {
            "rules" => $"Rule '{(index < Rules.Count ? Rules[index].Name : index.ToString(CultureInfo.InvariantCulture))}'",
            "proxies" => $"Proxy '{(index < Proxies.Count ? Proxies[index].Id : index.ToString(CultureInfo.InvariantCulture))}'",
            _ => $"Chain '{(index < Chains.Count ? Chains[index].Id : index.ToString(CultureInfo.InvariantCulture))}'",
        };
        return rest.Length > 0 ? $"{item} ({rest}): {error.Message}" : $"{item}: {error.Message}";
    }

    private bool LoadFromService(GetConfigResponse response)
    {
        var result = ConfigLoader.Parse(response.Json);
        if (!result.Success)
        {
            // The service only holds valid configurations; this would be a version mismatch with the GUI.
            StatusMessage = $"The service's configuration cannot be edited by this version of the GUI: {result.Errors[0]}";
            return false;
        }

        ConfigPath = response.Path;
        loadedJson = response.Json;
        Load(result.Config, dirty: false);
        StatusMessage = string.Empty;
        IsLoaded = true;
        return true;
    }

    private void Load(ProxynatorConfig config, bool dirty)
    {
        suspendTracking = true;
        try
        {
            baseConfig = config;
            Replace(Rules, config.Rules.Select(RuleItem.From));
            Replace(Proxies, config.Proxies.Select(ProxyItem.From));
            Replace(Chains, config.Chains.Select(ChainItem.From));
            Settings.PropertyChanged -= OnItemChanged;
            Settings = SettingsItem.From(config.Settings);
            Settings.PropertyChanged += OnItemChanged;
            UpdateTargets();
        }
        finally
        {
            suspendTracking = false;
        }

        IsDirty = dirty;
        Revalidate();
    }

    private void Replace<T>(ObservableCollection<T> collection, IEnumerable<T> items)
        where T : INotifyPropertyChanged
    {
        foreach (var old in collection)
        {
            old.PropertyChanged -= OnItemChanged;
        }

        collection.Clear();
        foreach (var item in items)
        {
            collection.Add(item);
        }
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        foreach (var item in e.OldItems?.OfType<INotifyPropertyChanged>() ?? [])
        {
            item.PropertyChanged -= OnItemChanged;
        }

        foreach (var item in e.NewItems?.OfType<INotifyPropertyChanged>() ?? [])
        {
            item.PropertyChanged += OnItemChanged;
        }

        Changed(sender is not ObservableCollection<RuleItem>);
    }

    private void OnItemChanged(object? sender, PropertyChangedEventArgs e)
    {
        // Derived properties (Summary, ...) and test results are not edits.
        if (e.PropertyName is nameof(RuleItem.Summary) or nameof(RuleItem.IsProxy) or nameof(ProxyItem.SupportsPassword) or
            nameof(ProxyItem.TestResult) or nameof(SettingsItem.IsRemoteDns))
        {
            return;
        }

        Changed(sender is ProxyItem or ChainItem && e.PropertyName == nameof(ProxyItem.Id));
    }

    private void Changed(bool targetsChanged)
    {
        if (suspendTracking)
        {
            return;
        }

        if (targetsChanged)
        {
            UpdateTargets();
        }

        IsDirty = true;
        Revalidate();
    }

    private void UpdateTargets()
    {
        var ids = Proxies.Select(p => p.Id).Concat(Chains.Select(c => c.Id)).Where(id => id.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (!ids.SequenceEqual(TargetIds))
        {
            TargetIds.Clear();
            foreach (var id in ids)
            {
                TargetIds.Add(id);
            }
        }
    }

    private void SetProblems(IEnumerable<Core.Configuration.ConfigError> errors)
    {
        var described = errors.Select(Describe).Distinct().ToList();
        if (described.SequenceEqual(Problems))
        {
            return;
        }

        Problems.Clear();
        foreach (var problem in described)
        {
            Problems.Add(problem);
        }

        OnPropertyChanged(nameof(ProblemSummary));
    }

    /// <summary>"No problems", "1 problem", "3 problems".</summary>
    public string ProblemSummary => Problems.Count switch
    {
        0 => "No problems",
        1 => "1 problem",
        var n => $"{n} problems",
    };

    [GeneratedRegex(@"^\$\.(?<kind>rules|proxies|chains)\[(?<index>\d+)\](?<rest>.*)$")]
    private static partial Regex ItemPath();
}
