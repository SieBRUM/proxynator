using System.Collections.ObjectModel;
using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Grpc.Core;
using Proxynator.Client;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>Service, capture and relay status, and the active rules (<c>proxynator status</c> + <c>rules list</c>).</summary>
internal sealed partial class OverviewViewModel : PageViewModel
{
    private readonly ServiceConnection service;

    public OverviewViewModel(ServiceConnection service, ServiceState state)
    {
        this.service = service;
        State = state;
        state.PropertyChanged += OnStateChanged;
    }

    public override string Title => "Overview";

    public override string Icon => "OverviewIcon";

    public ServiceState State { get; }

    public ObservableCollection<ActiveRule> Rules { get; } = [];

    public string Service => State.Status is { } s
        ? $"proxynatord {s.Version} on {s.Platform} (pid {s.ProcessId}), up {DisplayFormat.Duration(DateTimeOffset.UtcNow - s.StartedAt.ToDateTimeOffset())}"
        : "—";

    public string Capture => State.Status is { } s
        ? $"{s.Capture.Mode}: {ServiceState.Describe(s.Capture.State)}{(s.Capture.Activity.Length > 0 ? $" ({s.Capture.Activity})" : string.Empty)}"
        : "—";

    /// <summary>Why capture is failed or disabled; empty while it runs.</summary>
    public string CaptureDetail => State.Status is { Capture.State: CaptureState.Failed or CaptureState.Disabled } s ? s.Capture.Detail : string.Empty;

    public string Relay => State.Status is { } s
        ? $"TCP {string.Join(", ", s.RelayEndpoints)}   UDP {string.Join(", ", s.UdpRelayEndpoints)}"
        : "—";

    public string Dns => State.Status is { } s
        ? s.DnsMode == "remote" ? $"remote ({s.FakeIpCount} name(s) on fake addresses)" : s.DnsMode
        : "—";

    public string Config => State.Status is { } s ? $"{s.ConfigPath} ({s.RuleCount} active rule(s))" : "—";

    public string Connections => State.Status is { } s ? $"{s.ActiveConnections} active" : "—";

    public string Privileged => State.Status is { } s ? (s.Privileged ? "yes" : "NO: capture needs Administrator / root") : "—";

    [ObservableProperty]
    public partial string RulesMessage { get; private set; } = string.Empty;

    public override Task ActivateAsync() => RefreshAsync();

    public override async Task RefreshAsync()
    {
        try
        {
            var response = await service.Client.ListRulesAsync(new ListRulesRequest(), ServiceConnection.Options());
            var rules = response.Rules.Select((rule, index) => new ActiveRule(
                index + 1,
                rule.Name,
                rule.Enabled,
                rule.Match,
                rule.Action == "proxy" ? $"proxy via {string.Join(" → ", rule.Route)}" : rule.Action)).ToList();
            if (!rules.SequenceEqual(Rules))
            {
                Rules.Clear();
                foreach (var rule in rules)
                {
                    Rules.Add(rule);
                }
            }

            RulesMessage = rules.Count == 0
                ? "No rules configured: all traffic goes direct. Add some on the Rules page."
                : "Evaluated top to bottom; the first match wins. Unmatched traffic goes direct.";
        }
        catch (RpcException ex)
        {
            RulesMessage = service.Describe(ex);
        }
    }

    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(ServiceState.Status))
        {
            return;
        }

        foreach (var name in new[] { nameof(Service), nameof(Capture), nameof(CaptureDetail), nameof(Relay), nameof(Dns), nameof(Config), nameof(Connections), nameof(Privileged) })
        {
            OnPropertyChanged(name);
        }
    }
}
