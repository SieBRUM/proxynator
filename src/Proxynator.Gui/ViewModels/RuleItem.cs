using CommunityToolkit.Mvvm.ComponentModel;
using Proxynator.Core.Configuration;
using Proxynator.Core.Net;

namespace Proxynator.Gui.ViewModels;

/// <summary>An editable rule.</summary>
internal sealed partial class RuleItem : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Name { get; set; } = "New rule";

    [ObservableProperty]
    public partial bool Enabled { get; set; } = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Processes { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial bool IncludeChildren { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Hosts { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Addresses { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Ports { get; set; } = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial bool Tcp { get; set; } = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial bool Udp { get; set; } = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary), nameof(IsProxy))]
    public partial RuleActionType Action { get; set; } = RuleActionType.Proxy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Target { get; set; } = string.Empty;

    [ObservableProperty]
    public partial UdpFallback UdpFallback { get; set; } = UdpFallback.Block;

    public bool IsProxy => Action == RuleActionType.Proxy;

    /// <summary>One line for the rule list, e.g. "nxc*, python* (+children) → proxy via pivot".</summary>
    public string Summary
    {
        get
        {
            var criteria = new List<string>();
            if (ListText.Parse(Processes) is { Count: > 0 } processes)
            {
                criteria.Add(ListText.Format(processes) + (IncludeChildren ? " (+children)" : string.Empty));
            }

            criteria.AddRange(new[] { Hosts, Addresses }.Select(ListText.Parse).Where(l => l.Count > 0).Select(ListText.Format));
            if (ListText.Parse(Ports) is { Count: > 0 } ports)
            {
                criteria.Add("port " + ListText.Format(ports));
            }

            if (Tcp != Udp)
            {
                criteria.Add(Tcp ? "tcp" : "udp");
            }

            var match = criteria.Count == 0 ? "everything" : string.Join("; ", criteria);
            var action = Action switch
            {
                RuleActionType.Proxy => $"proxy via {(Target.Length > 0 ? Target : "?")}",
                RuleActionType.Block => "block",
                _ => "direct",
            };
            return $"{match} → {action}";
        }
    }

    public static RuleItem From(RuleDefinition rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return new RuleItem
        {
            Name = rule.Name,
            Enabled = rule.Enabled,
            Processes = ListText.Format(rule.Match.Processes),
            IncludeChildren = rule.Match.IncludeChildren,
            Hosts = ListText.Format(rule.Match.Hosts),
            Addresses = ListText.Format(rule.Match.Addresses),
            Ports = ListText.Format(rule.Match.Ports),
            Tcp = rule.Match.Protocols.Count == 0 || rule.Match.Protocols.Contains(TransportProtocol.Tcp),
            Udp = rule.Match.Protocols.Count == 0 || rule.Match.Protocols.Contains(TransportProtocol.Udp),
            Action = rule.Action.Type,
            Target = rule.Action.Target ?? string.Empty,
            UdpFallback = rule.Action.Udp,
        };
    }

    public RuleItem Clone() => From(ToDefinition());

    /// <summary>The rule as configuration; with neither TCP nor UDP selected it matches both (the workspace reports that as an error first).</summary>
    public RuleDefinition ToDefinition()
    {
        List<TransportProtocol> protocols = [];
        if (Tcp != Udp)
        {
            protocols.Add(Tcp ? TransportProtocol.Tcp : TransportProtocol.Udp);
        }

        return new RuleDefinition
        {
            Name = Name.Trim(),
            Enabled = Enabled,
            Match = new RuleMatch
            {
                Processes = ListText.Parse(Processes),
                IncludeChildren = IncludeChildren,
                Hosts = ListText.Parse(Hosts),
                Addresses = ListText.Parse(Addresses),
                Ports = ListText.Parse(Ports),
                Protocols = protocols,
            },
            Action = new RuleActionDefinition
            {
                Type = Action,
                Target = Action == RuleActionType.Proxy && Target.Trim().Length > 0 ? Target.Trim() : null,
                Udp = UdpFallback,
            },
        };
    }
}
