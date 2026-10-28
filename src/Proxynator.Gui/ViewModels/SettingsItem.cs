using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>The editable global settings.</summary>
internal sealed partial class SettingsItem : ObservableObject
{
    [ObservableProperty]
    public partial CaptureMode CaptureMode { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRemoteDns))]
    public partial DnsMode DnsMode { get; set; }

    [ObservableProperty]
    public partial string FakeIpRange { get; set; } = DnsSettings.DefaultFakeIpRange;

    [ObservableProperty]
    public partial string RemoteDomains { get; set; } = "*";

    [ObservableProperty]
    public partial bool UseRemoteServer { get; set; }

    [ObservableProperty]
    public partial string RemoteServerAddress { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string RemoteServerPort { get; set; } = "53";

    [ObservableProperty]
    public partial string RemoteServerVia { get; set; } = string.Empty;

    /// <summary>Resolve remote domains with the remote server and give proxies addresses (for pivots that cannot resolve).</summary>
    [ObservableProperty]
    public partial bool RemoteServerResolveNames { get; set; }

    [ObservableProperty]
    public partial string SniffTimeoutMs { get; set; } = "250";

    [ObservableProperty]
    public partial string DnsCacheSeconds { get; set; } = "60";

    [ObservableProperty]
    public partial bool DnsCacheUntilCleared { get; set; }

    [ObservableProperty]
    public partial bool BlockQuic { get; set; } = true;

    [ObservableProperty]
    public partial string ConnectTimeoutMs { get; set; } = "10000";

    public bool IsRemoteDns => DnsMode == DnsMode.Remote;

    public static SettingsItem From(ProxynatorSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var dns = settings.Dns;
        return new SettingsItem
        {
            CaptureMode = settings.Capture.Mode,
            DnsMode = dns.Mode,
            FakeIpRange = dns.FakeIpRange,
            RemoteDomains = ListText.Format(dns.RemoteDomains),
            UseRemoteServer = dns.RemoteServer is not null,
            RemoteServerAddress = dns.RemoteServer?.Address ?? string.Empty,
            RemoteServerPort = (dns.RemoteServer?.Port ?? 53).ToString(CultureInfo.InvariantCulture),
            RemoteServerVia = dns.RemoteServer?.Via ?? string.Empty,
            RemoteServerResolveNames = dns.RemoteServer?.ResolveNames ?? false,
            SniffTimeoutMs = dns.SniffTimeoutMs.ToString(CultureInfo.InvariantCulture),
            DnsCacheUntilCleared = dns.CacheSeconds == DnsSettings.CacheUntilCleared,
            DnsCacheSeconds = (dns.CacheSeconds == DnsSettings.CacheUntilCleared ? 60 : dns.CacheSeconds).ToString(CultureInfo.InvariantCulture),
            BlockQuic = settings.Udp.BlockQuic,
            ConnectTimeoutMs = settings.Relay.ConnectTimeoutMs.ToString(CultureInfo.InvariantCulture),
        };
    }

    /// <summary>
    /// The settings as configuration, keeping what this editor does not show from <paramref name="original"/>;
    /// numbers that do not parse are reported in <paramref name="problems"/>.
    /// </summary>
    public ProxynatorSettings ToSettings(ProxynatorSettings original, List<ConfigError> problems)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(problems);
        var remoteServer = UseRemoteServer
            ? new RemoteDnsServer
            {
                Address = RemoteServerAddress.Trim(),
                Port = Number(RemoteServerPort, "$.settings.dns.remoteServer.port", 53),
                Via = RemoteServerVia.Trim(),
                ResolveNames = RemoteServerResolveNames,
            }
            : null;
        return original with
        {
            Capture = original.Capture with { Mode = CaptureMode },
            Dns = original.Dns with
            {
                Mode = DnsMode,
                FakeIpRange = FakeIpRange.Trim(),
                RemoteDomains = ListText.Parse(RemoteDomains),
                RemoteServer = remoteServer,
                SniffTimeoutMs = Number(SniffTimeoutMs, "$.settings.dns.sniffTimeoutMs", 250),
                CacheSeconds = DnsCacheUntilCleared ? DnsSettings.CacheUntilCleared : Number(DnsCacheSeconds, "$.settings.dns.cacheSeconds", 60, NumberStyles.AllowLeadingSign), // -1 works too
            },
            Udp = original.Udp with { BlockQuic = BlockQuic },
            Relay = original.Relay with { ConnectTimeoutMs = Number(ConnectTimeoutMs, "$.settings.relay.connectTimeoutMs", 10_000) },
        };

        int Number(string text, string path, int fallback, NumberStyles styles = NumberStyles.None)
        {
            if (int.TryParse(text.Trim(), styles, CultureInfo.InvariantCulture, out var value))
            {
                return value;
            }

            problems.Add(new ConfigError(path, "Enter a whole number."));
            return fallback;
        }
    }
}
