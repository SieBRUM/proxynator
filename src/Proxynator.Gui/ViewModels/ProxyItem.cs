using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>An editable proxy.</summary>
internal sealed partial class ProxyItem : ObservableObject
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Id { get; set; } = "proxy";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary), nameof(SupportsPassword))]
    public partial ProxyType Type { get; set; } = ProxyType.Socks5;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Host { get; set; } = "127.0.0.1";

    /// <summary>The port as typed; the workspace reports it when it is not a number.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Summary))]
    public partial string Port { get; set; } = "1080";

    [ObservableProperty]
    public partial string Username { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string Password { get; set; } = string.Empty;

    /// <summary>The result of the last reachability test.</summary>
    [ObservableProperty]
    public partial string TestResult { get; set; } = string.Empty;

    /// <summary>SOCKS4 has a user ID but no password; SOCKS5 and HTTP have both.</summary>
    public bool SupportsPassword => Type is not ProxyType.Socks4 and not ProxyType.Socks4a;

    public string Summary => $"{Type.ToString().ToLowerInvariant()}://{Host}:{Port}";

    public static ProxyItem From(ProxyDefinition proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        return new ProxyItem
        {
            Id = proxy.Id,
            Type = proxy.Type,
            Host = proxy.Host,
            Port = proxy.Port.ToString(CultureInfo.InvariantCulture),
            Username = proxy.Auth?.Username ?? string.Empty,
            Password = proxy.Auth?.Password ?? string.Empty,
        };
    }

    /// <summary>Whether <see cref="Port"/> is a number (whether it is a valid port is the validator's call).</summary>
    public bool HasNumericPort => int.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out _);

    /// <summary>The proxy as configuration; a port that is not a number becomes 0.</summary>
    public ProxyDefinition ToDefinition() => new()
    {
        Id = Id.Trim(),
        Type = Type,
        Host = Host.Trim(),
        Port = int.TryParse(Port.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var port) ? port : 0,
        Auth = Username.Length > 0 ? new ProxyAuth { Username = Username, Password = SupportsPassword && Password.Length > 0 ? Password : null } : null,
    };
}
