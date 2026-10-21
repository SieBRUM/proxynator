using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Proxynator.Core.Configuration;

namespace Proxynator.Gui.ViewModels;

/// <summary>Edits the proxies and chains of the <see cref="ConfigWorkspace"/>.</summary>
internal sealed partial class ProxiesViewModel(ConfigWorkspace workspace) : PageViewModel
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);

    public override string Title => "Proxies";

    public override string Icon => "ProxiesIcon";

    public ConfigWorkspace Workspace { get; } = workspace;

    public static IReadOnlyList<ProxyType> ProxyTypes { get; } = Enum.GetValues<ProxyType>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProxySelection))]
    [NotifyCanExecuteChangedFor(nameof(DeleteProxyCommand), nameof(TestProxyCommand))]
    public partial ProxyItem? SelectedProxy { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasChainSelection))]
    [NotifyCanExecuteChangedFor(nameof(DeleteChainCommand))]
    public partial ChainItem? SelectedChain { get; set; }

    public bool HasProxySelection => SelectedProxy is not null;

    public bool HasChainSelection => SelectedChain is not null;

    public override Task ActivateAsync() => Workspace.IsLoaded ? Task.CompletedTask : Workspace.ReloadAsync();

    [RelayCommand]
    private void AddProxy()
    {
        var proxy = new ProxyItem { Id = UniqueId("proxy") };
        Workspace.Proxies.Add(proxy);
        SelectedProxy = proxy;
    }

    /// <summary>Adds Burp Suite's default listener, the most common upstream for analysis.</summary>
    [RelayCommand]
    private void AddBurp()
    {
        var proxy = new ProxyItem { Id = UniqueId("burp"), Type = ProxyType.Http, Host = "127.0.0.1", Port = "8080" };
        Workspace.Proxies.Add(proxy);
        SelectedProxy = proxy;
    }

    [RelayCommand(CanExecute = nameof(HasProxySelection))]
    private void DeleteProxy()
    {
        Workspace.Proxies.Remove(SelectedProxy!);
        SelectedProxy = Workspace.Proxies.FirstOrDefault();
    }

    /// <summary>Checks that the proxy accepts TCP connections (from this machine, without the proxy protocol).</summary>
    [RelayCommand(CanExecute = nameof(HasProxySelection))]
    private async Task TestProxyAsync()
    {
        var proxy = SelectedProxy!;
        if (!int.TryParse(proxy.Port, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            proxy.TestResult = "Enter a port number first.";
            return;
        }

        proxy.TestResult = "Connecting…";
        using var timeout = new CancellationTokenSource(TestTimeout);
        using var client = new TcpClient();
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await client.ConnectAsync(proxy.Host.Trim(), port, timeout.Token);
            proxy.TestResult = $"Reachable: {proxy.Host}:{port} accepted a connection in {stopwatch.ElapsedMilliseconds} ms.";
        }
        catch (OperationCanceledException)
        {
            proxy.TestResult = $"No answer from {proxy.Host}:{port} within {TestTimeout.TotalSeconds:0} s.";
        }
        catch (SocketException ex)
        {
            proxy.TestResult = $"Not reachable: {ex.Message}";
        }
    }

    [RelayCommand]
    private void AddChain()
    {
        var chain = new ChainItem { Id = UniqueId("chain"), Hops = ListText.Format(Workspace.Proxies.Take(2).Select(p => p.Id)) };
        Workspace.Chains.Add(chain);
        SelectedChain = chain;
    }

    [RelayCommand(CanExecute = nameof(HasChainSelection))]
    private void DeleteChain()
    {
        Workspace.Chains.Remove(SelectedChain!);
        SelectedChain = Workspace.Chains.FirstOrDefault();
    }

    /// <summary>Proxies and chains share one ID namespace.</summary>
    private string UniqueId(string id)
    {
        var baseId = id;
        for (var n = 2; Workspace.TargetIds.Contains(id, StringComparer.OrdinalIgnoreCase); n++)
        {
            id = $"{baseId}{n}";
        }

        return id;
    }
}
