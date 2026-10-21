using System.Collections.ObjectModel;
using Avalonia.Collections;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>
/// Live connections (<c>proxynator connections --follow</c>): the current list, then opened/closed events as they
/// happen; byte counters are refreshed on every tick. Closed connections stay in the list (up to
/// <see cref="ClosedLimit"/>) so short-lived ones can still be inspected.
/// </summary>
internal sealed partial class ConnectionsViewModel : PageViewModel, IDisposable
{
    public const int ClosedLimit = 1000;

    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(2);

    private readonly ServiceConnection service;
    private readonly Dictionary<long, ConnectionRow> byId = [];
    private readonly CancellationTokenSource stop = new();
    private Task? watchLoop;

    public ConnectionsViewModel(ServiceConnection service)
    {
        this.service = service;
        View = new DataGridCollectionView(Rows) { Filter = item => item is ConnectionRow row && row.Matches(Filter) && (ShowClosed || row.IsOpen) };
    }

    public override string Title => "Connections";

    public override string Icon => "ConnectionsIcon";

    public ObservableCollection<ConnectionRow> Rows { get; } = [];

    /// <summary>The filtered rows shown in the grid.</summary>
    public DataGridCollectionView View { get; }

    [ObservableProperty]
    public partial string Filter { get; set; } = string.Empty;

    [ObservableProperty]
    public partial bool ShowClosed { get; set; } = true;

    [ObservableProperty]
    public partial bool IsWatching { get; private set; }

    [ObservableProperty]
    public partial string Summary { get; private set; } = "Not connected to proxynatord.";

    [ObservableProperty]
    public partial ConnectionRow? SelectedRow { get; set; }

    /// <summary>Starts following the service's connections until disposed; reconnects when the service restarts.</summary>
    public void Start() => watchLoop ??= WatchAsync(stop.Token);

    /// <summary>Lists the current connections once and follows events until the stream ends (one round of <see cref="Start"/>).</summary>
    public async Task WatchOnceAsync(CancellationToken cancellationToken)
    {
        using var call = service.Client.WatchConnections(new WatchConnectionsRequest(), cancellationToken: cancellationToken);

        // Subscribe first, then list: a connection opened in between shows up in both, which Opened() tolerates.
        var list = await service.Client.ListConnectionsAsync(new ListConnectionsRequest(), ServiceConnection.Options(cancellationToken));
        Merge(list.Connections);
        IsWatching = true;
        UpdateSummary();
        await foreach (var connectionEvent in call.ResponseStream.ReadAllAsync(cancellationToken))
        {
            if (connectionEvent.Kind == ConnectionEvent.Types.Kind.Opened)
            {
                Opened(connectionEvent.Connection);
            }
            else
            {
                Closed(connectionEvent.Connection);
            }

            UpdateSummary();
        }
    }

    public override Task ActivateAsync() => RefreshAsync();

    /// <summary>Refreshes byte counters and ages of open connections.</summary>
    public override async Task RefreshAsync()
    {
        if (!IsWatching)
        {
            return;
        }

        try
        {
            var list = await service.Client.ListConnectionsAsync(new ListConnectionsRequest(), ServiceConnection.Options());
            Merge(list.Connections);
            UpdateSummary();
        }
        catch (RpcException)
        {
            // The watch loop notices too and reconnects.
        }
    }

    [RelayCommand]
    private void ClearClosed()
    {
        foreach (var row in Rows.Where(r => !r.IsOpen).ToList())
        {
            Rows.Remove(row);
            byId.Remove(row.Id);
        }

        UpdateSummary();
    }

    partial void OnFilterChanged(string value) => View.Refresh();

    partial void OnShowClosedChanged(bool value) => View.Refresh();

    public void Dispose()
    {
        stop.Cancel();
        stop.Dispose();
    }

    private async Task WatchAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await WatchOnceAsync(cancellationToken);
            }
            catch (RpcException ex) when (!cancellationToken.IsCancellationRequested)
            {
                Summary = service.Describe(ex);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }

            IsWatching = false;
            MarkAllClosed();
            try
            {
                await Task.Delay(RetryDelay, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void Merge(IEnumerable<Connection> current)
    {
        var open = new HashSet<long>();
        foreach (var connection in current)
        {
            open.Add(connection.Id);
            Opened(connection);
        }

        // Connections that ended while no event could be received (e.g. before the stream started).
        foreach (var row in Rows.Where(r => r.IsOpen && !open.Contains(r.Id)).ToList())
        {
            row.Close(new Connection { Id = row.Id, BytesSent = row.BytesSent, BytesReceived = row.BytesReceived });
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var row in Rows)
        {
            row.Tick(now);
        }
    }

    private void Opened(Connection connection)
    {
        if (byId.TryGetValue(connection.Id, out var existing))
        {
            existing.Update(connection);
            return;
        }

        var row = new ConnectionRow(connection);
        byId[row.Id] = row;
        Rows.Insert(0, row);
    }

    private void Closed(Connection connection)
    {
        if (byId.TryGetValue(connection.Id, out var row))
        {
            row.Close(connection);
        }
        else
        {
            // Opened and closed between the list and the first event.
            row = new ConnectionRow(connection);
            row.Close(connection);
            byId[row.Id] = row;
            Rows.Insert(0, row);
        }

        TrimClosed();
        if (!ShowClosed || Filter.Length > 0)
        {
            View.Refresh();
        }
    }

    private void TrimClosed()
    {
        var closed = Rows.Where(r => !r.IsOpen).ToList();
        for (var i = ClosedLimit; i < closed.Count; i++)
        {
            Rows.Remove(closed[i]);
            byId.Remove(closed[i].Id);
        }
    }

    private void MarkAllClosed()
    {
        foreach (var row in Rows.Where(r => r.IsOpen).ToList())
        {
            row.Close(new Connection { Id = row.Id, BytesSent = row.BytesSent, BytesReceived = row.BytesReceived });
        }
    }

    private void UpdateSummary()
    {
        var open = Rows.Count(r => r.IsOpen);
        Summary = $"{open} open, {Rows.Count - open} closed (newest first)";
    }
}
