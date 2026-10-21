using CommunityToolkit.Mvvm.ComponentModel;
using Proxynator.Client;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>A relayed connection, open or recently closed.</summary>
internal sealed partial class ConnectionRow : ObservableObject
{
    public ConnectionRow(Connection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Id = connection.Id;
        Protocol = connection.Protocol;
        ProcessId = connection.ProcessId;
        Process = connection.ProcessName.Length > 0 ? connection.ProcessName : $"pid {connection.ProcessId}";
        ProcessPath = connection.ProcessPath;
        Destination = connection.Destination;
        Rule = connection.Rule;
        Via = connection.Action == "proxy" ? connection.Route : connection.Action;
        StartedAt = connection.StartedAt.ToDateTimeOffset();
        Update(connection);
    }

    public long Id { get; }

    public string Protocol { get; }

    public int ProcessId { get; }

    public string Process { get; }

    public string ProcessPath { get; }

    public string Destination { get; }

    public string Rule { get; }

    public string Via { get; }

    public DateTimeOffset StartedAt { get; }

    public string Started => StartedAt.ToLocalTime().ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Sent))]
    public partial long BytesSent { get; private set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Received))]
    public partial long BytesReceived { get; private set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(State))]
    public partial bool IsOpen { get; private set; } = true;

    [ObservableProperty]
    public partial string Duration { get; private set; } = string.Empty;

    public string Sent => DisplayFormat.Bytes(BytesSent);

    public string Received => DisplayFormat.Bytes(BytesReceived);

    public string State => IsOpen ? "open" : "closed";

    /// <summary>Takes the latest byte counters.</summary>
    public void Update(Connection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        BytesSent = connection.BytesSent;
        BytesReceived = connection.BytesReceived;
        Tick(DateTimeOffset.UtcNow);
    }

    public void Close(Connection connection)
    {
        Update(connection);
        IsOpen = false;
    }

    /// <summary>Updates the age of an open connection (a closed one keeps its final duration).</summary>
    public void Tick(DateTimeOffset now)
    {
        if (IsOpen)
        {
            Duration = DisplayFormat.Duration(now - StartedAt);
        }
    }

    /// <summary>Whether the row contains <paramref name="text"/> in any column a user would search.</summary>
    public bool Matches(string text) =>
        string.IsNullOrWhiteSpace(text) ||
        new[] { Process, ProcessPath, Destination, Rule, Via, Protocol, State }.Any(value => value.Contains(text.Trim(), StringComparison.OrdinalIgnoreCase));
}
