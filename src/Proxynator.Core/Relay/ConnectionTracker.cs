using System.Collections.Concurrent;
using Proxynator.Core.Rules;

namespace Proxynator.Core.Relay;

/// <summary>Keeps the list of active relayed connections, for status output and the UI.</summary>
public sealed class ConnectionTracker(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<long, TrackedConnection> active = new();
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;
    private long nextId;

    /// <summary>Raised when a connection is opened.</summary>
    public event EventHandler<TrackedConnection>? Opened;

    /// <summary>Raised when a connection is closed, with its final byte counts.</summary>
    public event EventHandler<TrackedConnection>? Closed;

    /// <summary>A snapshot of the active connections, oldest first.</summary>
    public IReadOnlyList<TrackedConnection> GetActive() => [.. active.Values.OrderBy(c => c.Id)];

    /// <summary>Starts tracking a connection.</summary>
    public TrackedConnection Open(ConnectionContext context, RuleDecision decision)
    {
        var connection = new TrackedConnection(Interlocked.Increment(ref nextId), time.GetUtcNow(), context, decision);
        active[connection.Id] = connection;
        Opened?.Invoke(this, connection);
        return connection;
    }

    /// <summary>Stops tracking a connection.</summary>
    public void Close(TrackedConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (active.TryRemove(connection.Id, out _))
        {
            Closed?.Invoke(this, connection);
        }
    }
}
