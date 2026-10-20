using Proxynator.Core.Rules;

namespace Proxynator.Core.Relay;

/// <summary>A relayed connection with live byte counters.</summary>
public sealed class TrackedConnection
{
    private long bytesSent;
    private long bytesReceived;

    internal TrackedConnection(long id, DateTimeOffset startedAt, ConnectionContext context, RuleDecision decision)
    {
        Id = id;
        StartedAt = startedAt;
        Context = context;
        Decision = decision;
    }

    /// <summary>Unique, increasing identifier.</summary>
    public long Id { get; }

    /// <summary>When the relay accepted the connection.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>What was known about the connection when the rules were evaluated.</summary>
    public ConnectionContext Context { get; }

    /// <summary>The rule decision.</summary>
    public RuleDecision Decision { get; }

    /// <summary>Bytes sent from the client to the upstream side.</summary>
    public long BytesSent => Interlocked.Read(ref bytesSent);

    /// <summary>Bytes received from the upstream side and sent to the client.</summary>
    public long BytesReceived => Interlocked.Read(ref bytesReceived);

    internal void AddSent(int count) => Interlocked.Add(ref bytesSent, count);

    internal void AddReceived(int count) => Interlocked.Add(ref bytesReceived, count);
}
