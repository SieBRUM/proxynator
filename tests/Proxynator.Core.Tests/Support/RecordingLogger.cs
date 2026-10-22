using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Proxynator.Core.Tests.Support;

/// <summary>Keeps every formatted log message, so tests can assert why something happened.</summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    public ConcurrentQueue<string> Messages { get; } = new();

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        Messages.Enqueue(formatter(state, exception));
    }
}
