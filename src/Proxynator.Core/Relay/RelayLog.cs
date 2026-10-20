using System.Net;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.Relay;

internal static partial class RelayLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Relay listening on {Endpoint}")]
    public static partial void Listening(ILogger logger, IPEndPoint endpoint);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Warning, Message = "Dropping relay connection from {Client}: no original destination registered")]
    public static partial void UnknownClient(ILogger logger, EndPoint? client);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Information, Message = "#{ConnectionId} {Process} (pid {ProcessId}) -> {Destination}: rule '{Rule}' -> {Action} {Route}")]
    public static partial void Decided(ILogger logger, long connectionId, string process, int processId, string destination, string rule, RuleActionType action, string? route);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "#{ConnectionId} -> {Destination}: proxy route '{Route}' failed, connection refused: {Reason}")]
    public static partial void ProxyFailed(ILogger logger, long connectionId, string destination, string route, string reason);

    [LoggerMessage(EventId = 1004, Level = LogLevel.Warning, Message = "#{ConnectionId}: direct connection to {Destination} failed: {Reason}")]
    public static partial void DirectFailed(ILogger logger, long connectionId, string destination, string reason);

    [LoggerMessage(EventId = 1005, Level = LogLevel.Debug, Message = "#{ConnectionId} closed: {BytesSent} bytes sent, {BytesReceived} bytes received")]
    public static partial void Closed(ILogger logger, long connectionId, long bytesSent, long bytesReceived);

    [LoggerMessage(EventId = 1006, Level = LogLevel.Error, Message = "Accepting a relay connection failed")]
    public static partial void AcceptFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 1008, Level = LogLevel.Warning, Message = "Refusing a connection to fake address {Address}: it is not mapped to a hostname (expired, or from before a restart)")]
    public static partial void UnknownFakeAddress(ILogger logger, IPAddress address);

    [LoggerMessage(EventId = 1007, Level = LogLevel.Error, Message = "Unexpected error while relaying a connection")]
    public static partial void UnexpectedError(ILogger logger, Exception exception);
}
