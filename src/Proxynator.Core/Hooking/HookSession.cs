using Microsoft.Extensions.Logging;

namespace Proxynator.Core.Hooking;

/// <summary>Serves one hooked process over a connected stream until it disconnects.</summary>
public static partial class HookSession
{
    /// <summary>
    /// Reads requests and writes responses until the stream ends. A malformed message ends the session (the hook
    /// then fails closed). <paramref name="processId"/> must come from the transport (e.g. the pipe client PID),
    /// never from the hooked process's own claims.
    /// </summary>
    public static async Task RunAsync(Stream stream, int processId, HookRequestHandler handler, ILogger logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(handler);
        var request = new byte[HookProtocol.MaxBodyLength];
        var response = new byte[HookProtocol.MaxBodyLength];
        while (!cancellationToken.IsCancellationRequested)
        {
            var length = await HookProtocol.ReadFrameAsync(stream, request, cancellationToken).ConfigureAwait(false);
            if (length == 0)
            {
                return;
            }

            if (length < 0 || !HookProtocol.TryParseRequest(request.AsSpan(0, length), out var parsed))
            {
                Log.Malformed(logger, processId);
                return;
            }

            var answer = handler.Handle(processId, parsed);
            var written = HookProtocol.WriteResponse(answer, response);
            await HookProtocol.WriteFrameAsync(stream, response.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
        }
    }

    private static partial class Log
    {
        [LoggerMessage(EventId = 4010, Level = LogLevel.Warning, Message = "Closing the hook session of pid {ProcessId}: malformed message")]
        public static partial void Malformed(ILogger logger, int processId);
    }
}
