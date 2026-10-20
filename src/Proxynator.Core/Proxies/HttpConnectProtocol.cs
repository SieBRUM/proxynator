using System.Globalization;
using System.Text;
using Proxynator.Core.Net;

namespace Proxynator.Core.Proxies;

/// <summary>HTTP <c>CONNECT</c> tunnelling with optional Basic proxy authentication.</summary>
public sealed class HttpConnectProtocol(ProxyCredentials? credentials) : IProxyProtocol
{
    private const int MaxResponseHeaderBytes = 16 * 1024;

    /// <inheritdoc />
    public async ValueTask<Stream> ConnectAsync(Stream transport, TargetEndpoint target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(target);

        await transport.WriteAsync(Encoding.ASCII.GetBytes(BuildRequest(target)), cancellationToken).ConfigureAwait(false);

        var statusLine = await ReadResponseHeadAsync(transport, cancellationToken).ConfigureAwait(false);
        var status = ParseStatusCode(statusLine);
        if (status is >= 200 and < 300)
        {
            return transport;
        }

        throw status == 407
            ? new ProxyException(ProxyFailure.AuthenticationFailed, $"HTTP proxy requires authentication: {statusLine}")
            : new ProxyException(ProxyFailure.Rejected, $"HTTP proxy refused CONNECT to {target}: {statusLine}");
    }

    internal string BuildRequest(TargetEndpoint target)
    {
        var authority = string.Create(CultureInfo.InvariantCulture, $"{target.AuthorityHost}:{target.Port}");
        var request = new StringBuilder()
            .Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n")
            .Append("Host: ").Append(authority).Append("\r\n");
        if (credentials is not null)
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.Username}:{credentials.Password}"));
            request.Append("Proxy-Authorization: Basic ").Append(token).Append("\r\n");
        }

        return request.Append("\r\n").ToString();
    }

    /// <summary>
    /// Reads the response head one byte at a time so that no tunnelled bytes after the blank line are consumed
    /// (the target may speak first, e.g. SSH or SMTP banners). Returns the status line.
    /// </summary>
    private static async Task<string> ReadResponseHeadAsync(Stream transport, CancellationToken cancellationToken)
    {
        var head = new List<byte>(256);
        var oneByte = new byte[1];
        while (!EndsWithBlankLine(head))
        {
            if (head.Count >= MaxResponseHeaderBytes)
            {
                throw new ProxyException(ProxyFailure.ProtocolError, "HTTP proxy response headers are too large.");
            }

            await transport.ReadExactlyAsync(oneByte, cancellationToken).ConfigureAwait(false);
            head.Add(oneByte[0]);
        }

        var text = Encoding.ASCII.GetString(head.ToArray());
        return text[..text.IndexOf("\r\n", StringComparison.Ordinal)];
    }

    private static bool EndsWithBlankLine(List<byte> head) =>
        head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n';

    private static int ParseStatusCode(string statusLine)
    {
        var parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.Ordinal) ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var status))
        {
            throw new ProxyException(ProxyFailure.ProtocolError, $"Malformed HTTP proxy response: '{statusLine}'.");
        }

        return status;
    }
}
