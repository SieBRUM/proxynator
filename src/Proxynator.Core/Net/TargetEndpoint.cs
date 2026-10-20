using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Proxynator.Core.Net;

/// <summary>
/// A connection target: a hostname, an IP address, or both (a hostname whose resolved address is already known),
/// plus a port. Proxies that support hostnames are given <see cref="Host"/> when it is set.
/// </summary>
public sealed record TargetEndpoint
{
    private TargetEndpoint(string? host, IPAddress? address, int port)
    {
        Host = host;
        Address = address;
        Port = port;
    }

    /// <summary>The hostname, when known.</summary>
    public string? Host { get; }

    /// <summary>The IP address, when known.</summary>
    public IPAddress? Address { get; }

    /// <summary>The TCP/UDP port.</summary>
    public int Port { get; }

    /// <summary>The host part as used in an HTTP authority: the hostname, or the address (IPv6 in brackets).</summary>
    public string AuthorityHost => Host ?? (Address!.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]" : Address.ToString());

    /// <summary>Creates an address-only target.</summary>
    public static TargetEndpoint FromAddress(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidatePort(port);
        return new TargetEndpoint(null, address.Normalize(), port);
    }

    /// <summary>
    /// Creates a target from a hostname or IP literal. When <paramref name="knownAddress"/> is given, the target carries
    /// both, so proxies without hostname support can still use the address.
    /// </summary>
    public static TargetEndpoint FromHost(string host, int port, IPAddress? knownAddress = null)
    {
        ArgumentNullException.ThrowIfNull(host);
        ValidatePort(port);
        if (TryParseAddressLiteral(host, out var literal))
        {
            return new TargetEndpoint(null, literal, port);
        }

        if (!IsValidHostName(host))
        {
            throw new ArgumentException($"'{host}' is not a valid hostname.", nameof(host));
        }

        return new TargetEndpoint(host, knownAddress?.Normalize(), port);
    }

    /// <summary>
    /// Whether <paramref name="host"/> is a syntactically valid DNS hostname (ASCII letters, digits, '-', '_', '.';
    /// at most 253 characters). Internationalized names must be given in their ASCII (punycode) form.
    /// </summary>
    public static bool IsValidHostName(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253 || host[0] == '.' || host.Contains("..", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in host)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        if (Host is not null && Address is not null)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{Host}:{Port} ({Address})");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{AuthorityHost}:{Port}");
    }

    private static bool TryParseAddressLiteral(string host, out IPAddress address)
    {
        var text = host.Length > 2 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        if (IPAddress.TryParse(text, out var parsed) && (text.Contains(':', StringComparison.Ordinal) || text.Count(c => c == '.') == 3))
        {
            address = parsed.Normalize();
            return true;
        }

        address = IPAddress.None;
        return false;
    }

    private static void ValidatePort(int port)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }
    }
}
