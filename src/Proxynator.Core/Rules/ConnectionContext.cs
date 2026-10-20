using System.Net;
using Proxynator.Core.Net;
using Proxynator.Core.Processes;

namespace Proxynator.Core.Rules;

/// <summary>Everything known about a new connection when rules are evaluated.</summary>
/// <param name="Process">The owning process, if known.</param>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="DestinationAddress">The real destination address; <see langword="null"/> when only a hostname is known.</param>
/// <param name="DestinationHost">The destination hostname, if known.</param>
/// <param name="DestinationPort">The destination port.</param>
public sealed record ConnectionContext(
    ProcessInfo? Process,
    TransportProtocol Protocol,
    IPAddress? DestinationAddress,
    string? DestinationHost,
    int DestinationPort)
{
    /// <summary>A display form of the destination, e.g. <c>example.com:443</c>.</summary>
    public string DestinationDisplay => DestinationHost is not null
        ? $"{DestinationHost}:{DestinationPort}"
        : DestinationAddress is not null ? new IPEndPoint(DestinationAddress, DestinationPort).ToString() : $"?:{DestinationPort}";
}
