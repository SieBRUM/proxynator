using System.Net;

namespace Proxynator.Core.Relay;

/// <summary>Where a redirected connection was originally going, as recorded by the capture backend.</summary>
/// <param name="Destination">The original destination endpoint.</param>
/// <param name="ProcessId">The process that opened the connection.</param>
/// <param name="Hostname">The hostname the process resolved, when the backend knows it (resolver hooks, fake IPs).</param>
/// <param name="HostnameIsHint">
/// The hostname came from the process's earlier name lookups (several names can share an address), so a hostname
/// sniffed from the connection itself takes precedence. False for fake addresses, whose hostname is exact.
/// </param>
public sealed record OriginalDestination(IPEndPoint Destination, int ProcessId, string? Hostname = null, bool HostnameIsHint = false);
