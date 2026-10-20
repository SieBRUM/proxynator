using Proxynator.Core.Net;

namespace Proxynator.Core.Configuration;

/// <summary>
/// Rule criteria. All non-empty criteria must match (AND); entries within one criterion are alternatives (OR).
/// </summary>
public sealed record RuleMatch
{
    /// <summary>
    /// Process name patterns (e.g. <c>test.exe</c>, <c>chrome*</c>), or full path patterns when the pattern contains
    /// a path separator. <c>*</c> and <c>?</c> wildcards, case-insensitive.
    /// </summary>
    public IReadOnlyList<string> Processes { get; set; } = [];

    /// <summary>Also match descendants of processes matching <see cref="Processes"/>.</summary>
    public bool IncludeChildren { get; set; }

    /// <summary>Destination hostname patterns (e.g. <c>*.example.com</c>). Only match when the hostname is known.</summary>
    public IReadOnlyList<string> Hosts { get; set; } = [];

    /// <summary>Destination IP addresses or CIDR ranges.</summary>
    public IReadOnlyList<string> Addresses { get; set; } = [];

    /// <summary>Destination ports or port ranges (<c>443</c>, <c>8000-8100</c>).</summary>
    public IReadOnlyList<string> Ports { get; set; } = [];

    /// <summary>Transport protocols; empty means both.</summary>
    public IReadOnlyList<TransportProtocol> Protocols { get; set; } = [];
}
