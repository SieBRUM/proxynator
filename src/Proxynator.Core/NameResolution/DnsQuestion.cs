namespace Proxynator.Core.NameResolution;

/// <summary>The header and first question of a DNS query.</summary>
/// <param name="Id">Transaction ID.</param>
/// <param name="RecursionDesired">The RD flag, echoed in the response.</param>
/// <param name="Name">The queried name, lower case, without a trailing dot.</param>
/// <param name="Type">QTYPE.</param>
/// <param name="Class">QCLASS.</param>
/// <param name="End">Offset just after the question in the message.</param>
internal readonly record struct DnsQuestion(ushort Id, bool RecursionDesired, string Name, ushort Type, ushort Class, int End);
