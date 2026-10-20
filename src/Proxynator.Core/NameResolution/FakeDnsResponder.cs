namespace Proxynator.Core.NameResolution;

/// <summary>
/// Answers DNS queries with fake addresses (<see cref="FakeIpPool"/>) for the names <c>shouldFake</c> accepts:
/// A queries get a fake IPv4 address; AAAA, SVCB and HTTPS queries get an empty answer, so clients use the fake IPv4
/// address and do not learn real addresses from IP hints. Everything else must be forwarded to the real server.
/// </summary>
public sealed class FakeDnsResponder(FakeIpPool pool)
{
    /// <summary>Short, so fake answers do not outlive the service in client caches for long.</summary>
    public const uint TimeToLiveSeconds = 10;

    /// <summary>The pool fake addresses come from.</summary>
    public FakeIpPool Pool => pool;

    /// <summary>Returns the response for <paramref name="query"/>, or <see langword="null"/> to forward it upstream.</summary>
    public byte[]? TryAnswer(ReadOnlySpan<byte> query, Func<string, bool> shouldFake)
    {
        ArgumentNullException.ThrowIfNull(shouldFake);
        if (!DnsWire.TryParseQuery(query, out var question) || question.Class != DnsWire.ClassIn || !shouldFake(question.Name))
        {
            return null;
        }

        return question.Type switch
        {
            DnsWire.TypeA => DnsWire.BuildResponse(query, question, pool.GetOrAllocate(question.Name), TimeToLiveSeconds),
            DnsWire.TypeAaaa or DnsWire.TypeSvcb or DnsWire.TypeHttps => DnsWire.BuildResponse(query, question, null, TimeToLiveSeconds),
            _ => null,
        };
    }
}
