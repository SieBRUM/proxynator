namespace Proxynator.Core.Tests.Support;

/// <summary>Cancellation tokens that stop network tests from hanging forever.</summary>
internal static class TestTimeout
{
    public static CancellationToken Token(int seconds = 10)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        source.CancelAfter(TimeSpan.FromSeconds(seconds));
        return source.Token;
    }
}
