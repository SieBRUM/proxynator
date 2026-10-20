namespace Proxynator.Core.Proxies;

/// <summary>Credentials for a proxy hop. <see cref="ToString"/> never reveals the password.</summary>
public sealed record ProxyCredentials(string Username, string Password)
{
    /// <inheritdoc />
    public override string ToString() => $"ProxyCredentials {{ Username = {Username}, Password = *** }}";
}
