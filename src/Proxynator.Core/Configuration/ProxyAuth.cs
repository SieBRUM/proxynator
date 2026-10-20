namespace Proxynator.Core.Configuration;

/// <summary>Proxy credentials. For SOCKS4/4a only <see cref="Username"/> is used, as the user ID.</summary>
public sealed record ProxyAuth
{
    /// <summary>User name (SOCKS5, HTTP) or user ID (SOCKS4/4a).</summary>
    public required string Username { get; init; }

    /// <summary>Password (SOCKS5, HTTP).</summary>
    public string? Password { get; set; }

    /// <inheritdoc />
    public override string ToString() => $"ProxyAuth {{ Username = {Username}, Password = *** }}";
}
