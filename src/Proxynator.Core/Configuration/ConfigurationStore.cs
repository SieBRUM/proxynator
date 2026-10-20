namespace Proxynator.Core.Configuration;

/// <summary>
/// Holds the active configuration and swaps it atomically. Readers take <see cref="Current"/> once per connection,
/// so a configuration change never affects connections that are already established.
/// </summary>
public sealed class ConfigurationStore
{
    private ActiveConfiguration current;

    /// <summary>Creates the store with an initial configuration.</summary>
    /// <exception cref="ConfigValidationException">The configuration is invalid.</exception>
    public ConfigurationStore(ProxynatorConfig initial)
    {
        current = ActiveConfiguration.Create(initial);
    }

    /// <summary>Raised after a new configuration has been applied.</summary>
    public event EventHandler<ActiveConfiguration>? Changed;

    /// <summary>The active configuration.</summary>
    public ActiveConfiguration Current => Volatile.Read(ref current);

    /// <summary>
    /// Validates and applies <paramref name="config"/>. On failure nothing changes and the errors are returned;
    /// on success the result is empty.
    /// </summary>
    public IReadOnlyList<ConfigError> TryApply(ProxynatorConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        ActiveConfiguration next;
        try
        {
            next = ActiveConfiguration.Create(config);
        }
        catch (ConfigValidationException ex)
        {
            return ex.Errors;
        }

        Volatile.Write(ref current, next);
        Changed?.Invoke(this, next);
        return [];
    }
}
