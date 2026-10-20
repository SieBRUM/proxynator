namespace Proxynator.Core.Configuration;

/// <summary>Thrown when an invalid configuration is applied.</summary>
public sealed class ConfigValidationException : Exception
{
    /// <summary>Creates the exception from a list of validation errors.</summary>
    public ConfigValidationException(IReadOnlyList<ConfigError> errors)
        : base("The configuration is invalid:" + Environment.NewLine + string.Join(Environment.NewLine, errors))
    {
        Errors = errors;
    }

    /// <summary>The validation errors.</summary>
    public IReadOnlyList<ConfigError> Errors { get; }
}
