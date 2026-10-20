using System.Diagnostics.CodeAnalysis;

namespace Proxynator.Core.Configuration;

/// <summary>The outcome of loading a configuration: either a valid config or a list of errors.</summary>
public sealed class ConfigLoadResult
{
    private ConfigLoadResult(ProxynatorConfig? config, IReadOnlyList<ConfigError> errors)
    {
        Config = config;
        Errors = errors;
    }

    /// <summary>The loaded configuration, or <see langword="null"/> when loading failed.</summary>
    public ProxynatorConfig? Config { get; }

    /// <summary>All problems found; empty on success.</summary>
    public IReadOnlyList<ConfigError> Errors { get; }

    /// <summary>Whether loading succeeded.</summary>
    [MemberNotNullWhen(true, nameof(Config))]
    public bool Success => Config is not null;

    internal static ConfigLoadResult Succeeded(ProxynatorConfig config) => new(config, []);

    internal static ConfigLoadResult Failed(IReadOnlyList<ConfigError> errors) => new(null, errors);

    internal static ConfigLoadResult Failed(string path, string message) => new(null, [new ConfigError(path, message)]);
}
