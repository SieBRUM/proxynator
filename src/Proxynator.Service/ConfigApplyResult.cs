using Proxynator.Core.Configuration;

namespace Proxynator.Service;

/// <summary>The outcome of applying a configuration through the control API.</summary>
internal sealed record ConfigApplyResult(
    bool Applied,
    IReadOnlyList<ConfigError> Errors,
    bool Persisted = false,
    string? PersistError = null,
    string? RestartRequiredReason = null);
