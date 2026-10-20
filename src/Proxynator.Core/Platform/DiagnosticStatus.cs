namespace Proxynator.Core.Platform;

/// <summary>Outcome of a diagnostic check.</summary>
public enum DiagnosticStatus
{
    /// <summary>The check passed.</summary>
    Ok,

    /// <summary>Something is not ideal but Proxynator can work.</summary>
    Warning,

    /// <summary>Proxynator cannot work correctly until this is fixed.</summary>
    Error,
}
