namespace Proxynator.Service;

/// <summary>The service cannot start; the message is shown to the user and the process exits with <see cref="ExitCode"/>.</summary>
internal sealed class ServiceStartupException(int exitCode, string message) : Exception(message)
{
    public const int GeneralError = 1;
    public const int InsufficientPrivileges = 2;
    public const int InvalidConfiguration = 3;

    public int ExitCode { get; } = exitCode;
}
