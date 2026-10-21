namespace Proxynator.Client;

/// <summary>A program could not be started with, or attached to, Proxynator's hook.</summary>
public sealed class LaunchException : Exception
{
    /// <summary>Creates the exception.</summary>
    public LaunchException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public LaunchException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public LaunchException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What went wrong and how to fix it.</param>
    /// <param name="serviceUnavailable">The service is not accepting hooked processes (wrong capture mode, not running).</param>
    public LaunchException(string message, bool serviceUnavailable)
        : base(message) => ServiceUnavailable = serviceUnavailable;

    /// <summary>The service is not accepting hooked processes (not running, or not in a user-mode capture mode).</summary>
    public bool ServiceUnavailable { get; }
}
