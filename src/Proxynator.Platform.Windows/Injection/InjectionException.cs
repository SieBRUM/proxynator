namespace Proxynator.Platform.Windows.Injection;

/// <summary>Starting or attaching to a process with the hook DLL failed.</summary>
public sealed class InjectionException : Exception
{
    /// <summary>Creates the exception.</summary>
    public InjectionException()
    {
    }

    /// <summary>Creates the exception.</summary>
    public InjectionException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    public InjectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
