namespace Proxynator.Service;

/// <summary>State of the capture backend.</summary>
internal enum CaptureState
{
    /// <summary>Capture disabled with <c>--no-capture</c>.</summary>
    Disabled,

    /// <summary>Capturing traffic.</summary>
    Running,

    /// <summary>The backend could not be created or started; see the detail message.</summary>
    Failed,

    /// <summary>The service is shutting down.</summary>
    Stopped,
}
