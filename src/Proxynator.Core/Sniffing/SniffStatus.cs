namespace Proxynator.Core.Sniffing;

/// <summary>Result of inspecting the first bytes of a connection for a hostname.</summary>
public enum SniffStatus
{
    /// <summary>A hostname was found.</summary>
    Found,

    /// <summary>The data is not TLS or HTTP, or carries no usable hostname.</summary>
    NotFound,

    /// <summary>The data looks like TLS or HTTP but is incomplete.</summary>
    NeedMoreData,
}
