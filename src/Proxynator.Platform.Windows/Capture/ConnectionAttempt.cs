using System.Net;
using Proxynator.Core.Net;
using Proxynator.Platform.Windows.Interop;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>A new outbound TCP connection (SYN) or UDP flow (first datagram) seen by the NAT, offered to the redirect decision.</summary>
internal readonly record struct ConnectionAttempt(TransportProtocol Protocol, bool IsIPv6, UInt128 LocalAddress, int LocalPort, UInt128 RemoteAddress, int RemotePort)
{
    public IPAddress RemoteIPAddress => AddressKey.ToIPAddress(RemoteAddress);

    public IPAddress LocalIPAddress => AddressKey.ToIPAddress(LocalAddress);
}
