using System.Collections.Concurrent;
using Proxynator.Core.Net;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// Socket owners learned from WinDivert SOCKET-layer <c>connect</c> events, keyed by protocol, local port and remote
/// endpoint. Filled by the socket thread, read by the packet thread.
/// </summary>
internal sealed class SocketOwnerCache
{
    private const int MaxEntries = 65_536;

    private readonly ConcurrentDictionary<Key, int> owners = new();

    public void Add(TransportProtocol protocol, int localPort, UInt128 remoteAddress, int remotePort, int processId)
    {
        if (owners.Count >= MaxEntries)
        {
            owners.Clear(); // close events were missed; the OS tables remain as fallback
        }

        owners[new Key(protocol, (ushort)localPort, remoteAddress, (ushort)remotePort)] = processId;
    }

    public void Remove(TransportProtocol protocol, int localPort, UInt128 remoteAddress, int remotePort) =>
        owners.TryRemove(new Key(protocol, (ushort)localPort, remoteAddress, (ushort)remotePort), out _);

    public bool TryGet(TransportProtocol protocol, int localPort, UInt128 remoteAddress, int remotePort, out int processId) =>
        owners.TryGetValue(new Key(protocol, (ushort)localPort, remoteAddress, (ushort)remotePort), out processId);

    private readonly record struct Key(TransportProtocol Protocol, ushort LocalPort, UInt128 RemoteAddress, ushort RemotePort);
}
