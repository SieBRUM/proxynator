using System.Collections.Concurrent;

namespace Proxynator.Platform.Windows.Capture;

/// <summary>
/// Connection owners learned from WinDivert SOCKET-layer <c>connect</c> events, keyed by local port and remote
/// endpoint. Filled by the socket thread, read by the packet thread.
/// </summary>
internal sealed class SocketOwnerCache
{
    private const int MaxEntries = 65_536;

    private readonly ConcurrentDictionary<Key, int> owners = new();

    public void Add(int localPort, UInt128 remoteAddress, int remotePort, int processId)
    {
        if (owners.Count >= MaxEntries)
        {
            owners.Clear(); // close events were missed; the TCP table remains as fallback
        }

        owners[new Key((ushort)localPort, remoteAddress, (ushort)remotePort)] = processId;
    }

    public void Remove(int localPort, UInt128 remoteAddress, int remotePort) =>
        owners.TryRemove(new Key((ushort)localPort, remoteAddress, (ushort)remotePort), out _);

    public bool TryGet(int localPort, UInt128 remoteAddress, int remotePort, out int processId) =>
        owners.TryGetValue(new Key((ushort)localPort, remoteAddress, (ushort)remotePort), out processId);

    private readonly record struct Key(ushort LocalPort, UInt128 RemoteAddress, ushort RemotePort);
}
