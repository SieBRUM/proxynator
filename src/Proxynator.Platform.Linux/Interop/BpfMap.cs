using System.Runtime.Versioning;

namespace Proxynator.Platform.Linux.Interop;

/// <summary>Typed access to a BPF map by file descriptor (owned by the BPF object).</summary>
[SupportedOSPlatform("linux")]
internal readonly unsafe struct BpfMap<TKey, TValue>(int fd)
    where TKey : unmanaged
    where TValue : unmanaged
{
    public bool IsValid => fd > 0;

    public void Update(TKey key, TValue value)
    {
        var error = LibBpf.bpf_map_update_elem(fd, &key, &value, 0);
        if (error != 0)
        {
            throw new InvalidOperationException($"Updating an eBPF map failed (error {-error}).");
        }
    }

    public bool TryGet(TKey key, out TValue value)
    {
        TValue result;
        var found = LibBpf.bpf_map_lookup_elem(fd, &key, &result) == 0;
        value = found ? result : default;
        return found;
    }

    public bool Delete(TKey key) => LibBpf.bpf_map_delete_elem(fd, &key) == 0;

    public List<TKey> Keys()
    {
        var keys = new List<TKey>();
        TKey current;
        if (LibBpf.bpf_map_get_next_key(fd, null, &current) != 0)
        {
            return keys;
        }

        keys.Add(current);
        TKey next;
        while (LibBpf.bpf_map_get_next_key(fd, &current, &next) == 0)
        {
            keys.Add(next);
            current = next;
        }

        return keys;
    }
}
