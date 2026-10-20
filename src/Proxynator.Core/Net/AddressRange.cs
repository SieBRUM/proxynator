using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Proxynator.Core.Net;

/// <summary>
/// An IPv4 or IPv6 network in CIDR notation (<c>10.0.0.0/8</c>, <c>2001:db8::/32</c>) or a single address.
/// Host bits are ignored, so <c>10.1.2.3/8</c> is the same as <c>10.0.0.0/8</c>.
/// </summary>
public sealed class AddressRange
{
    private readonly byte[] network;

    private AddressRange(byte[] network, int prefixLength, AddressFamily family)
    {
        this.network = network;
        PrefixLength = prefixLength;
        AddressFamily = family;
    }

    /// <summary>Number of leading bits that must match.</summary>
    public int PrefixLength { get; }

    /// <summary>The address family of the range.</summary>
    public AddressFamily AddressFamily { get; }

    /// <summary>The first address of the range.</summary>
    public IPAddress NetworkAddress => new(network);

    /// <summary>Parses a CIDR range or a single address.</summary>
    public static bool TryParse([NotNullWhen(true)] string? text, [NotNullWhen(true)] out AddressRange? range)
    {
        range = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var addressText = (slash < 0 ? text : text[..slash]).Trim();
        if (!IPAddress.TryParse(addressText, out var address))
        {
            return false;
        }

        address = address.Normalize();
        var bytes = address.GetAddressBytes();
        var maxPrefix = bytes.Length * 8;
        var prefix = maxPrefix;
        if (slash >= 0 &&
            (!int.TryParse(text[(slash + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix > maxPrefix))
        {
            return false;
        }

        for (var bit = prefix; bit < maxPrefix; bit++)
        {
            bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        }

        range = new AddressRange(bytes, prefix, address.AddressFamily);
        return true;
    }

    /// <summary>Whether <paramref name="address"/> lies in the range. IPv4-mapped IPv6 addresses are treated as IPv4.</summary>
    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        address = address.Normalize();
        if (address.AddressFamily != AddressFamily)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written) || written != network.Length)
        {
            return false;
        }

        var fullBytes = PrefixLength / 8;
        if (!bytes[..fullBytes].SequenceEqual(network.AsSpan(0, fullBytes)))
        {
            return false;
        }

        var remainingBits = PrefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (bytes[fullBytes] & mask) == network[fullBytes];
    }

    /// <inheritdoc />
    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{NetworkAddress}/{PrefixLength}");
}
