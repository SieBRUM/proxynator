using System.Globalization;
using System.Runtime.Versioning;
using Proxynator.Platform.Linux.Interop;

namespace Proxynator.Platform.Linux;

/// <summary>Group ownership for the control socket: members of the <c>proxynator</c> group may use the CLI.</summary>
public static class UnixGroups
{
    /// <summary>The group the package creates for CLI users.</summary>
    public const string ControlGroup = "proxynator";

    /// <summary>Gives <paramref name="path"/> to the group <paramref name="group"/>, if it exists. Returns whether it did.</summary>
    [SupportedOSPlatform("linux")]
    public static bool TryGiveToGroup(string path, string group = ControlGroup)
    {
        var gid = FindGroupId(File.Exists("/etc/group") ? File.ReadAllText("/etc/group") : string.Empty, group);
        return gid is { } id && Libc.chown(path, -1, id) == 0;
    }

    internal static int? FindGroupId(string groupFile, string group)
    {
        foreach (var line in groupFile.Split('\n'))
        {
            var fields = line.Split(':');
            if (fields.Length >= 3 && fields[0] == group && int.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out var id))
            {
                return id;
            }
        }

        return null;
    }
}
