using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Proxynator.Service;

/// <summary>Location and safe writing of the service configuration file.</summary>
internal static class ConfigFile
{
    /// <summary><c>%ProgramData%\Proxynator\config.json</c> on Windows, <c>/etc/proxynator/config.json</c> elsewhere.</summary>
    public static string DefaultPath => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Proxynator", "config.json")
        : "/etc/proxynator/config.json";

    /// <summary>
    /// Writes <paramref name="json"/> atomically (temporary file + rename). The file can contain proxy credentials, so a
    /// newly created directory is only accessible to administrators (Windows) and the file is not world-readable (Unix).
    /// </summary>
    public static async Task SaveAsync(string path, string json, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(path);
        EnsureDirectory(Path.GetDirectoryName(fullPath)!);
        var temporary = fullPath + ".tmp";
        await File.WriteAllTextAsync(temporary, json, cancellationToken).ConfigureAwait(false);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }

        File.Move(temporary, fullPath, overwrite: true);
    }

    private static void EnsureDirectory(string directory)
    {
        if (Directory.Exists(directory))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            CreateRestrictedWindowsDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CreateRestrictedWindowsDirectory(string directory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(directory).Create(security);
    }
}
