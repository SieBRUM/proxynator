using System.Diagnostics;
using System.Runtime.Versioning;

namespace Proxynator.Platform.Linux.Preload;

/// <summary>
/// Starts programs with the preload library (<c>proxynator run</c> in the preload capture mode). Children inherit
/// the environment, and so the library, unless a program clears it (sudo, setuid programs).
/// </summary>
[SupportedOSPlatform("linux")]
public static class PreloadLauncher
{
    /// <summary>The variable naming the service's hook socket, read by the library.</summary>
    public const string EndpointVariable = "PROXYNATOR_HOOK_ENDPOINT";

    /// <summary>Whether the service is accepting hooked processes on <paramref name="hookSocket"/>.</summary>
    public static bool IsServing(string hookSocket) => File.Exists(hookSocket);

    /// <summary>
    /// The start info for <paramref name="program"/> (found on the PATH) with the library added to <c>LD_PRELOAD</c>.
    /// Standard input and output are inherited.
    /// </summary>
    public static ProcessStartInfo CreateStartInfo(string program, IEnumerable<string> arguments, string hookSocket, string? existingPreload)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var start = new ProcessStartInfo(program) { UseShellExecute = false };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        var library = NativeFiles.PathOf(NativeFiles.PreloadLibrary);
        start.Environment["LD_PRELOAD"] = string.IsNullOrEmpty(existingPreload) ? library : $"{library}:{existingPreload}";
        start.Environment[EndpointVariable] = hookSocket;
        return start;
    }
}
