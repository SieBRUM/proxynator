using Proxynator.Core.Platform;
using Proxynator.Platform.Linux;
using Proxynator.Platform.Windows;

namespace Proxynator.Service;

/// <summary>Picks the platform module for the operating system we run on.</summary>
internal static class PlatformModules
{
    public static IPlatformModule ForCurrentOS() =>
        OperatingSystem.IsWindows() ? new WindowsPlatformModule()
        : OperatingSystem.IsLinux() ? new LinuxPlatformModule()
        : new FallbackPlatformModule();
}
