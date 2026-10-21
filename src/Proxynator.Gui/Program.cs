using Avalonia;

namespace Proxynator.Gui;

internal static class Program
{
    /// <summary>Starts the GUI. Options: <c>--endpoint &lt;pipe name | socket path&gt;</c> (default: the platform default or PROXYNATOR_ENDPOINT).</summary>
    [STAThread]
    public static int Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    /// <summary>Used by the designer and by <see cref="Main"/>.</summary>
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().LogToTrace();
}
