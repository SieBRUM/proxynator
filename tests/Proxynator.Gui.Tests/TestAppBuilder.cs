using Avalonia;
using Avalonia.Headless;
using Proxynator.Gui;
using Proxynator.Gui.Tests;

[assembly: AvaloniaTestApplication(typeof(TestAppBuilder))]
[assembly: CollectionBehavior(DisableTestParallelization = false)]

namespace Proxynator.Gui.Tests;

/// <summary>The real application (styles, templates) on the headless platform, rendering with Skia for screenshots.</summary>
public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UseSkia()
        .WithInterFont()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}
