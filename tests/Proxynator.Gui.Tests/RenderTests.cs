using System.Net;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.LogicalTree;
using Avalonia.Styling;
using Avalonia.Threading;
using Proxynator.Core.Processes;
using Proxynator.Core.Relay;
using Proxynator.Core.Tests.Support;
using Proxynator.Gui.ViewModels;
using Proxynator.Gui.Views;
using Proxynator.Service.Tests;

namespace Proxynator.Gui.Tests;

/// <summary>
/// The real window on the headless platform: every page is shown with data from an in-process service, its bindings
/// must resolve, and a screenshot of each is written to <c>PROXYNATOR_SCREENSHOTS</c> (default: screenshots/ next
/// to the tests).
/// </summary>
public class RenderTests
{
    private static string ScreenshotDirectory =>
        Environment.GetEnvironmentVariable("PROXYNATOR_SCREENSHOTS") is { Length: > 0 } directory
            ? directory
            : Path.Combine(AppContext.BaseDirectory, "screenshots");

    [AvaloniaFact]
    public async Task Every_page_renders_with_live_data()
    {
        var platform = new TestPlatformModule();
        platform.Processes[4242] = new ProcessInfo(4242, "nxc", "/home/kali/.local/bin/nxc");
        platform.Processes[4343] = new ProcessInfo(4343, "firefox", "/usr/lib/firefox/firefox");
        await using var gui = await GuiHarness.StartAsync(GuiHarness.SampleConfig, platform);
        await using var echo = new EchoServer();
        var window = new MainWindow { DataContext = gui.ViewModel, Width = 1200, Height = 780 };
        window.Show();
        gui.ViewModel.Connections.Start();
        await Wait.UntilAsync(() => gui.ViewModel.Connections.IsWatching, "the connection watch");

        // A few relayed connections for the Connections page: two stay open, one is closed.
        using var first = await ConnectAsync(gui.Service, echo, 4242);
        using var second = await ConnectAsync(gui.Service, echo, 4343);
        using (var third = await ConnectAsync(gui.Service, echo, 4242))
        {
            third.Shutdown(SocketShutdown.Send);
            Assert.True(await third.IsClosedByPeerAsync(TestTimeout.Token()));
        }

        await Wait.UntilAsync(() => gui.ViewModel.Connections.Rows.Count(r => !r.IsOpen) == 1 && gui.ViewModel.Connections.Rows.Count == 3, "three connections");
        await gui.ViewModel.TickAsync();

        foreach (var page in gui.ViewModel.Pages)
        {
            gui.ViewModel.SelectedPage = page;
            if (page == gui.ViewModel.Rules)
            {
                gui.ViewModel.Rules.SelectedRule = gui.Workspace.Rules[1];
            }
            else if (page == gui.ViewModel.Proxies)
            {
                gui.ViewModel.Proxies.SelectedProxy = gui.Workspace.Proxies[2];
                gui.ViewModel.Proxies.SelectedChain = gui.Workspace.Chains[0];
            }

            await SettleAsync();
            if (page == gui.ViewModel.Diagnostics)
            {
                await Wait.UntilAsync(() => !gui.ViewModel.Diagnostics.IsRunning, "the diagnostics");
                await SettleAsync();
            }

            var content = window.GetLogicalDescendants().OfType<ContentControl>().First(c => c.Content == page);
            Assert.NotNull(content.Presenter?.Child);
            Save(window, $"{Array.IndexOf([.. gui.ViewModel.Pages], page) + 1:00}-{page.Title.ToLowerInvariant()}.png");
        }

        // Rendered text comes from the service, through the bindings.
        gui.ViewModel.SelectedPage = gui.ViewModel.Overview;
        await SettleAsync();
        var texts = window.GetLogicalDescendants().OfType<TextBlock>().Select(t => t.Text).ToList();
        Assert.Contains("Active rules", texts);
        Assert.Contains(texts, t => t?.StartsWith("proxynatord", StringComparison.Ordinal) == true);

        // An edit shows the bar for applying it.
        gui.Workspace.Rules[0].Ports = "443";
        gui.ViewModel.SelectedPage = gui.ViewModel.Rules;
        gui.ViewModel.Rules.SelectedRule = gui.Workspace.Rules[0];
        await SettleAsync();
        Assert.Contains(window.GetLogicalDescendants().OfType<TextBlock>(), t => t.Text == "Unapplied configuration changes" && t.IsEffectivelyVisible);
        Save(window, "09-pending-changes.png");

        Application.Current!.RequestedThemeVariant = ThemeVariant.Dark;
        try
        {
            gui.ViewModel.SelectedPage = gui.ViewModel.Connections;
            await SettleAsync();
            Save(window, "10-connections-dark.png");
        }
        finally
        {
            Application.Current.RequestedThemeVariant = ThemeVariant.Default;
        }

        window.Close();
    }

    [AvaloniaFact]
    public async Task A_missing_service_is_explained_in_the_window()
    {
        var endpoint = OperatingSystem.IsWindows() ? $"proxynator-missing-{Guid.NewGuid():N}" : Path.Combine(Path.GetTempPath(), $"pn-missing-{Guid.NewGuid():N}.sock");
        using var viewModel = new MainWindowViewModel(new Services.ServiceConnection(endpoint), new FakeFileDialogs());
        var window = new MainWindow { DataContext = viewModel, Width = 1200, Height = 780 };
        window.Show();

        await viewModel.TickAsync();
        await SettleAsync();

        Assert.Contains(window.GetLogicalDescendants().OfType<TextBlock>(), t => t.Text?.StartsWith("Cannot reach proxynatord", StringComparison.Ordinal) == true && t.IsEffectivelyVisible);
        Save(window, "00-service-unreachable.png");
        window.Close();
    }

    private static async Task<Socket> ConnectAsync(TestService service, EchoServer echo, int processId)
    {
        var ct = TestTimeout.Token();
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        service.Engine.Destinations.Register((IPEndPoint)client.LocalEndPoint!, new OriginalDestination(echo.Endpoint, processId));
        await client.ConnectAsync(service.Engine.Relay!.LocalEndpoints[0], ct);
        await client.SendAsync("hello"u8.ToArray(), ct);
        Assert.Equal("hello", await client.ReceiveStringAsync(5, ct));
        return client;
    }

    /// <summary>Lets page activation (service calls) finish and the layout settle.</summary>
    private static async Task SettleAsync()
    {
        for (var i = 0; i < 5; i++)
        {
            await Task.Delay(30);
            Dispatcher.UIThread.RunJobs();
        }
    }

    private static void Save(Window window, string name)
    {
        var frame = window.CaptureRenderedFrame();
        Assert.NotNull(frame);
        Directory.CreateDirectory(ScreenshotDirectory);
        frame.Save(Path.Combine(ScreenshotDirectory, name), new Avalonia.Media.Imaging.PngBitmapEncoderOptions());
    }
}
