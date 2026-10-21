using Proxynator.Core.Tests.Support;
using Proxynator.Gui.Services;
using Proxynator.Gui.ViewModels;
using Proxynator.Service.Tests;

namespace Proxynator.Gui.Tests;

/// <summary>File pickers that answer with prepared paths.</summary>
internal sealed class FakeFileDialogs : IFileDialogs
{
    public string? OpenPath { get; set; }

    public string? SavePath { get; set; }

    public string? FolderPath { get; set; }

    public Task<string?> PickFileToOpenAsync(string title, string? filterName, IReadOnlyList<string>? patterns) => Task.FromResult(OpenPath);

    public Task<string?> PickFileToSaveAsync(string title, string suggestedName) => Task.FromResult(SavePath);

    public Task<string?> PickFolderAsync(string title) => Task.FromResult(FolderPath);
}

/// <summary>An in-process proxynatord and the GUI's view model connected to it.</summary>
internal sealed class GuiHarness : IAsyncDisposable
{
    private GuiHarness(TestService service, MainWindowViewModel viewModel, FakeFileDialogs dialogs)
    {
        Service = service;
        ViewModel = viewModel;
        Dialogs = dialogs;
    }

    public static string SampleConfig => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "samples", "config.json"));

    public TestService Service { get; }

    public MainWindowViewModel ViewModel { get; }

    public FakeFileDialogs Dialogs { get; }

    public ConfigWorkspace Workspace => ViewModel.Workspace;

    public static async Task<GuiHarness> StartAsync(string? initialConfigJson = null, TestPlatformModule? platform = null)
    {
        var service = await TestService.StartAsync(platform, initialConfigJson: initialConfigJson);
        var dialogs = new FakeFileDialogs();
        var viewModel = new MainWindowViewModel(new ServiceConnection(service.Endpoint), dialogs);
        var harness = new GuiHarness(service, viewModel, dialogs);
        await viewModel.TickAsync();
        return harness;
    }

    public async ValueTask DisposeAsync()
    {
        ViewModel.Dispose();
        await Service.DisposeAsync();
    }
}

internal static class Wait
{
    /// <summary>Waits (on the UI thread, so view model updates keep coming) until <paramref name="condition"/> holds.</summary>
    public static async Task UntilAsync(Func<bool> condition, string what)
    {
        var token = TestTimeout.Token();
        while (!condition())
        {
            if (token.IsCancellationRequested)
            {
                Assert.Fail($"Timed out waiting for {what}.");
            }

            await Task.Delay(20, CancellationToken.None);
        }
    }
}
