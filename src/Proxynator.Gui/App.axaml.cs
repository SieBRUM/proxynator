using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Proxynator.Gui.Services;
using Proxynator.Gui.ViewModels;
using Proxynator.Gui.Views;

namespace Proxynator.Gui;

internal sealed partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var options = GuiOptions.Parse(desktop.Args ?? []);
            var window = new MainWindow();
            var viewModel = new MainWindowViewModel(new ServiceConnection(options.Endpoint), new StorageFileDialogs(() => window));
            window.DataContext = viewModel;
            window.Opened += (_, _) => viewModel.Start();
            desktop.Exit += (_, _) => viewModel.Dispose();
            desktop.MainWindow = window;
        }

        base.OnFrameworkInitializationCompleted();
    }
}
