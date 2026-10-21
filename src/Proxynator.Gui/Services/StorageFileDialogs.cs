using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace Proxynator.Gui.Services;

/// <summary><see cref="IFileDialogs"/> on Avalonia's storage provider of the main window.</summary>
internal sealed class StorageFileDialogs(Func<TopLevel?> topLevel) : IFileDialogs
{
    public async Task<string?> PickFileToOpenAsync(string title, string? filterName, IReadOnlyList<string>? patterns)
    {
        if (topLevel()?.StorageProvider is not { CanOpen: true } storage)
        {
            return null;
        }

        var options = new FilePickerOpenOptions { Title = title, AllowMultiple = false };
        if (filterName is not null && patterns is not null)
        {
            options.FileTypeFilter = [new FilePickerFileType(filterName) { Patterns = patterns }, FilePickerFileTypes.All];
        }

        var files = await storage.OpenFilePickerAsync(options);
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }

    public async Task<string?> PickFileToSaveAsync(string title, string suggestedName)
    {
        if (topLevel()?.StorageProvider is not { CanSave: true } storage)
        {
            return null;
        }

        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = "json",
            FileTypeChoices = [new FilePickerFileType("JSON") { Patterns = ["*.json"] }],
        });
        return file?.TryGetLocalPath();
    }

    public async Task<string?> PickFolderAsync(string title)
    {
        if (topLevel()?.StorageProvider is not { CanPickFolder: true } storage)
        {
            return null;
        }

        var folders = await storage.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title });
        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    }
}
