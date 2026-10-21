namespace Proxynator.Gui.Services;

/// <summary>File pickers, behind an interface so view models can be tested without a window.</summary>
internal interface IFileDialogs
{
    /// <summary>Asks for a file to open; null when cancelled.</summary>
    Task<string?> PickFileToOpenAsync(string title, string? filterName, IReadOnlyList<string>? patterns);

    /// <summary>Asks for a file to save to; null when cancelled.</summary>
    Task<string?> PickFileToSaveAsync(string title, string suggestedName);

    /// <summary>Asks for a folder; null when cancelled.</summary>
    Task<string?> PickFolderAsync(string title);
}
