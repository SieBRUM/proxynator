using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Grpc.Core;
using Proxynator.Gui.Services;
using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>
/// The "Clear DNS cache" action (<c>proxynator dns clear-cache</c>), shown on the Overview and Settings pages. It acts
/// on the running service at once; it is not part of the configuration.
/// </summary>
internal sealed partial class DnsCacheViewModel(ServiceConnection service) : ObservableObject
{
    /// <summary>Also clear the operating system's DNS cache (Windows DNS client, systemd-resolved).</summary>
    [ObservableProperty]
    public partial bool IncludeSystem { get; set; }

    /// <summary>The outcome of the last clear.</summary>
    [ObservableProperty]
    public partial string Message { get; private set; } = string.Empty;

    [ObservableProperty]
    public partial bool IsError { get; private set; }

    [RelayCommand]
    private async Task ClearAsync()
    {
        try
        {
            var response = await service.Client.ClearDnsCacheAsync(new ClearDnsCacheRequest { IncludeSystem = IncludeSystem }, ServiceConnection.Options());
            var message = $"Cleared {response.ClearedEntries} cached answer(s) at {DateTime.Now:HH:mm:ss}.";
            IsError = IncludeSystem && !response.SystemCacheCleared;
            Message = IncludeSystem ? $"{message} {response.SystemCacheDetail}" : message;
        }
        catch (RpcException ex)
        {
            IsError = true;
            Message = service.Describe(ex);
        }
    }
}
