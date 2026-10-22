using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Proxynator.Core.Platform;
using Proxynator.Core.Tests.Support;
using Proxynator.Ipc;
using Proxynator.Ipc.V1;

namespace Proxynator.Service.Tests;

/// <summary>Runs proxynatord in-process on a private pipe/socket and a temporary config path.</summary>
internal sealed class TestService : IAsyncDisposable
{
    private readonly string directory;
    private GrpcChannel? channel;

    private TestService(WebApplication app, string endpoint, string directory, string configPath)
    {
        App = app;
        Endpoint = endpoint;
        this.directory = directory;
        ConfigPath = configPath;
    }

    public WebApplication App { get; }

    public string Endpoint { get; }

    public string ConfigPath { get; }

    public ProxynatorEngine Engine => App.Services.GetRequiredService<ProxynatorEngine>();

    public Control.ControlClient Client
    {
        get
        {
            channel ??= ControlClientFactory.CreateChannel(Endpoint);
            return ControlClientFactory.CreateClient(channel);
        }
    }

    public static string NewEndpoint(string directory) => OperatingSystem.IsWindows()
        ? $"proxynator-test-{Guid.NewGuid():N}"
        : Path.Combine(directory, "s.sock");

    public static async Task<TestService> StartAsync(IPlatformModule? platform = null, bool noCapture = true, string? initialConfigJson = null, string? endpoint = null)
    {
        var directory = Directory.CreateTempSubdirectory("pn-").FullName;
        var configPath = Path.Combine(directory, "config.json");
        if (initialConfigJson is not null)
        {
            await File.WriteAllTextAsync(configPath, initialConfigJson);
        }

        endpoint ??= NewEndpoint(directory);
        var options = new ServiceOptions { ConfigPath = configPath, Endpoint = endpoint, NoCapture = noCapture };
        var app = ServiceHost.Build(options, platform ?? new TestPlatformModule());
        var service = new TestService(app, endpoint, directory, configPath);
        try
        {
            await app.StartAsync(TestTimeout.Token());
        }
        catch
        {
            await service.DisposeAsync();
            throw;
        }

        return service;
    }

    public async ValueTask DisposeAsync()
    {
        channel?.Dispose();
        try
        {
            await App.StopAsync(TestTimeout.Token());
        }
        catch (InvalidOperationException)
        {
            // Never started.
        }

        await App.DisposeAsync();
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
