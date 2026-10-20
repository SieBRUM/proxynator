using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Proxynator.Core.Tests.Support;
using Proxynator.Ipc;
using Proxynator.Service;

namespace Proxynator.IntegrationTests;

/// <summary>An in-process proxynatord with its own control endpoint (and so its own hook pipe).</summary>
internal sealed class IntegrationService : IAsyncDisposable
{
    private readonly WebApplication app;
    private bool disposed;

    private IntegrationService(WebApplication app, string endpoint)
    {
        this.app = app;
        Endpoint = endpoint;
    }

    public string Endpoint { get; }

    /// <summary>The pipe hooked processes register on.</summary>
    public string HookPipe => IpcEndpoint.HookEndpoint(Endpoint);

    /// <summary>Writes the configuration into <paramref name="directory"/> and starts the service; capture must come up.</summary>
    public static async Task<IntegrationService> StartAsync(string directory, string configJson)
    {
        var configPath = Path.Combine(directory, "config.json");
        await File.WriteAllTextAsync(configPath, configJson);
        var options = new ServiceOptions
        {
            ConfigPath = configPath,
            // A pipe name on Windows, a socket path elsewhere (the hook endpoint is derived from it).
            Endpoint = OperatingSystem.IsWindows()
                ? $"proxynator-it-{Guid.NewGuid():N}"
                : Path.Combine(directory, "proxynator.sock"),
            Verbose = true,
        };

        var app = ServiceHost.Build(options);
        await app.StartAsync(TestTimeout.Token(30));
        var engine = app.Services.GetRequiredService<ProxynatorEngine>();
        var service = new IntegrationService(app, options.Endpoint);
        if (engine.CaptureState != CaptureState.Running)
        {
            await service.DisposeAsync();
            Assert.Fail($"Capture did not start: {engine.CaptureDetail}");
        }

        return service;
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        await app.StopAsync(TestTimeout.Token(30));
        await app.DisposeAsync();
    }
}
