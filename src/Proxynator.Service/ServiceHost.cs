using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Proxynator.Core.Platform;

namespace Proxynator.Service;

/// <summary>Builds the <c>proxynatord</c> host: engine + gRPC control API on the local IPC endpoint.</summary>
internal static class ServiceHost
{
    public static WebApplication Build(ServiceOptions options, IPlatformModule? platform = null, string[]? args = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
        {
            Args = args ?? [],
            ContentRootPath = AppContext.BaseDirectory,
        });

        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(o =>
        {
            o.SingleLine = true;
            o.TimestampFormat = "HH:mm:ss ";
        });

        // After ClearProviders: when actually running as a Windows service this also logs to the Event Log
        // (source "proxynatord"); under systemd it switches to journald-friendly console output.
        builder.Host.UseWindowsService(o => o.ServiceName = "proxynatord");
        builder.Host.UseSystemd();

        builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning);
        builder.Logging.AddFilter("Grpc", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Extensions.Hosting.Internal.Host", LogLevel.Critical); // startup errors are reported by Program
        if (options.Verbose)
        {
            builder.Logging.AddFilter("Proxynator", LogLevel.Debug);
        }

        ConfigureTransport(builder.WebHost, options.Endpoint);

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(platform ?? PlatformModules.ForCurrentOS());
        builder.Services.AddSingleton<ProxynatorEngine>();
        builder.Services.AddHostedService(services => services.GetRequiredService<ProxynatorEngine>());
        builder.Services.AddGrpc();

        var app = builder.Build();
        app.MapGrpcService<ControlService>();

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            if (!OperatingSystem.IsWindows())
            {
                RestrictSocket(options.Endpoint);
            }
        });

        return app;
    }

    private static void ConfigureTransport(IWebHostBuilder webHost, string endpoint)
    {
        if (OperatingSystem.IsWindows())
        {
            var security = CreatePipeSecurity();
            webHost.UseNamedPipes(o =>
            {
                o.CurrentUserOnly = false;
                o.PipeSecurity = security;
            });
            webHost.ConfigureKestrel(k => k.ListenNamedPipe(endpoint, l => l.Protocols = HttpProtocols.Http2));
            return;
        }

        var directory = Path.GetDirectoryName(Path.GetFullPath(endpoint));
        if (directory is not null)
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(endpoint))
        {
            File.Delete(endpoint); // stale socket from a previous run
        }

        webHost.ConfigureKestrel(k => k.ListenUnixSocket(endpoint, l => l.Protocols = HttpProtocols.Http2));
    }

    /// <summary>Owner and group only: whoever can use the socket controls where traffic goes.</summary>
    [UnsupportedOSPlatform("windows")]
    private static void RestrictSocket(string path) =>
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.GroupWrite);

    /// <summary>
    /// SYSTEM, Administrators and the account running the service. In console mode that is the user who started it,
    /// so their non-elevated CLI works; as a Windows service (LocalSystem) the CLI must run elevated.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        using var identity = WindowsIdentity.GetCurrent();
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                     identity.User!,
                 })
        {
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        return security;
    }
}
