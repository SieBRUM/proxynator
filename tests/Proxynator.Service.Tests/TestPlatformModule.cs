using System.Net;
using Microsoft.Extensions.Logging;
using Proxynator.Core.Configuration;
using Proxynator.Core.Platform;
using Proxynator.Core.Processes;

namespace Proxynator.Service.Tests;

/// <summary>A configurable platform module so engine behaviour can be tested on any OS without a driver.</summary>
internal sealed class TestPlatformModule : IPlatformModule, IPrivilegeChecker, IProcessInfoProvider
{
    public bool Privileged { get; init; } = true;

    /// <summary>When null, capture is unsupported.</summary>
    public FakeCaptureBackend? Backend { get; init; }

    public Dictionary<int, ProcessInfo> Processes { get; } = [];

    public string Name => "Test";

    public CaptureMode DefaultCaptureMode => CaptureMode.WinDivert;

    public IPrivilegeChecker PrivilegeChecker => this;

    public IProcessInfoProvider ProcessInfo => this;

    public bool Supports(CaptureMode mode) => Backend is not null;

    public ICaptureBackend CreateCaptureBackend(CaptureMode mode, ILoggerFactory loggerFactory) =>
        Backend ?? throw new NotSupportedException("Capture is not supported by the test platform.");

    public IEnumerable<DiagnosticResult> RunDiagnostics() => [new DiagnosticResult("Test platform", DiagnosticStatus.Ok, "fine")];

    public PrivilegeCheckResult Check() => new(Privileged, Privileged ? "test: privileged" : "test: not privileged");

    public ProcessInfo? GetProcessInfo(int processId) => Processes.GetValueOrDefault(processId);
}

internal sealed class FakeCaptureBackend : ICaptureBackend
{
    public CaptureContext? Context { get; private set; }

    public bool Stopped { get; private set; }

    public CaptureMode Mode => CaptureMode.WinDivert;

    public IReadOnlyList<IPEndPoint> RelayListenEndpoints => [new IPEndPoint(IPAddress.Loopback, 0)];

    public Task StartAsync(CaptureContext context, CancellationToken cancellationToken)
    {
        Context = context;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Stopped = true;
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => new(StopAsync(CancellationToken.None));
}
