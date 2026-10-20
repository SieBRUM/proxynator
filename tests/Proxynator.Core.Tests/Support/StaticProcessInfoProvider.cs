using Proxynator.Core.Processes;

namespace Proxynator.Core.Tests.Support;

internal sealed class StaticProcessInfoProvider(params ProcessInfo[] processes) : IProcessInfoProvider
{
    private readonly Dictionary<int, ProcessInfo> byId = processes.ToDictionary(p => p.ProcessId);

    public ProcessInfo? GetProcessInfo(int processId) => byId.GetValueOrDefault(processId);
}
