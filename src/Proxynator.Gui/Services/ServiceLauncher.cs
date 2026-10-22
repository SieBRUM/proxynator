using Proxynator.Client;

namespace Proxynator.Gui.Services;

/// <summary>The real <see cref="IServiceLauncher"/>.</summary>
internal sealed class ServiceLauncher : IServiceLauncher
{
    public ServiceStartPlan? Plan(string endpoint, out string problem) => ServiceStarter.PlanForThisMachine(endpoint, out problem);

    public string? Start(ServiceStartPlan plan) => ServiceStarter.Start(plan);
}
