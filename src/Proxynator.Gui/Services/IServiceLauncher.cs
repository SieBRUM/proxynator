using Proxynator.Client;

namespace Proxynator.Gui.Services;

/// <summary>Starts proxynatord elevated (<see cref="ServiceStarter"/>); an interface so view models can be tested.</summary>
internal interface IServiceLauncher
{
    /// <summary>How the service would be started, or null with <paramref name="problem"/>.</summary>
    ServiceStartPlan? Plan(string endpoint, out string problem);

    /// <summary>Runs the plan; null when started, otherwise why not.</summary>
    string? Start(ServiceStartPlan plan);
}
