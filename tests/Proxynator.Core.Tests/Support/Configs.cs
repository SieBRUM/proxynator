using Proxynator.Core.Configuration;

namespace Proxynator.Core.Tests.Support;

internal static class Configs
{
    public static ProxynatorConfig Minimal() => new() { Version = ConfigVersion.Current };

    public static ProxyDefinition Proxy(string id, ProxyType type, int port, string host = "127.0.0.1", ProxyAuth? auth = null) =>
        new() { Id = id, Type = type, Host = host, Port = port, Auth = auth };

    public static RuleDefinition Rule(string name, RuleActionType action, string? target = null, RuleMatch? match = null) =>
        new() { Name = name, Match = match ?? new RuleMatch(), Action = new RuleActionDefinition { Type = action, Target = target } };
}
