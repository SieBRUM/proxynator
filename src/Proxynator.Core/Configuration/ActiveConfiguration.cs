using Proxynator.Core.Net;
using Proxynator.Core.Proxies;
using Proxynator.Core.Rules;

namespace Proxynator.Core.Configuration;

/// <summary>A validated configuration with its routes resolved and rules compiled. Immutable.</summary>
public sealed class ActiveConfiguration
{
    private ActiveConfiguration(ProxynatorConfig config, IReadOnlyDictionary<string, ProxyRoute> routes, RuleEngine rules)
    {
        Config = config;
        Routes = routes;
        Rules = rules;
        ProxyEndpoints = [.. routes.Values.SelectMany(r => r.Hops).Select(h => h.Endpoint).Distinct()];
        proxyHostnames = new HashSet<string>(ProxyEndpoints.Where(e => e.Host is not null).Select(e => e.Host!), StringComparer.OrdinalIgnoreCase);
        remoteDomains = [.. config.Settings.Dns.RemoteDomains.Select(d => new WildcardPattern(d.TrimEnd('.')))];
    }

    private readonly HashSet<string> proxyHostnames;
    private readonly WildcardPattern[] remoteDomains;

    /// <summary>The source configuration.</summary>
    public ProxynatorConfig Config { get; }

    /// <summary>Global settings.</summary>
    public ProxynatorSettings Settings => Config.Settings;

    /// <summary>Routes by proxy or chain identifier (case-insensitive).</summary>
    public IReadOnlyDictionary<string, ProxyRoute> Routes { get; }

    /// <summary>The compiled rules.</summary>
    public RuleEngine Rules { get; }

    /// <summary>Every configured proxy endpoint; capture backends must never redirect connections to these.</summary>
    public IReadOnlyList<TargetEndpoint> ProxyEndpoints { get; }

    /// <summary>
    /// Whether a DNS query for <paramref name="name"/> gets a fake answer in <see cref="DnsMode.Remote"/>. Proxy
    /// hostnames (they must resolve for real), single-label names, <c>localhost</c> and reverse lookups never do.
    /// </summary>
    public bool ShouldFakeResolve(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        name = name.TrimEnd('.');
        if (!name.Contains('.', StringComparison.Ordinal) ||
            name.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase) ||
            proxyHostnames.Contains(name))
        {
            return false;
        }

        return remoteDomains.Any(pattern => pattern.IsMatch(name));
    }

    /// <summary>Validates and compiles <paramref name="config"/>.</summary>
    /// <exception cref="ConfigValidationException">The configuration is invalid.</exception>
    public static ActiveConfiguration Create(ProxynatorConfig config)
    {
        var errors = ConfigValidator.Validate(config);
        if (errors.Count > 0)
        {
            throw new ConfigValidationException(errors);
        }

        var hops = config.Proxies.ToDictionary(p => p.Id, ProxyHop.FromDefinition, StringComparer.OrdinalIgnoreCase);
        var routes = new Dictionary<string, ProxyRoute>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, hop) in hops)
        {
            routes[id] = new ProxyRoute(id, [hop]);
        }

        foreach (var chain in config.Chains)
        {
            routes[chain.Id] = new ProxyRoute(chain.Id, [.. chain.Hops.Select(h => hops[h])]);
        }

        return new ActiveConfiguration(config, routes, RuleEngine.Create(config.Rules, routes));
    }
}
