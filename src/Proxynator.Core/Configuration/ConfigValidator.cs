using Proxynator.Core.Net;

namespace Proxynator.Core.Configuration;

/// <summary>Checks a configuration for semantic errors. All problems are reported, not just the first.</summary>
public static class ConfigValidator
{
    /// <summary>Returns all problems in <paramref name="config"/>; empty when it is valid.</summary>
    public static IReadOnlyList<ConfigError> Validate(ProxynatorConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        var errors = new List<ConfigError>();

        if (config.Version != ConfigVersion.Current)
        {
            errors.Add(new("$.version", $"Expected version {ConfigVersion.Current}, found {config.Version}."));
        }

        ValidateSettings(config.Settings, errors);
        var proxyIds = ValidateProxies(config.Proxies, errors);
        var targetIds = ValidateChains(config.Chains, proxyIds, errors);
        ValidateRules(config.Rules, targetIds, errors);
        ValidateRemoteDnsServer(config.Settings.Dns.RemoteServer, targetIds, errors);
        return errors;
    }

    private static void ValidateSettings(ProxynatorSettings settings, List<ConfigError> errors)
    {
        CheckDefined(settings.Capture.Mode, "$.settings.capture.mode", errors);
        CheckDefined(settings.Dns.Mode, "$.settings.dns.mode", errors);

        if (!AddressRange.TryParse(settings.Dns.FakeIpRange, out var fakeRange) ||
            fakeRange.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || fakeRange.PrefixLength > 24)
        {
            errors.Add(new("$.settings.dns.fakeIpRange", $"'{settings.Dns.FakeIpRange}' is not an IPv4 CIDR range with room for at least 256 addresses."));
        }

        CheckEntries(settings.Dns.RemoteDomains, "$.settings.dns.remoteDomains", static d => !string.IsNullOrWhiteSpace(d), "Must not be empty.", errors);

        if (settings.Dns.SniffTimeoutMs is < 0 or > 10_000)
        {
            errors.Add(new("$.settings.dns.sniffTimeoutMs", "Must be between 0 and 10000."));
        }

        if (settings.Relay.ConnectTimeoutMs is < 100 or > 300_000)
        {
            errors.Add(new("$.settings.relay.connectTimeoutMs", "Must be between 100 and 300000."));
        }
    }

    private static void ValidateRemoteDnsServer(RemoteDnsServer? server, HashSet<string> targetIds, List<ConfigError> errors)
    {
        if (server is null)
        {
            return;
        }

        const string path = "$.settings.dns.remoteServer";
        if (!System.Net.IPAddress.TryParse(server.Address, out _))
        {
            errors.Add(new($"{path}.address", $"'{server.Address}' is not an IP address (the server must be reachable without DNS)."));
        }

        if (server.Port is < 1 or > 65535)
        {
            errors.Add(new($"{path}.port", "Must be between 1 and 65535."));
        }

        if (!targetIds.Contains(server.Via))
        {
            errors.Add(new($"{path}.via", $"Unknown proxy or chain '{server.Via}'."));
        }
    }

    private static HashSet<string> ValidateProxies(IReadOnlyList<ProxyDefinition> proxies, List<ConfigError> errors)
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < proxies.Count; i++)
        {
            var path = $"$.proxies[{i}]";
            var proxy = proxies[i];
            ValidateId(proxy.Id, path, ids, errors);
            CheckDefined(proxy.Type, $"{path}.type", errors);

            if (string.IsNullOrWhiteSpace(proxy.Host) || !IsValidHostOrAddress(proxy.Host))
            {
                errors.Add(new($"{path}.host", $"'{proxy.Host}' is not a valid hostname or IP address."));
            }

            if (proxy.Port is < 1 or > 65535)
            {
                errors.Add(new($"{path}.port", "Must be between 1 and 65535."));
            }

            if (proxy.Auth is { } auth)
            {
                ValidateAuth(proxy.Type, auth, $"{path}.auth", errors);
            }
        }

        return ids;
    }

    private static void ValidateAuth(ProxyType type, ProxyAuth auth, string path, List<ConfigError> errors)
    {
        if (string.IsNullOrEmpty(auth.Username))
        {
            errors.Add(new($"{path}.username", "Must not be empty."));
        }

        switch (type)
        {
            case ProxyType.Socks4 or ProxyType.Socks4a when auth.Password is not null:
                errors.Add(new($"{path}.password", "SOCKS4 only supports a user ID; remove the password."));
                break;
            case ProxyType.Socks5 when auth.Password is null:
                errors.Add(new($"{path}.password", "SOCKS5 username/password authentication requires a password."));
                break;
            case ProxyType.Socks5 when System.Text.Encoding.UTF8.GetByteCount(auth.Username) > 255 ||
                                       System.Text.Encoding.UTF8.GetByteCount(auth.Password ?? string.Empty) > 255:
                errors.Add(new(path, "SOCKS5 user names and passwords are limited to 255 bytes."));
                break;
        }
    }

    private static HashSet<string> ValidateChains(IReadOnlyList<ChainDefinition> chains, HashSet<string> proxyIds, List<ConfigError> errors)
    {
        var allIds = new HashSet<string>(proxyIds, StringComparer.OrdinalIgnoreCase);
        var chainIds = new HashSet<string>(chains.Select(c => c.Id).Where(id => id is not null), StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < chains.Count; i++)
        {
            var path = $"$.chains[{i}]";
            var chain = chains[i];
            ValidateId(chain.Id, path, allIds, errors);

            if (chain.Hops.Count == 0)
            {
                errors.Add(new($"{path}.hops", "A chain needs at least one hop."));
            }

            for (var h = 0; h < chain.Hops.Count; h++)
            {
                var hop = chain.Hops[h];
                if (proxyIds.Contains(hop))
                {
                    continue;
                }

                errors.Add(new(
                    $"{path}.hops[{h}]",
                    chainIds.Contains(hop) ? $"'{hop}' is a chain; chains can only contain proxies." : $"Unknown proxy '{hop}'."));
            }
        }

        return allIds;
    }

    private static void ValidateRules(IReadOnlyList<RuleDefinition> rules, HashSet<string> targetIds, List<ConfigError> errors)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < rules.Count; i++)
        {
            var path = $"$.rules[{i}]";
            var rule = rules[i];

            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                errors.Add(new($"{path}.name", "Must not be empty."));
            }
            else if (!names.Add(rule.Name))
            {
                errors.Add(new($"{path}.name", $"Duplicate rule name '{rule.Name}'."));
            }

            ValidateMatch(rule.Match, $"{path}.match", errors);
            ValidateAction(rule.Action, $"{path}.action", targetIds, errors);
        }
    }

    private static void ValidateMatch(RuleMatch match, string path, List<ConfigError> errors)
    {
        CheckEntries(match.Processes, $"{path}.processes", static p => !string.IsNullOrWhiteSpace(p), "Must not be empty.", errors);
        CheckEntries(match.Hosts, $"{path}.hosts", static h => !string.IsNullOrWhiteSpace(h), "Must not be empty.", errors);
        CheckEntries(match.Addresses, $"{path}.addresses", static a => AddressRange.TryParse(a, out _), "Not a valid IP address or CIDR range.", errors);
        CheckEntries(match.Ports, $"{path}.ports", static p => PortRange.TryParse(p, out _), "Not a valid port or port range (e.g. 443 or 8000-8100).", errors);
        for (var i = 0; i < match.Protocols.Count; i++)
        {
            CheckDefined(match.Protocols[i], $"{path}.protocols[{i}]", errors);
        }
    }

    private static void ValidateAction(RuleActionDefinition action, string path, HashSet<string> targetIds, List<ConfigError> errors)
    {
        CheckDefined(action.Type, $"{path}.type", errors);
        CheckDefined(action.Udp, $"{path}.udp", errors);

        if (action.Type == RuleActionType.Proxy)
        {
            if (string.IsNullOrWhiteSpace(action.Target))
            {
                errors.Add(new($"{path}.target", "A proxy action needs a target proxy or chain."));
            }
            else if (!targetIds.Contains(action.Target))
            {
                errors.Add(new($"{path}.target", $"Unknown proxy or chain '{action.Target}'."));
            }
        }
        else if (action.Target is not null)
        {
            errors.Add(new($"{path}.target", $"A '{action.Type.ToString().ToLowerInvariant()}' action does not take a target."));
        }
    }

    private static void ValidateId(string id, string path, HashSet<string> seen, List<ConfigError> errors)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            errors.Add(new($"{path}.id", "Must not be empty."));
        }
        else if (!seen.Add(id))
        {
            errors.Add(new($"{path}.id", $"Duplicate proxy/chain id '{id}'."));
        }
    }

    private static void CheckEntries(IReadOnlyList<string> entries, string path, Func<string, bool> isValid, string message, List<ConfigError> errors)
    {
        for (var i = 0; i < entries.Count; i++)
        {
            if (entries[i] is null || !isValid(entries[i]))
            {
                errors.Add(new($"{path}[{i}]", $"'{entries[i]}': {message}"));
            }
        }
    }

    private static void CheckDefined<TEnum>(TEnum value, string path, List<ConfigError> errors)
        where TEnum : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            errors.Add(new(path, $"Unknown value '{value}'."));
        }
    }

    private static bool IsValidHostOrAddress(string host)
    {
        try
        {
            _ = TargetEndpoint.FromHost(host, 1);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
