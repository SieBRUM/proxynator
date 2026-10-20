using System.Text.Json;
using System.Text.Json.Nodes;

namespace Proxynator.Core.Configuration;

/// <summary>Reads, migrates, validates and writes configuration files.</summary>
public static class ConfigLoader
{
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>Parses configuration JSON: parse, migrate to the current version, deserialize, validate.</summary>
    public static ConfigLoadResult Parse(string json) => Parse(json, ConfigMigrator.Default);

    /// <summary>Loads and parses a configuration file.</summary>
    public static async Task<ConfigLoadResult> LoadFileAsync(string path, CancellationToken cancellationToken = default)
    {
        string json;
        try
        {
            json = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ConfigLoadResult.Failed("$", $"Could not read '{path}': {ex.Message}");
        }

        return Parse(json);
    }

    /// <summary>Serializes a configuration to indented JSON.</summary>
    public static string Serialize(ProxynatorConfig config) =>
        JsonSerializer.Serialize(config, ConfigJsonContext.Default.ProxynatorConfig);

    internal static ConfigLoadResult Parse(string json, ConfigMigrator migrator)
    {
        ArgumentNullException.ThrowIfNull(json);

        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json, documentOptions: DocumentOptions);
        }
        catch (JsonException ex)
        {
            return ConfigLoadResult.Failed("$", $"Invalid JSON: {ex.Message}");
        }

        if (root is not JsonObject rootObject)
        {
            return ConfigLoadResult.Failed("$", "The configuration must be a JSON object.");
        }

        if (!rootObject.TryGetPropertyValue("version", out var versionNode) || versionNode is null)
        {
            return ConfigLoadResult.Failed("$.version", "The 'version' property is required.");
        }

        if (versionNode is not JsonValue versionValue || !versionValue.TryGetValue<int>(out var version))
        {
            return ConfigLoadResult.Failed("$.version", "The 'version' property must be an integer.");
        }

        if (version > ConfigVersion.Current)
        {
            return ConfigLoadResult.Failed(
                "$.version",
                $"Configuration version {version} is newer than this build supports ({ConfigVersion.Current}). Upgrade Proxynator.");
        }

        if (version < ConfigVersion.Minimum)
        {
            return ConfigLoadResult.Failed("$.version", $"Configuration version {version} is not supported.");
        }

        migrator.Upgrade(rootObject, version, ConfigVersion.Current);

        ProxynatorConfig? config;
        try
        {
            config = rootObject.Deserialize(ConfigJsonContext.Default.ProxynatorConfig);
        }
        catch (JsonException ex)
        {
            return ConfigLoadResult.Failed(ex.Path ?? "$", ex.Message);
        }

        if (config is null)
        {
            return ConfigLoadResult.Failed("$", "The configuration is empty.");
        }

        var errors = ConfigValidator.Validate(config);
        return errors.Count == 0 ? ConfigLoadResult.Succeeded(config) : ConfigLoadResult.Failed(errors);
    }
}
