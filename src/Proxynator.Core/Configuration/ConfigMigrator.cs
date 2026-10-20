using System.Text.Json.Nodes;

namespace Proxynator.Core.Configuration;

/// <summary>Applies <see cref="IConfigMigration"/>s in sequence to bring old configuration files up to date.</summary>
internal sealed class ConfigMigrator(IEnumerable<IConfigMigration> migrations)
{
    /// <summary>
    /// The migrations shipped with this build. When <see cref="ConfigVersion.Current"/> is bumped, add a migration
    /// from the previous version here.
    /// </summary>
    public static ConfigMigrator Default { get; } = new([]);

    private readonly Dictionary<int, IConfigMigration> byVersion = migrations.ToDictionary(m => m.FromVersion);

    public void Upgrade(JsonObject root, int fromVersion, int toVersion)
    {
        for (var version = fromVersion; version < toVersion; version++)
        {
            if (!byVersion.TryGetValue(version, out var migration))
            {
                throw new InvalidOperationException($"No configuration migration from version {version} to {version + 1}.");
            }

            migration.Apply(root);
        }

        root["version"] = toVersion;
    }
}
