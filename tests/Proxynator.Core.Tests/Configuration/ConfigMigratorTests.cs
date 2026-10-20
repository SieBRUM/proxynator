using System.Text.Json.Nodes;
using Proxynator.Core.Configuration;

namespace Proxynator.Core.Tests.Configuration;

public class ConfigMigratorTests
{
    private sealed class RenameMigration(int fromVersion, string from, string to) : IConfigMigration
    {
        public int FromVersion => fromVersion;

        public void Apply(JsonObject root)
        {
            var value = root[from];
            root.Remove(from);
            root[to] = value?.DeepClone();
        }
    }

    [Fact]
    public void Migrations_are_applied_in_order_and_version_is_updated()
    {
        var migrator = new ConfigMigrator([new RenameMigration(2, "b", "c"), new RenameMigration(1, "a", "b")]);
        var root = new JsonObject { ["version"] = 1, ["a"] = 42 };

        migrator.Upgrade(root, 1, 3);

        Assert.Equal(42, root["c"]!.GetValue<int>());
        Assert.False(root.ContainsKey("a"));
        Assert.Equal(3, root["version"]!.GetValue<int>());
    }

    [Fact]
    public void Missing_migration_throws()
    {
        var migrator = new ConfigMigrator([]);

        Assert.Throws<InvalidOperationException>(() => migrator.Upgrade(new JsonObject(), 1, 2));
    }
}
