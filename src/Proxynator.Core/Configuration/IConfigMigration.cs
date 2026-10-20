using System.Text.Json.Nodes;

namespace Proxynator.Core.Configuration;

/// <summary>Upgrades the raw JSON of a configuration from <see cref="FromVersion"/> to <see cref="FromVersion"/> + 1.</summary>
internal interface IConfigMigration
{
    int FromVersion { get; }

    void Apply(JsonObject root);
}
