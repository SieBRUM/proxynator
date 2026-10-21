using Proxynator.Ipc;

namespace Proxynator.Gui;

/// <summary>Command line options of the GUI.</summary>
internal sealed record GuiOptions(string Endpoint)
{
    /// <summary>Reads <c>--endpoint &lt;value&gt;</c> or <c>--endpoint=&lt;value&gt;</c>; anything else is ignored.</summary>
    public static GuiOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var endpoint = IpcEndpoint.Default;
        for (var i = 0; i < args.Count; i++)
        {
            if (args[i] == "--endpoint" && i + 1 < args.Count)
            {
                endpoint = args[++i];
            }
            else if (args[i].StartsWith("--endpoint=", StringComparison.Ordinal))
            {
                endpoint = args[i]["--endpoint=".Length..];
            }
        }

        return new GuiOptions(endpoint);
    }
}
