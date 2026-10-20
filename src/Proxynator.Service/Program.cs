using System.CommandLine;
using Proxynator.Ipc;
using Proxynator.Service;

var configOption = new Option<string>("--config", "-c")
{
    Description = "Configuration file.",
    DefaultValueFactory = _ => ConfigFile.DefaultPath,
};
var endpointOption = new Option<string>("--endpoint")
{
    Description = $"Control API endpoint: pipe name on Windows, socket path elsewhere (default: {IpcEndpoint.Default}).",
    DefaultValueFactory = _ => IpcEndpoint.Default,
};
var noCaptureOption = new Option<bool>("--no-capture") { Description = "Run the control API and relay without capturing traffic (development/testing)." };
var verboseOption = new Option<bool>("--verbose", "-v") { Description = "Debug logging (logs every redirected connection)." };
var consoleOption = new Option<bool>("--console") { Description = "Run in the foreground (the default when not started by the service manager)." };

var root = new RootCommand("proxynatord: the Proxynator service. Captures traffic of selected applications and routes it through proxies.")
{
    configOption, endpointOption, noCaptureOption, verboseOption, consoleOption,
};

root.SetAction(async (parseResult, cancellationToken) =>
{
    var options = new ServiceOptions
    {
        ConfigPath = Path.GetFullPath(parseResult.GetValue(configOption)!),
        Endpoint = parseResult.GetValue(endpointOption)!,
        NoCapture = parseResult.GetValue(noCaptureOption),
        Verbose = parseResult.GetValue(verboseOption),
    };

    try
    {
        await using var app = ServiceHost.Build(options);
        await app.RunAsync(cancellationToken);
        return 0;
    }
    catch (ServiceStartupException ex)
    {
        await Console.Error.WriteLineAsync($"proxynatord: {ex.Message}");
        return ex.ExitCode;
    }
});

return await root.Parse(args).InvokeAsync();
