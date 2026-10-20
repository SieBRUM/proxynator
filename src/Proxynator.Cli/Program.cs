using System.CommandLine;
using Proxynator.Cli;
using Proxynator.Ipc;

var endpointOption = new Option<string>("--endpoint")
{
    Description = $"proxynatord control endpoint: pipe name on Windows, socket path elsewhere (default: {IpcEndpoint.Default}; env {IpcEndpoint.EnvironmentVariable}).",
    DefaultValueFactory = _ => IpcEndpoint.Default,
    Recursive = true,
};

Commands CreateCommands(ParseResult parseResult) => new(parseResult.GetValue(endpointOption)!, Console.Out, Console.Error);

var status = new Command("status", "Show service, capture and relay status.");
status.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).StatusAsync(cancellationToken));

var fileArgument = new Argument<string>("file") { Description = "Path to a configuration JSON file." };
var validate = new Command("validate", "Check a configuration file without applying it (works without the service).") { fileArgument };
validate.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).ValidateConfigAsync(parseResult.GetValue(fileArgument)!, cancellationToken));

var noSaveOption = new Option<bool>("--no-save") { Description = "Apply only until the service restarts; do not save it as the service configuration." };
var load = new Command("load", "Validate a configuration file and apply it to the running service atomically.") { fileArgument, noSaveOption };
load.SetAction((parseResult, cancellationToken) =>
    CreateCommands(parseResult).LoadConfigAsync(parseResult.GetValue(fileArgument)!, !parseResult.GetValue(noSaveOption), cancellationToken));

var show = new Command("show", "Print the active configuration as JSON.");
show.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).ShowConfigAsync(cancellationToken));

var config = new Command("config", "Validate, load or show the configuration.") { validate, load, show };

var rulesList = new Command("list", "List the active rules in evaluation order.");
rulesList.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).ListRulesAsync(cancellationToken));
var rules = new Command("rules", "Inspect routing rules.") { rulesList };

var followOption = new Option<bool>("--follow", "-f") { Description = "Keep running and print connections as they open and close." };
var connections = new Command("connections", "List connections currently handled by the relay.") { followOption };
connections.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).ConnectionsAsync(parseResult.GetValue(followOption), cancellationToken));

var doctor = new Command("doctor", "Check privileges, driver files, capture, relay and proxy reachability.");
doctor.SetAction((parseResult, cancellationToken) => CreateCommands(parseResult).DoctorAsync(cancellationToken));

var root = new RootCommand("proxynator: control the Proxynator service (proxynatord).")
{
    endpointOption, status, config, rules, connections, doctor,
};

return await root.Parse(args).InvokeAsync();
