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

var detachOption = new Option<bool>("--detach", "-d") { Description = "Do not wait for the program to exit." };
var programArgument = new Argument<string>("program") { Description = "The program to start: an .exe, or a command found on the PATH (e.g. nxc, roadtx, python)." };
var programArguments = new Argument<string[]>("arguments") { Description = "Arguments for the program. Put -- before the program so its options are not read as proxynator's.", Arity = ArgumentArity.ZeroOrMore };
var run = new Command("run", "Start a program (and everything it starts) with Proxynator's hook, so its connections follow the rules. Needs the injection capture mode. Example: proxynator run -- nxc smb dc01.corp.local") { detachOption, programArgument, programArguments };
run.SetAction((parseResult, _) => new InjectionCommands(parseResult.GetValue(endpointOption)!, Console.Out, Console.Error)
    .RunAsync(parseResult.GetValue(programArgument)!, parseResult.GetValue(programArguments) ?? [], parseResult.GetValue(detachOption)));

var pidArgument = new Argument<int>("pid") { Description = "The process ID." };
var attach = new Command("attach", "Load Proxynator's hook into a running process, so its new connections (and its future child processes) follow the rules. Needs the injection capture mode.") { pidArgument };
attach.SetAction(parseResult => new InjectionCommands(parseResult.GetValue(endpointOption)!, Console.Out, Console.Error).Attach(parseResult.GetValue(pidArgument)));

var root = new RootCommand("proxynator: control the Proxynator service (proxynatord).")
{
    endpointOption, status, config, rules, connections, doctor, run, attach,
};

var parsed = root.Parse(args);

// 'run' leaves Ctrl+C to the started program (it shares the console) and waits for it to exit.
return await parsed.InvokeAsync(parsed.CommandResult.Command == run ? new InvocationConfiguration { ProcessTerminationTimeout = null } : null);
