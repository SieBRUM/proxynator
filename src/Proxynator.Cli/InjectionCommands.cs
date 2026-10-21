using Proxynator.Client;

namespace Proxynator.Cli;

/// <summary>
/// <c>proxynator run</c> and <c>proxynator attach</c>: user-mode capture of chosen processes (Windows injection mode,
/// Linux preload mode).
/// </summary>
internal sealed class InjectionCommands(string endpoint, TextWriter output, TextWriter error)
{
    /// <summary>Starts <paramref name="command"/> with the hook and, unless <paramref name="detach"/>, waits for it and returns its exit code.</summary>
    public async Task<int> RunAsync(string command, IReadOnlyList<string> arguments, bool detach)
    {
        LaunchedProgram program;
        try
        {
            program = new ProgramLauncher(endpoint).Start(command, arguments);
        }
        catch (LaunchException ex)
        {
            error.WriteLine(ex.Message);
            return ex.ServiceUnavailable ? ExitCodes.ServiceUnreachable : ExitCodes.Failure;
        }

        using (program)
        {
            error.WriteLine($"proxynator: started {program.Name} (pid {program.ProcessId}); its connections follow the proxynatord rules.");
            if (detach)
            {
                return ExitCodes.Success;
            }

            // Ctrl+C reaches the child through the shared console (Windows) or the terminal's process group (Linux);
            // keep waiting so its exit code is returned.
            ConsoleCancelEventHandler ignore = (_, e) => e.Cancel = true;
            Console.CancelKeyPress += ignore;
            try
            {
                return await program.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                Console.CancelKeyPress -= ignore;
            }
        }
    }

    /// <summary>Loads the hook DLL into the running process <paramref name="processId"/>.</summary>
    public int Attach(int processId)
    {
        try
        {
            new ProgramLauncher(endpoint).Attach(processId);
        }
        catch (LaunchException ex)
        {
            error.WriteLine(ex.Message);
            return ex.ServiceUnavailable ? ExitCodes.ServiceUnreachable : ExitCodes.Failure;
        }

        output.WriteLine($"Hook loaded into process {processId}. Its new connections, and those of processes it starts, follow the proxynatord rules; open connections are not affected.");
        return ExitCodes.Success;
    }
}
