namespace Proxynator.Client;

/// <summary>What <see cref="ServiceStarter"/> runs, elevated, to start proxynatord.</summary>
/// <param name="FileName">The program.</param>
/// <param name="Arguments">Its arguments.</param>
/// <param name="Description">The command as a user would type it, for messages.</param>
public sealed record ServiceStartPlan(string FileName, IReadOnlyList<string> Arguments, string Description);
