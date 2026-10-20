namespace Proxynator.Core.Platform;

/// <summary>The result of one diagnostic check (shown by <c>proxynator doctor</c>).</summary>
/// <param name="Name">Short name of the check.</param>
/// <param name="Status">The outcome.</param>
/// <param name="Detail">What was found and, for problems, how to fix them.</param>
public sealed record DiagnosticResult(string Name, DiagnosticStatus Status, string Detail);
