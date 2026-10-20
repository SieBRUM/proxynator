namespace Proxynator.Core.Platform;

/// <summary>Whether the current process has the privileges the service needs.</summary>
/// <param name="IsSufficient">Whether the service may start.</param>
/// <param name="Description">What was found, or what is missing and how to fix it.</param>
public sealed record PrivilegeCheckResult(bool IsSufficient, string Description);
