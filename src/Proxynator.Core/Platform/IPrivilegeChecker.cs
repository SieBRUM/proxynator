namespace Proxynator.Core.Platform;

/// <summary>Checks for Administrator (Windows) or root / required capabilities (Linux).</summary>
public interface IPrivilegeChecker
{
    /// <summary>Performs the check.</summary>
    PrivilegeCheckResult Check();
}
