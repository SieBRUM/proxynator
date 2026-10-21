using Proxynator.Ipc.V1;

namespace Proxynator.Gui.ViewModels;

/// <summary>One health check result.</summary>
internal sealed record DiagnosticItem(string Name, DiagnosticStatus Status, string Detail)
{
    public string Label => Status switch
    {
        DiagnosticStatus.Ok => "OK",
        DiagnosticStatus.Warning => "WARN",
        _ => "FAIL",
    };

    public bool IsOk => Status == DiagnosticStatus.Ok;

    public bool IsWarning => Status == DiagnosticStatus.Warning;

    public bool IsError => Status is not DiagnosticStatus.Ok and not DiagnosticStatus.Warning;
}
