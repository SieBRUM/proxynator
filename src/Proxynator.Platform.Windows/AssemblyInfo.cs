using System.Runtime.InteropServices;

// WinDivert.dll ships next to the application; system libraries come from System32 only.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
