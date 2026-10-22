# Building

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download). Set `AVALONIA_TELEMETRY_OPTOUT=1`: the GUI
framework's build otherwise sends anonymous usage statistics.

```
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
```

Building on Windows downloads the pinned WinDivert release (SHA-256 verified) next to `proxynatord`.

## Native parts

The capture modes' native parts are built first; the .NET build copies them next to the executables. Without them
everything still builds, and only the modes that need them report what's missing.

```
./build/build-native.ps1    # Windows: the hook DLLs (CMake and Visual Studio's "Desktop development with C++")
./build/build-native.sh     # Linux: the eBPF object and the preload library (sudo apt install clang llvm libbpf-dev gcc)
```

`build-native.sh` builds for the machine's architecture (x64 or arm64).

## Packages

```
dotnet publish src/Proxynator.Service -c Release -r win-x64 --self-contained -o out
dotnet publish src/Proxynator.Cli -c Release -r win-x64 --self-contained -o out
dotnet publish src/Proxynator.Gui -c Release -r win-x64 --self-contained -o out

dotnet publish src/Proxynator.Service -c Release -r linux-x64 --self-contained -o out
dotnet publish src/Proxynator.Cli -c Release -r linux-x64 --self-contained -o out
dotnet publish src/Proxynator.Gui -c Release -r linux-x64 --self-contained -o out
./build/package-deb.sh out 1.0.0             # .deb for this machine's architecture
./build/package-tar.sh out 1.0.0 linux-x64   # .tar.gz
```

Use `linux-arm64` on an arm64 machine.

## Tests

- **Unit tests** run anywhere. They cover the proxy protocols against real in-process SOCKS and HTTP servers, the
  rules, DNS, the relay including the [C2 SOCKS scenarios](guides/c2-socks.md), the service and CLI over a real
  pipe/socket, and the GUI's view models. They also render every GUI page headlessly, saving screenshots under
  `tests/Proxynator.Gui.Tests/bin/.../screenshots`.
- **Integration tests** push real traffic (curl, nslookup, PowerShell, Python, LDAP clients) through the real capture
  modes. They need an elevated prompt on Windows and root on Linux:
  `dotnet test tests/Proxynator.IntegrationTests`.

## Continuous integration and releases

Every push is built and tested on Windows x64, Linux x64 and Linux arm64, including the integration tests, and every
run produces the packages (`packages-<platform>` artifacts). A push to `main` that passes on every platform is
published as release `v<major>.<minor>.<run number>`, with `SHA256SUMS`. Major and minor come from
`Directory.Build.props`.

Architecture, conventions and design rules are in [`CLAUDE.md`](../CLAUDE.md); design decisions in [`adr/`](adr).
