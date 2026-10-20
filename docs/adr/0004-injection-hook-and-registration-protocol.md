# ADR 0004: Injection hook DLL and the hook registration protocol

- Status: accepted
- Date: 2026-10-20

## Context

Phase 4 adds the Windows `injection` capture mode: only programs started with `proxynator run` (or attached with
`proxynator attach`) and their children are captured, without a driver and without touching the rest of the
machine. It must reuse the relay, rules and DNS logic like the WinDivert backend (ADR 0001), and its design should
carry over to the Linux `preload` mode.

## Decision

- **A native hook DLL** (`native/windows/hook`, C++17, Microsoft Detours at a pinned commit, static CRT) is built for
  x64 and x86 (`proxynator-hook64.dll`, `proxynator-hook32.dll`) by CMake and copied next to the executables
  (`build/NativeHook.targets`). Hooks are only installed in processes that carry a Detours **payload** (pipe path);
  the CLI loads the same DLL just for its exports, and rundll32 helpers load it for Detours' ordinal 1.
- **Registration protocol** (`Core/Hooking`, mirrored in `protocol.h`): length-prefixed binary frames over one
  stream per process (named pipe `<endpoint>.hook` on Windows; a Unix socket for Linux later). Requests: Hello,
  Connect (TCP/UDP, local endpoint, original destination, hostname hint), Resolve (name). The service decides with
  `HookRequestHandler`, which applies the same rules as the kernel backends; the transport supplies the caller's PID
  (`GetNamedPipeClientProcessId`), never the hook.
- **TCP:** the hook binds unbound sockets to the wildcard address (a "direct" answer still works), reports
  `loopback:port` as the key, and connects to the relay endpoint of the socket's family if told so. `connect`,
  `WSAConnect`, `ConnectEx` (detoured once found via `WSAIoctl` or a start-up lookup) and `WSAConnectByName*`
  (reimplemented on the hooked paths) are covered. `getpeername` returns the original destination.
- **UDP** sends (`sendto`, `WSASendTo`, `WSASendMsg`, UDP `connect`) are checked and cached briefly; the answer is only
  direct or block (rule `udp` fallback, QUIC blocking). Relaying UDP would also require rewriting receive paths.
- **DNS:** resolver hooks (`getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExW`, `gethostbyname`) ask the service in
  remote mode and produce fake answers by calling the real resolver with the numeric fake address, so results are
  allocated (and freed) by Winsock. Otherwise results are remembered as hostname hints. Hints are marked
  (`OriginalDestination.HostnameIsHint`): the relay still sniffs and prefers a sniffed name.
- **Children** are hooked in `CreateProcessInternalW` (all CreateProcess variants end there): created suspended,
  `DetourUpdateProcessWithDll` for the same bitness, Detours' rundll32 helper for the other, then resumed.
- **Fail closed everywhere:** unreachable service → connects refused, UDP blocked; hooks that cannot be installed →
  DllMain fails (the process does not start, or attach fails); a child that cannot be hooked is terminated. Only
  name resolution falls back to normal behaviour.
- **Launch and attach** run in the unprivileged CLI (`HookInjector` in `Platform.Windows`, calling the x64 DLL's
  exports): `run` starts the program suspended with inherited console handles; `attach` uses a remote `LoadLibraryW`
  thread, through a 32-bit rundll32 for 32-bit targets.

## Consequences

- Injection mode needs no driver, firewall rule or DNS cache changes; stopping the service affects only hooked
  programs, which then refuse connections.
- Programs that bypass Winsock (raw syscalls, own stacks) or refuse unsigned DLLs (signature mitigation) are not
  captured or fail to start; `windivert` mode remains the default.
- The hook pipe is open to authenticated users and AppContainers (hooked programs run as any user); it is created with
  `FirstPipeInstance`, the hook only accepts loopback relay endpoints and connects with `SECURITY_IDENTIFICATION`.
- The Linux `preload` library can implement the same protocol; `HookRequestHandler` and `HookSession` are shared.
