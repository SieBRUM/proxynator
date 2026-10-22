# CLAUDE.md

Guidance for Claude (and other contributors) working in this repository. Read this fully before making changes.

## What Proxynator is

Proxynator forces the network traffic of chosen applications through SOCKS4/4a/5 or HTTP(S) `CONNECT` proxies, typically so the traffic can be analysed in an intercepting proxy such as Burp Suite or mitmproxy. It must work for **applications that ignore proxy settings** and for applications that escape user-mode hooking (the reason why LD_PRELOAD-style tools miss traffic from e.g. Firefox, Go binaries, statically linked binaries, sandboxed child processes, and apps doing their own DNS).

Proxynator only routes traffic. TLS interception, certificates and request inspection belong to the upstream proxy (Burp etc.). Do not build MITM features into Proxynator.

Targets: **Windows first** (10/11, x64), **Linux second** (Ubuntu LTS and Kali rolling, x64 and arm64). Everything is designed so Linux slots in as an additional platform module, not a rewrite.

## Golden rules

1. **Never reference or compare Proxynator to commercial proxy-redirection products by name** — not in code, comments, docs, commit messages, issues or PRs. Describe Proxynator on its own terms.
2. **No platform code in `Proxynator.Core`.** Core is pure .NET and must build and pass its tests on both Windows and Linux. Anything that touches WinDivert, Win32, Detours, eBPF, nftables, `/proc`, etc. lives in a platform project behind a Core interface.
3. **Reliable routing is the priority.** Fail closed and loudly when a rule says *proxy* but the proxy is unreachable (connection is refused/reset, never silently sent direct). Analysis/logging features are secondary.
4. **Never break the host's networking.** Every capture backend must restore normal traffic flow when the service stops or crashes (WinDivert does this automatically when its handle closes; Linux backends must clean up BPF programs / nft tables on shutdown and on next start).
5. **Privilege check at startup.** The service refuses to start without Administrator (elevated token) on Windows or root (or `CAP_NET_ADMIN` + `CAP_BPF`/`CAP_SYS_ADMIN`) on Linux, with a clear message. The CLI and GUI run unprivileged.
6. **No AV evasion.** This is a legitimate tool. Do not obfuscate, pack, or add tricks to avoid detection.
7. Prefer being future-proof over quick hacks: versioned config schema, versioned IPC contract, interfaces at platform seams.

## Architecture

```
┌──────────────┐  ┌──────────────┐
│ proxynator   │  │ proxynator-  │      unprivileged
│ (CLI)        │  │ gui (GUI)    │
└──────┬───────┘  └──────┬───────┘
       │  gRPC over named pipe (Windows) / Unix domain socket (Linux)
┌──────▼─────────────────▼────────────────────────────────────┐
│ proxynatord  (service / daemon, privileged)                 │
│                                                             │
│  Core (platform-agnostic)                                   │
│   Config ─► RuleEngine ─► Relay ─► ProxyChainDialer ─► net  │
│                 ▲           ▲                               │
│                 │           │ OriginalDestinationTable      │
│  Platform module (selected at runtime)                      │
│   Windows: WinDivertCapture | InjectionCapture (Detours)    │
│   Linux:   BpfCapture (eBPF)    | PreloadCapture (LD_PRELOAD)│
└─────────────────────────────────────────────────────────────┘
```

### The central idea: one relay, many capture backends

Every capture backend does the same two things:

1. **Redirect** a matching outbound connection to Proxynator's local relay listener instead of its real destination.
2. **Record** the original destination (+ owning PID, + hostname if known) in the `OriginalDestinationTable`, keyed by the client's local endpoint (address + source port).

The relay accepts the connection, looks up the original destination by the peer endpoint, asks the `RuleEngine` what to do, dials through the selected proxy or chain, and pumps bytes both ways. Proxy protocols, chaining, rule evaluation, DNS handling and connection tracking are therefore written **once**, in Core, and shared by all backends on all platforms.

### Capture backends

The user chooses the capture mode in config (`settings.capture.mode`).

**Windows – `windivert` (default, kernel-level, catches everything)**
- Uses the signed WinDivert 2.2.2 driver (loaded dynamically, unmodified; LGPLv3). `build/WinDivert.targets`
  downloads it (pinned version + SHA-256) and is imported by **executable** projects only (`proxynatord`); the files
  flow to projects that reference it. Struct layouts and constants come from `windivert.h`; keep
  `InteropLayoutTests` passing.
- A sniffing `SOCKET`-layer handle records `connect`/`close` events (PID per local port + remote endpoint). The
  packet thread falls back to `GetExtendedTcpTable` when the event hasn't arrived yet (it is asynchronous).
- A `NETWORK`-layer handle diverts `tcp and ((outbound and !loopback) or (inbound and !loopback and tcp.DstPort ==
  relayPort))`. `ReflectNat` (pure managed code, unit-tested on any OS): on a SYN, `RuleEngine.RequiresRelay`
  decides; redirected client packets `A:pa → B:pb` become `B:pa → A:relay` and are injected *inbound*; relay replies
  `A:relay → B:pa` become `B:pb → A:pa`. The relay therefore sees peer `B:pa`, which is the key registered in the
  `OriginalDestinationTable`. Unmatched flows are reinjected untouched; inbound packets from the network to the relay
  port are dropped. Checksums are recalculated with `WinDivertHelperCalcChecksums`.
- The relay listens dual-mode on `[::]:<ephemeral>` (reflected packets arrive on the client's interface address).
  An inbound Windows Firewall rule "Proxynator relay" is added for that port on start and removed on stop.
- Connections whose owner cannot be determined (no socket event, not in the TCP table) are never redirected: one of
  them could be the relay's own upstream connection, which a catch-all rule would loop back into the relay.
- Always excluded from redirection: the service's own PID (otherwise the relay's upstream connections loop),
  connections to configured proxy endpoints (resolved on every config change) and loopback (`proxyLoopback` is not
  implemented yet and logs a warning).
- UDP is diverted too (`(tcp or udp) and ...`): the same NAT reflects UDP flows to the UDP relay port (a flow starts
  with any datagram). Owners come from SOCKET-layer events or `GetExtendedUdpTable` (by local port). Flows to fake-IP
  addresses and, in `remote` DNS mode, UDP/53 always go to the relays. The DNS client cache is flushed on start and
  stop so no fake answers outlive the service.
- **Timeout invariant:** a NAT entry must expire *before* the relay session it feeds (UDP NAT 60 s / DNS 10 s, checked
  on every lookup; UDP relay sessions 2 min / DNS 15 s). Otherwise a late datagram reaches the relay with neither
  session nor registration and is dropped.
- `block` action: TCP connections are relayed and reset; UDP datagrams are dropped by the UDP relay.

**Windows – `injection` (user-mode, opt-in)** — see ADR 0004
- Native hook DLL in `native/windows/hook` (C++17, Microsoft Detours at a pinned commit via CMake FetchContent,
  static CRT), built for **x64 and x86** (`proxynator-hook64.dll` / `proxynator-hook32.dll`) by
  `build/build-native.ps1` into `artifacts/native/win-x64|win-x86`; `build/NativeArtifacts.targets` (imported by
  `proxynatord`, `proxynator` and `proxynator-gui`) copies them when present. Ordinal 1 must stay `DetourFinishHelperProcess`.
- Hooks are installed only in processes carrying the Detours payload (`payload.h`: pipe path). Elsewhere the DLL only
  serves exports: `ProxynatorCreateProcess` / `ProxynatorAttach` (called by `HookInjector` in the CLI) and
  `ProxynatorAttachRundllW` (32-bit attach via SysWOW64 rundll32).
- Applies to processes started via `proxynator run -- <cmd>` (created suspended, injected, resumed) or attached via
  `proxynator attach <pid>` (remote `LoadLibraryW`), plus their children (`CreateProcessInternalW` hook; the other
  bitness through Detours' rundll32 helper).
- Hooks `connect`, `WSAConnect`, `ConnectEx` (detoured when found via `WSAIoctl` or a start-up lookup),
  `WSAConnectByName*` (reimplemented), `getpeername` (returns the original destination), `closesocket`, the UDP send
  family (`sendto`, `WSASendTo`, `WSASendMsg`), and the resolver family (`getaddrinfo`, `GetAddrInfoW`,
  `GetAddrInfoExW`, `gethostbyname`). A per-thread `ReentrancyGuard` makes only the outermost hook act (Detours
  patches function bodies, so Winsock's internal calls are hooked too).
- Registration protocol (`Core/Hooking/HookProtocol`, mirrored in `native/.../protocol.h` — keep in sync): one pipe
  `<endpoint>.hook` per process. Before connecting, the hook binds unbound sockets to the wildcard address, sends
  `Connect{protocol, local (wildcard reported as loopback), destination, hostname hint}`; `HookRequestHandler`
  registers relayed connections in the same `OriginalDestinationTable` and answers direct / relay(endpoint) / block.
  The PID comes from `GetNamedPipeClientProcessId`, never from the hook.
- Remote DNS is per process here: `Resolve{name}` returns a fake address; the hook calls the real resolver with the
  numeric fake address so Winsock allocates the results. Other lookups become hostname hints
  (`OriginalDestination.HostnameIsHint`), which the relay replaces with a sniffed name when there is one.
- Fails closed: service unreachable → connections refused; hooks not installable → DllMain fails; child not
  hookable → terminated. `PROXYNATOR_HOOK_LOG=<file>` logs from every hooked process (also OutputDebugString).
- Known limitations (document, don't hide): processes with binary-signature mitigation (some browser sandboxes)
  refuse unsigned DLLs; raw syscalls / custom stacks bypass it. Recommend `windivert` mode in those cases.
- UDP in injection mode is `direct` or `block` only (rule `udp` fallback, QUIC blocking) until implemented.

**Linux – `ebpf` (default, kernel-level, machine-wide)** — see ADR 0005
- `native/linux/bpf/proxynator.bpf.c` (clang `-target bpf`, license "Dual MIT/GPL"), loaded by `BpfCaptureBackend`
  through the system libbpf (P/Invoke, `libbpf.so.1` or `.so.0`). Programs on the **root cgroup v2** (found in
  `/proc/self/mountinfo`; `/sys/fs/cgroup` or `/sys/fs/cgroup/unified`) as `bpf_link`s owned by the service: when it
  exits, the kernel detaches them (golden rule 4 for free).
- Only stable UAPI context fields plus two CO-RE `task_struct` fields (`pid`, `tgid`, `preserve_access_index`), so one
  object works on every kernel with BTF. Tracepoints are `tp_btf/*` (no tracefs needed; the classic
  `sched_process_fork` format changed in 6.x, so never parse tracepoint records by offset).
- Process classification lives in the `decisions` map (tgid → flags: TARGET, IGNORE, UDP_BLOCK_QUIC, UDP_BLOCK,
  DNS_REDIRECT), computed in userspace by `ProcessClassifier.Decide` (`RuleEngine.MayRelay`: could any non-direct rule
  apply, judging by process criteria only). Fork copies the parent's value (in BPF, synchronously), exec deletes it
  and notifies the service (ring buffer → `Classify`), exit deletes it. The service classifies all running processes
  at start and after every config change.
- TCP: `cgroup/connect4/6` rewrite candidates' connects to the loopback relay (v4-mapped → `::ffff:127.0.0.1`), store
  the original by socket cookie; `sockops` (`TCP_CONNECT_CB`) re-keys it by local port; the relay finds it through
  `OriginalDestinationTable.ExternalSource` (`BpfCaptureBackend.TryTake`). **Unclassified processes also go to the
  relay** (relay-first), which classifies them on the spot: nothing can slip past before the service knows a process.
- UDP: `connect4/6` + `sendmsg4/6` block (EPERM) or pass per the process flags; no UDP relaying. Remote DNS: UDP/53 of
  candidates (also to the 127.0.0.53 stub) goes to `DnsForwarder` (Core), `recvmsg4/6` rewrites the reply source
  back to the server the program asked. So remote DNS is per process here. Two safety nets (config `flags`,
  `fake_network`/`fake_mask`): in remote mode, DNS of *unclassified* processes goes to the forwarder too (a freshly
  exec'd tool's first lookup can beat its classification), and TCP to the fake range always goes to the relay, even
  from ignored processes (a fake address only means something to the relay).
- Always excluded: the service's tgid, loopback/unspecified destinations, configured proxy endpoints (`excluded`
  map, refreshed on config change).

**Linux – `preload` (user-mode, opt-in)**
- `native/linux/preload/*.c` → `libproxynator-preload.so` (C11, no C++ runtime in target processes). Same
  registration protocol as the Windows hook (`protocol.c` mirrors `HookProtocol.cs`; keep in sync) over the Unix
  socket `<endpoint>.hook` (mode 0666; PID from `SO_PEERCRED`), served by `PreloadCaptureBackend` with the shared
  `HookRequestHandler`/`HookSession`.
- Hooks `connect`, `getpeername`, `close`, `sendto`, `sendmsg`, `sendmmsg`, `getaddrinfo`, `gethostbyname`. Inactive
  unless `PROXYNATOR_HOOK_ENDPOINT` is set; `pthread_atfork` makes children reconnect (the service identifies them by
  peer credentials). `proxynator run` (`PreloadLauncher`) sets `LD_PRELOAD` + the endpoint; children inherit them.
- Escapes (documented): static/Go binaries, raw syscalls, setuid programs and sudo (drop `LD_PRELOAD`). No `attach`.
- `nftables` mode: not implemented (all supported distributions have BPF + BTF); choosing it leaves capture
  `FAILED` with a clear message.

### DNS handling (`settings.dns.mode`, user-selectable)

| Mode | Behaviour | Notes |
|------|-----------|-------|
| `sniff` (default) | App resolves locally; relay peeks TLS SNI / HTTP `Host` from the first bytes and hands the **hostname** to the proxy (SOCKS5 domain / SOCKS4a / `CONNECT host:port`). | Least invasive; upstream sees hostnames; local DNS still happens. |
| `local` | App resolves locally; proxy receives the IP. | Simplest. |
| `remote` | Fake-IP: DNS answers come from a synthetic range (default `198.18.0.0/15`); the relay maps the fake IP back to the hostname and lets the proxy resolve it. | No local DNS leak for proxied apps. |

`remote` mode (Core `NameResolution/`): the capture redirects UDP/53 to the UDP relay, whose DNS sessions answer A
queries for `settings.dns.remoteDomains` (default `*`) from `FakeIpPool` and return empty answers for AAAA/SVCB/HTTPS
(so clients use the fake IPv4 address and get no real IP hints); other queries are forwarded to the real server.
Proxy hostnames, single-label names, `*.localhost` and reverse lookups are never faked (`ActiveConfiguration.ShouldFakeResolve`).
Connections to fake addresses always go to the relays, which use the hostname: proxies get it, direct connections
resolve it with `ModeAwareResolver`, which queries the upstream DNS servers directly (`UpstreamDnsResolver`) while
remote mode is on — the system resolver would return Proxynator's own fake answers.

`settings.dns.remoteServer` (`{ address, port, via }`): in remote mode, queries for remote domains that the fake
responder does not answer (SRV, TXT, MX, ...: domain controller discovery) go to that DNS server as DNS over TCP
through the `via` route (`RemoteDnsClient`, used by the UDP relay's DNS sessions and by `DnsForwarder`). Failure →
SERVFAIL, never the local DNS. A/AAAA stay fake. With `remoteServer.resolveNames`, the TCP relay also resolves
remote-domain names there (`RemoteDnsClient.ResolveAsync`: an A query through the route, cached 60 s) and gives the
proxy the address instead of the name: for pivots that cannot resolve internal names and for plain SOCKS4. Unknown
name → the connection fails (closed). Without it, a name-only target whose route ends in plain `socks4` is refused
with an explanation (never resolved locally: that would give the proxy a fake address or fail), and `doctor` warns
about remote DNS + SOCKS4 routes. These C2/pivot situations are reproduced in `C2SocksScenarioTests` (see ADR 0007).

Gotcha: on Windows most DNS queries are sent by the `Dnscache` service (`svchost.exe`), not by the app, so per-process attribution of DNS packets is impossible in `windivert` mode. `remote` mode in `windivert` is therefore applied system-wide for the listed domains (relay sends non-proxied fake-IP connections direct after real resolution). That includes the service's own process and in-process tests: resolve real addresses before turning remote mode on. In `injection`, `preload` and `ebpf` modes it is per-process (resolver hooks, or the eBPF DNS redirect of candidate processes). Apps using their own DoH just look like ordinary TCP/443 flows and are handled by the rules.

### UDP

- `UdpRelayServer` (Core) mirrors the TCP relay: one session per client flow (keyed by the datagram source, i.e. the
  registration key), idle sessions expire.
- SOCKS5 proxies: UDP via `UDP ASSOCIATE` (`Socks5UdpAssociation`, one association per flow), only when the route is a
  single SOCKS5 hop (UDP cannot be tunnelled through a TCP chain).
- HTTP and SOCKS4 proxies and chains can't carry UDP; the rule's `udp` setting decides `block` (default, fail
  closed) or `direct`.
- `settings.udp.blockQuic` (default `true`) drops UDP/443 for proxied processes so browsers fall back to TCP/TLS, which the proxy can see.

### Rules

- Ordered list, **first match wins**, always ends with a default rule (`direct` unless configured otherwise).
- Match criteria (all optional, AND-ed; lists inside a criterion are OR-ed): process name or full path (wildcards), include child processes, destination host (wildcards, e.g. `*.example.com`), destination IP/CIDR, destination port/range, protocol (tcp/udp).
- Actions: `proxy` (target = proxy id or chain id), `direct`, `block`.
- Different rules can target different proxies, e.g. `test.exe` → SOCKS5 `127.0.0.1:5000` and `test3.exe` → HTTP `127.0.0.1:8080` (Burp).
- Rule evaluation happens once per new connection; changing rules never affects established connections.
- Child-process matching uses `ProcessTree` (Core): processes keyed by (PID, creation time), exited ones remembered
  for 10 minutes, a parent only accepted if it is older than its child (PID reuse). On Windows it is fed by a
  Toolhelp snapshot every 2 s and on every unknown PID, so launcher → `python.exe` chains (pipx tools) still match
  after the launcher exits. On Linux it is fed from `/proc` (`LinuxProcessInfoProvider`); a cached entry is reused
  only while start time and `comm` are unchanged (exec keeps the PID).
- Process patterns also match `ProcessInfo.ScriptPath`, the script an interpreter runs. Linux (`ProcessIdentity`):
  a shebang script is named after the script by the kernel (pipx's `nxc`); `python3 tool.py` and
  `#!/usr/bin/env python3` are named after the interpreter, with the script as `ScriptPath`.

### Proxies and chains

- Types: `socks4`, `socks4a`, `socks5` (no-auth + username/password), `http` (`CONNECT`, optional Basic auth). The `http` type covers HTTPS traffic — that is how Burp is used. `https` (TLS to the proxy itself) is reserved for later; keep the dialer extensible for it.
- Chains: ordered list of proxy ids; the dialer tunnels each hop through the previous one. A rule may target a single proxy or a chain.

### Config

- JSON, camelCase, with a top-level `"version"` field. Migrations live in Core and upgrade older versions on load. Ship a JSON schema in `schema/`.
- Default locations: `%ProgramData%\Proxynator\config.json` (Windows), `/etc/proxynator/config.json` (Linux). Overridable with `--config`.
- Load = parse → migrate → validate → **atomic swap**. Invalid config is rejected entirely; the running config stays active.
- Use `System.Text.Json` source generation (trim/AOT friendly). Strict parsing: unknown properties, `null` for
  non-nullable properties and missing `required` properties are errors; comments and trailing commas are allowed.
- **Gotcha:** config records use `required ... { get; init; }` for mandatory values and `{ get; set; }` for optional
  values with defaults. The source generator overwrites the initializers of *init-only* properties that are missing
  from the JSON with `default`, so optional properties must not be `init`.

### IPC

- gRPC (`Protos/proxynator/v1/control.proto` in `Proxynator.Ipc`), served by Kestrel (HTTP/2) on the named pipe
  `proxynator.v1` on Windows and the Unix socket `/run/proxynator/proxynator.sock` elsewhere. `--endpoint` or the
  `PROXYNATOR_ENDPOINT` environment variable overrides it (tests use a private endpoint each).
- Version the service (`proxynator.v1`). Additive changes only within a version; breaking changes go into `v2`
  served side by side.
- Restrict access: anyone who can talk to the service can redirect traffic. Pipe ACL = SYSTEM + Administrators + the
  account running the service (in console mode that is the user who started it, so their CLI works without
  elevation; as LocalSystem the CLI must run elevated). Unix socket mode `0660`, group `proxynator` when it exists
  (the `.deb` creates it) so its members can use the CLI without sudo.
- Configuration is exchanged as JSON text (the config file format is the single source of truth). `config validate`
  runs locally in the CLI; `ApplyConfig` validates again in the service and can persist the file atomically.

### Service (`proxynatord`) and CLI (`proxynator`)

- Startup: privilege check → load config (missing file = empty rule set; invalid file = refuse to start) → relay →
  capture backend. If the backend cannot start (driver missing, unsupported mode) the service keeps running with
  capture `FAILED`, so `status`/`doctor` can explain why; nothing is redirected in that state.
- `--no-capture` runs the control API and relay without capturing (and without requiring privileges); used for
  development on Linux and in the service tests.
- Saved config: written atomically; a newly created `%ProgramData%\Proxynator` gets an Administrators/SYSTEM-only ACL,
  on Unix the file is `0640`, because it can contain proxy passwords.
- Exit codes: `proxynatord` 1 general, 2 insufficient privileges, 3 invalid configuration; `proxynator` 0 success,
  1 failure, 2 service unreachable.

### GUI (`proxynator-gui`) — see ADR 0006

- Avalonia 12 (Fluent, follows the system theme), MVVM with CommunityToolkit.Mvvm (`[ObservableProperty]` on
  `partial` properties, `[RelayCommand]`). Compiled bindings everywhere (`x:DataType`, also on `DataGrid` columns);
  `ViewLocator` maps page view models to views without reflection. Everything is `internal` (exe).
- An unprivileged client of the same gRPC API as the CLI (`ServiceConnection`: one channel, 10 s deadline per call);
  no GUI-specific RPCs. `--endpoint` / `PROXYNATOR_ENDPOINT` as for the CLI.
- `MainWindowViewModel.TickAsync` runs every 2 s: status (`ServiceState`), then, when the service answers, outside
  config changes (only while nothing is edited) and the visible page's `RefreshAsync`.
- `ConfigWorkspace`: the working copy behind the Rules, Proxies, Settings and JSON pages. Items (`RuleItem`,
  `ProxyItem`, `ChainItem`, `SettingsItem`) hold text as typed; `Build` turns them into a `ProxynatorConfig` with
  `with` on the loaded config (settings without a form survive), `Revalidate` runs `ConfigValidator` on every change
  and words the problems (`Describe`: `$.rules[1].action.target` → `Rule 'x' (action.target): ...`). Values the
  editor cannot convert are reported once, by the editor. `ApplyAsync` sends it with `ApplyConfig`.
- `ConnectionsViewModel`: `WatchConnections` (subscribe, then list; duplicates tolerated), counters refreshed with
  `ListConnections`, reconnects after a service restart, keeps up to 1000 closed rows.
- Launching lives in `Proxynator.Client` (`ProgramLauncher`), shared with `proxynator run|attach`: Windows injection
  (`HookInjector`, batch files through a hooked `cmd.exe`, PowerShell/pwsh as the hooked terminal), Linux preload
  (`PreloadLauncher`; the terminal runs `env LD_PRELOAD=... PROXYNATOR_HOOK_ENDPOINT=... $SHELL`, `LinuxTerminals`
  picks `x-terminal-emulator` first).
- File pickers are behind `IFileDialogs` so view models are testable.
- The unreachable-service banner has **Start proxynatord** (`ServiceStarter` in `Proxynator.Client`, behind
  `IServiceLauncher`): Windows runs the installed service (`sc.exe start`) or `proxynatord.exe` next to the GUI through
  UAC (`runas`); Linux runs `pkexec systemctl start proxynatord` (unit installed) or `pkexec <dir>/proxynatord`. A
  non-default endpoint bypasses the installed service and is passed on. `ServiceStarter.Plan` is pure (tested on any OS).

## Repository layout

```
src/
  Proxynator.Core/                 Platform-agnostic core, by namespace:
    Configuration/                   config model, loader (parse -> migrate -> validate), JSON source-gen
                                     context, ConfigValidator, ActiveConfiguration, ConfigurationStore
    NameResolution/                  DnsWire (minimal DNS format), FakeIpPool, FakeDnsResponder, IHostResolver,
                                     UpstreamDnsResolver, ModeAwareResolver
    Net/                             TargetEndpoint, AddressRange (CIDR), PortRange, ITcpConnector
    Rules/                           RuleEngine (Evaluate, RequiresRelay), compiled rules, wildcard matching
    Processes/                       ProcessInfo, IProcessInfoProvider, ProcessTree (ancestors incl. exited parents)
    Proxies/                         SOCKS4/4a, SOCKS5 (+ UDP ASSOCIATE), HTTP CONNECT clients, ProxyRouteDialer (chains)
    Sniffing/                        HostnameSniffer (TLS SNI, HTTP Host)
    Relay/                           RelayServer (TCP), UdpRelayServer, IOriginalDestinationTable, ConnectionTracker
    Hooking/                         hook registration protocol, HookRequestHandler (decisions), HookSession
    Platform/                        ICaptureBackend, CaptureContext, IPrivilegeChecker
  Proxynator.Platform.Windows/     WindowsPlatformModule, WinDivert interop + capture backend (Capture/,
                                   Interop/, Packets/), InjectionCaptureBackend (hook pipe), Injection/ (HookInjector,
                                   command line quoting, PATH lookup), process info with ancestors, admin check,
                                   firewall rule
  Proxynator.Platform.Linux/       LinuxPlatformModule, BpfCaptureBackend (+ ProcessClassifier, EventCallback),
                                   PreloadCaptureBackend, Preload/PreloadLauncher, Interop/ (libbpf, libc, BpfMap),
                                   /proc process info + ProcessIdentity, capabilities check, cgroup2 discovery
  Proxynator.Ipc/                  .proto contracts, generated client/server, ControlClientFactory, IpcEndpoint
  Proxynator.Service/              proxynatord: ServiceHost (Kestrel on pipe/socket, Windows service, systemd),
                                   ProxynatorEngine, ControlService (gRPC), platform selection
  Proxynator.Client/               shared by CLI and GUI: ProgramLauncher (run/attach/hooked terminal), LinuxTerminals,
                                   ArgumentSplitter, DisplayFormat, ServiceHints, ServiceStarter (elevated start)
  Proxynator.Cli/                  proxynator CLI (System.CommandLine; Commands.cs is testable with captured output;
                                   InjectionCommands.cs: run, attach)
  Proxynator.Gui/                  proxynator-gui (Avalonia): Services/ (ServiceConnection, file dialogs),
                                   ViewModels/ (one per page + ConfigWorkspace and editable items), Views/, Assets/
build/
  WinDivert.targets                pinned WinDivert download + verification, imported by executables
  NativeArtifacts.targets          copies native parts from artifacts/native/<rid>, imported by executables
  build-native.ps1                 builds the hook DLLs (CMake + MSVC, x64 and x86)
  build-native.sh                  builds proxynator.bpf.o and libproxynator-preload.so for this machine's
                                   architecture into artifacts/native/linux-x64|linux-arm64 (clang, libbpf-dev, gcc)
  package-deb.sh                   .deb from a linux-x64/arm64 publish (systemd unit, /etc config, proxynator group,
                                   desktop entry + icon)
  package-tar.sh                   .tar.gz from a linux-x64/arm64 publish (other distributions)
  version.sh                       CI version: <major>.<minor> from Directory.Build.props + run number
native/
  windows/hook/                    C++ Detours hook DLL (x64 + x86)
  linux/preload/                   C LD_PRELOAD library
  linux/bpf/                       eBPF programs (one object)
packaging/linux/                   systemd unit, default /etc/proxynator/config.json, proxynator.desktop
tests/
  Proxynator.Core.Tests/           Pure unit tests, run on both OSes (Support/ has fake proxies, echo server)
  Proxynator.Platform.Windows.Tests/  NAT, packet parsing, interop struct layouts; run on both OSes
  Proxynator.Platform.Linux.Tests/ /proc, mountinfo, capability parsing, process identity, eBPF classification; both OSes
  Proxynator.Service.Tests/        In-process proxynatord + CLI over a real pipe/socket, fake platform module; Client helpers
  Proxynator.Gui.Tests/            GUI view models against the in-process service; the real window on Avalonia's headless
                                   platform ([AvaloniaFact], Skia) incl. screenshots of every page (PROXYNATOR_SCREENSHOTS)
  Proxynator.IntegrationTests/     Real capture in all four modes (curl, python, ...); elevated Windows / root on Linux;
                                   tagged [Trait("Category","Integration")], skipped elsewhere unless
                                   PROXYNATOR_REQUIRE_INTEGRATION=1 (CI), which turns a skip into a failure
schema/                            config JSON schema (keep in sync with the config model)
samples/                           example configs (every samples/*.json is loaded by a test, so they must stay valid);
                                   the guides link to them
docs/                              user documentation (GUI-first; every guide has GUI steps + JSON): README.md (index),
                                   installation, gui, configuration, cli, troubleshooting, building, guides/ (burp,
                                   internal-domain, c2-socks, active-directory, chains, hooking), images/ (GUI
                                   screenshots from the GUI tests), adr/ (design decisions, NNNN-title.md)
.github/workflows/                 CI
```

## Tech stack and conventions

- **.NET 10 (LTS)**, C# latest. `Directory.Build.props` (shared settings) + `Directory.Packages.props` (central package management).
- `<Nullable>enable</Nullable>`, `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`, `<ImplicitUsings>enable</ImplicitUsings>`, analyzers on. `CA1416` (platform compatibility) is an error.
- Platform projects target `net10.0` and mark types with `[SupportedOSPlatform("windows")]` / `[SupportedOSPlatform("linux")]` so the **whole solution builds on both OSes**. The service chooses the platform module at runtime via `OperatingSystem.IsWindows()` / `IsLinux()`.
- Interop: `LibraryImport` (source-generated), `SafeHandle` for native handles, no `DllImport` unless unavoidable. Keep code AOT/trim-compatible (no reflection-based serialization).
- File-scoped namespaces, one public type per file, `async` all the way, `CancellationToken` on every async API, `System.IO.Pipelines`/`Socket` APIs on the hot path, avoid per-packet allocations (`ArrayPool`, `Span<T>`).
- Logging via `Microsoft.Extensions.Logging` (Event Log/file on Windows, journald on Linux). Use structured logging; never log proxy credentials.
- Native code: C++17, CMake, built in CI. Third-party binaries (WinDivert) are downloaded at build time with a pinned
  version and verified SHA-256 (into `.cache/`, git-ignored), not committed.
- Tests: xUnit v3 (`using Xunit` is global). Every proxy protocol client is tested against the in-process fake
  proxy servers in `tests/Proxynator.Core.Tests/Support` (real SOCKS4/4a/5 incl. UDP ASSOCIATE and HTTP CONNECT
  servers on loopback; also TCP/UDP echo servers and a scriptable UDP DNS server). `UdpRelayServer.DnsPort` is
  internal so tests can treat a non-privileged port as DNS.
  Network tests take a `TestTimeout.Token()` so they can never hang. The rule engine, validator and sniffer get
  table-driven tests. Relay tests simulate a capture backend: bind the client socket, register it in the
  `OriginalDestinationTable`, connect to the relay.
- Architecture decisions that change any of the above get an ADR in `docs/adr/`.
- Commits: imperative mood, focused. Keep `README.md`, `docs/` and this file up to date when behaviour or layout
  changes. The README is a short front page; details go into `docs/`. Guides lead with the GUI and show the same
  setup as JSON. `DocumentationTests` validates every complete JSON configuration in the README and `docs/` and
  every relative link and `#anchor`, so examples and links can't rot.

## Build, test, run

Requires the .NET 10 SDK (`global.json` pins the 10.0 feature band, rolling forward).

```
./build/build-native.ps1                               # Windows: hook DLLs (CMake + VS C++ workload); optional
./build/build-native.sh                                # Linux: eBPF object + preload library; optional
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
dotnet test tests/Proxynator.IntegrationTests          # elevated Windows (internet) or root on Linux
```

The native sources can be syntax-checked on Linux with MinGW (`x86_64-w64-mingw32-g++` / `i686-w64-mingw32-g++
-std=c++17 -fsyntax-only -I<detours>/src ...`); the real build is MSVC in CI.

Run locally (elevated on Windows, root on Linux; `--no-capture` runs without privileges or capture):

```
dotnet run --project src/Proxynator.Service -- --config ./samples/config.json --verbose
dotnet run --project src/Proxynator.Cli -- status
dotnet run --project src/Proxynator.Gui                # unprivileged; --endpoint <pipe|socket> for a test service
```

Set `AVALONIA_TELEMETRY_OPTOUT=1` when building: Avalonia's build otherwise sends anonymous usage statistics (CI sets
it). On Linux without a display, `xvfb-run -a dotnet run --project src/Proxynator.Gui` starts the real app.

On Linux, `-p:IncludeWinDivert=true` forces the WinDivert download (e.g. to check `build/WinDivert.targets`). A
Windows publish (`dotnet publish src/Proxynator.Service -c Release -r win-x64 --self-contained`) can be produced from
Linux too.

CI (`.github/workflows/ci.yml`) builds and unit-tests in Release on three platforms: `win-x64` (`windows-latest`),
`linux-x64` (`ubuntu-latest`) and `linux-arm64` (`ubuntu-24.04-arm`). Windows: builds the hook DLLs (x64 + x86) first,
runs the WinDivert and injection integration tests (elevated) and packages a self-contained `.zip` (service, CLI,
GUI, WinDivert, hook DLLs). Linux: builds the eBPF object and preload library for the runner's architecture first,
packages a `.deb` and a `.tar.gz`, then runs the eBPF and preload integration tests with sudo (after the other build
steps, so no root-owned files affect them). Tests for the other OS skip; on the right OS a skip is a failure in CI.
Every platform uploads `packages-<rid>`, `gui-screenshots-<rid>` and `test-results-<rid>`. The `release` job runs
only for pushes to `main`, after all platforms passed: it publishes the packages and `SHA256SUMS` as GitHub release
`v<major>.<minor>.<run number>` (`build/version.sh`; bump major/minor in `Directory.Build.props`). Not built:
Windows arm64 (no WinDivert driver, x64/x86 hook DLLs) and macOS (no capture backend).

This container-style environment can run the Linux integration tests too (root, BPF, cgroup v2): `sudo dotnet test
tests/Proxynator.IntegrationTests --filter FullyQualifiedName~LinuxCaptureTests` after `build/build-native.sh`.

Before pushing: build with zero warnings (warnings are errors) and run the unit tests. Network tests run in
parallel, so run the suite a few times when touching the relay or proxy code to catch races. Code that only runs on
Windows (WinDivert, Win32) is only exercised by CI's Windows job; check it after pushing.

### Gotchas

- `CA1416` does not see `OperatingSystem.IsWindows()` checks from inside lambdas: hoist the platform-specific call
  into a method attributed `[SupportedOSPlatform]`/`[UnsupportedOSPlatform]` and call it under the check.
- When a server resets a connection immediately, the client's `ConnectAsync` can itself fail with
  `ConnectionReset` on Linux. Tests that expect a reset must accept that (see `IsRejectedByRelayAsync`).
- WinDivert SOCKET/FLOW addresses are four host-order 32-bit words, most significant word last, IPv4 as
  `::ffff:a.b.c.d` (`AddressWords`).
- `pkill -f <pattern>` in a shell whose own command line contains the pattern kills that shell; use PID files.
- Windows-only behaviour that unit tests can't reach (real driver, Dnscache, firewall, process launch chains) is
  covered by `tests/Proxynator.IntegrationTests`: curl.exe (TCP, SNI/Host sniffing, block, fail-closed, remote DNS
  proxied and direct), nslookup.exe (UDP through SOCKS5) and a venv's pip.exe (pipx-style launcher chain); for
  injection: 64/32-bit curl, cmd.exe children across bitness, fail-closed without service, per-process remote DNS,
  pwsh (.NET ConnectEx), pip, attach to 64-bit python and 32-bit Windows PowerShell. The hook log is printed.
- LDAP tests use curl's `ldap://` (WinLDAP / OpenLDAP) against `FakeLdapServer`, reached through the fake proxy at a
  TEST-NET address (203.0.113.10) that only exists for the proxy's `Resolve`, so no internet is needed; SRV tests use
  `FakeTcpDnsServer` as the domain controller's DNS (`nslookup -type=SRV`).
- Integration tests never run in parallel (`DisableTestParallelization`): capture affects the machine or the started
  processes.
- `cmd.exe` does not parse its command line like the C runtime: build `cmd /d /s /c "..."` lines by hand, don't
  pass them through `WindowsCommandLine.Join`.
- eBPF mode: a program's `getpeername` (curl's `remote_ip`) shows the relay, because the kernel rewrote the
  destination; don't assert on it.
- Types in `Proxynator.Platform.Linux` are `[SupportedOSPlatform("linux")]` per type, not per assembly; keep pure
  logic (parsers, `ProcessClassifier`, `Capabilities`) unattributed so its tests also build and run on Windows.
- Avalonia: `TextBox.Watermark` is obsolete (use `PlaceholderText`); a binding on an element whose `DataContext` is
  itself bound (`DataContext="{Binding SelectedRule}"`) resolves against the new context, so put `IsVisible` on a
  parent; `IsVisible="{Binding !!Items.Count}"` turns a count into a bool. Button `Classes="accent"` takes the Fluent
  palette's accent (set in `App.axaml`).
- GUI tests run on Avalonia's dispatcher (`[AvaloniaFact]`); awaiting gRPC calls there is fine. Wait for view-model
  state with `Wait.UntilAsync`, never with blocking waits.
- Pure logic about the *other* OS (Linux paths in `LinuxTerminals`/`ServiceStarter`, tested on Windows too) must not use
  `Path.Combine`: it joins with this process's separator. Join with the target OS's separator explicitly.
- Linux `open(2)` flags differ per architecture (x86's `O_DIRECTORY` is arm64's `O_DIRECT`): use `OpenFlags`, never
  hard-coded x86 values. CI's `linux-arm64` job catches such mistakes.
- The BPF `config` struct, `origin` and `endpoint_key` layouts are mirrored in `BpfCaptureBackend`; ports are network
  byte order, `sockops` local ports host order.

## Roadmap

- [x] Phase 0 — `README.md`, `CLAUDE.md`, license.
- [x] Phase 1 — Solution scaffold, CI, Core: config model + schema + validation, rule engine, SOCKS4/4a/5 + HTTP CONNECT clients with auth, chain dialer, relay with hostname sniffing, `OriginalDestinationTable`. Fully unit-tested on both OSes.
- [x] Phase 2 — Windows `windivert` TCP capture, PID attribution, exclusions, privilege check, `proxynatord` (console + Windows service), gRPC IPC, basic CLI (`status`, `config load|validate`, `rules list`, `connections`, `doctor`).
- [x] Phase 3 — DNS modes (`sniff`, `remote` fake-IP), UDP capture + relay via SOCKS5, QUIC blocking, child-process matching with process history.
- [x] Phase 4 — Windows `injection` mode (Detours hook DLL x64/x86, `run`, `attach`, child propagation, per-process remote DNS).
- [x] Phase 5 — Linux: `ebpf` capture, `preload` mode, systemd unit, `.deb` packaging for Ubuntu/Kali. (`nftables`
  fallback not implemented: every supported distribution has BPF and BTF.)
- [x] Phase 6 — Avalonia GUI (`proxynator-gui`): overview, live connections, rule/proxy/chain/settings editors on a
  validated working copy, JSON, launching hooked programs and terminals, attach (Windows), diagnostics.
- [x] Releases — every push to `main` publishes tested packages for Windows x64, Linux x64 and Linux arm64.
- [x] 1.0 — C2/pivot DNS handling (`remoteServer.resolveNames`, SOCKS4 refusal, scenario tests), start the service
  from the GUI, user documentation in `docs/`.
- [ ] Later — connection log export, pcap output, statistics, `https` (TLS-to-proxy) hops, Windows ARM64 (WinDivert has no ARM64 build; would need ARM64 hook DLLs).
