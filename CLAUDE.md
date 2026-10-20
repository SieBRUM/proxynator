# CLAUDE.md

Guidance for Claude (and other contributors) working in this repository. Read this fully before making changes.

## What Proxynator is

Proxynator forces the network traffic of chosen applications through SOCKS4/4a/5 or HTTP(S) `CONNECT` proxies, typically so the traffic can be analysed in an intercepting proxy such as Burp Suite or mitmproxy. It must work for **applications that ignore proxy settings** and for applications that escape user-mode hooking (the reason why LD_PRELOAD-style tools miss traffic from e.g. Firefox, Go binaries, statically linked binaries, sandboxed child processes, and apps doing their own DNS).

Proxynator only routes traffic. TLS interception, certificates and request inspection belong to the upstream proxy (Burp etc.). Do not build MITM features into Proxynator.

Targets: **Windows first** (10/11, x64), **Linux second** (Ubuntu LTS and Kali rolling, x64). Everything is designed so Linux slots in as an additional platform module, not a rewrite.

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
│ proxynator   │  │ GUI (later,  │      unprivileged
│ (CLI)        │  │ Avalonia)    │
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
│   Linux:   BpfCapture / NftCapture | PreloadCapture (later) │
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
- Uses the signed WinDivert driver (loaded dynamically, unmodified; LGPLv3).
- `SOCKET`/`FLOW` layer (sniff mode) supplies PID ↔ flow mapping at `connect()` time; fall back to `GetExtendedTcpTable`/`GetExtendedUdpTable` by local port if the event hasn't arrived yet.
- `NETWORK` layer rewrites outbound TCP SYNs of flows whose rule action is not `direct` into the local relay (NAT-style "reflect" technique, as in WinDivert's `streamdump` sample) and rewrites the replies back. Unmatched flows are reinjected untouched.
- Always excluded from redirection: the service's own PID (otherwise the relay's upstream connections loop), connections to configured proxy endpoints, and loopback unless explicitly enabled.
- `block` action: drop + RST (TCP) / drop (UDP).

**Windows – `injection` (user-mode, opt-in)**
- Native hook DLL in `native/windows/hook` (C++, Microsoft Detours), built for **x64 and x86** so 32-bit targets work.
- Applies to processes started via `proxynator run -- <cmd>` (created suspended, injected, resumed) or attached via `proxynator attach <pid>`, plus their children (`CreateProcessW` / `CreateProcessAsUserW` hooks propagate injection).
- Hooks `connect`, `WSAConnect`, `ConnectEx`, `WSAConnectByName*`, and the resolver family (`getaddrinfo`, `GetAddrInfoW`, `GetAddrInfoExW`, `gethostbyname`).
- Registration protocol: before connecting, the hook binds the socket (if unbound), sends `{pid, localEndpoint, originalDestination, hostname?}` to the service over a named pipe, then connects to the relay. This feeds the same `OriginalDestinationTable` as WinDivert, so the relay doesn't care which backend is active.
- Known limitations (document, don't hide): processes with binary-signature mitigation (some browser sandboxes) refuse unsigned DLLs; raw syscalls / custom stacks bypass it. Recommend `windivert` mode in those cases.
- TCP first; UDP in injection mode is `direct` or `block` only until implemented.

**Linux (later)**
- `ebpf` (default): `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4/6` programs on the root cgroup rewrite the destination to the relay and store the original in a BPF map. Target PIDs/cgroups are pushed into a BPF map by the service, tracking process exec events. BPF C sources in `native/linux/bpf`, loaded via libbpf (P/Invoke).
- `nftables` fallback: move matched processes into a Proxynator cgroup, `socket cgroupv2` match + `redirect`/`tproxy`, original destination via `SO_ORIGINAL_DST`.
- `preload` (opt-in, the Linux equivalent of `injection`): `LD_PRELOAD` shared object in `native/linux/preload`, same registration protocol over a Unix domain socket.

### DNS handling (`settings.dns.mode`, user-selectable)

| Mode | Behaviour | Notes |
|------|-----------|-------|
| `sniff` (default) | App resolves locally; relay peeks TLS SNI / HTTP `Host` from the first bytes and hands the **hostname** to the proxy (SOCKS5 domain / SOCKS4a / `CONNECT host:port`). | Least invasive; upstream sees hostnames; local DNS still happens. |
| `local` | App resolves locally; proxy receives the IP. | Simplest. |
| `remote` | Fake-IP: DNS answers come from a synthetic range (default `198.18.0.0/15`); the relay maps the fake IP back to the hostname and lets the proxy resolve it. | No local DNS leak for proxied apps. |

Gotcha: on Windows most DNS queries are sent by the `Dnscache` service (`svchost.exe`), not by the app, so per-process attribution of DNS packets is impossible in `windivert` mode. `remote` mode in `windivert` is therefore applied system-wide (relay sends non-proxied fake-IP connections direct after real resolution). In `injection`/`preload` mode the resolver hooks make it per-process. Apps using their own DoH just look like ordinary TCP/443 flows and are handled by the rules.

### UDP

- SOCKS5 proxies: UDP via `UDP ASSOCIATE` (one association per flow/process).
- HTTP and SOCKS4 proxies can't carry UDP; the rule's `udp` setting decides `block` or `direct`.
- `settings.udp.blockQuic` (default `true`) drops UDP/443 for proxied processes so browsers fall back to TCP/TLS, which the proxy can see.

### Rules

- Ordered list, **first match wins**, always ends with a default rule (`direct` unless configured otherwise).
- Match criteria (all optional, AND-ed; lists inside a criterion are OR-ed): process name or full path (wildcards), include child processes, destination host (wildcards, e.g. `*.example.com`), destination IP/CIDR, destination port/range, protocol (tcp/udp).
- Actions: `proxy` (target = proxy id or chain id), `direct`, `block`.
- Different rules can target different proxies, e.g. `test.exe` → SOCKS5 `127.0.0.1:5000` and `test3.exe` → HTTP `127.0.0.1:8080` (Burp).
- Rule evaluation happens once per new connection; changing rules never affects established connections.
- Child-process matching needs a parent-PID tracker (ETW process events on Windows, proc connector/BPF on Linux). Guard against PID reuse by also tracking process start time.

### Proxies and chains

- Types: `socks4`, `socks4a`, `socks5` (no-auth + username/password), `http` (`CONNECT`, optional Basic auth). The `http` type covers HTTPS traffic — that is how Burp is used. `https` (TLS to the proxy itself) is reserved for later; keep the dialer extensible for it.
- Chains: ordered list of proxy ids; the dialer tunnels each hop through the previous one. A rule may target a single proxy or a chain.

### Config

- JSON, camelCase, with a top-level `"version"` field. Migrations live in Core and upgrade older versions on load. Ship a JSON schema in `schema/`.
- Default locations: `%ProgramData%\Proxynator\config.json` (Windows), `/etc/proxynator/config.json` (Linux). Overridable with `--config`.
- Load = parse → migrate → validate → **atomic swap**. Invalid config is rejected entirely; the running config stays active.
- Use `System.Text.Json` source generation (trim/AOT friendly).

### IPC

- gRPC (`.proto` contracts in `Proxynator.Ipc`), over a named pipe on Windows and a Unix domain socket on Linux.
- Version the service (`proxynator.v1`). Additive changes only within a version.
- Restrict access: pipe ACL = Administrators + SYSTEM (+ optional configured group); socket `0660` owned by `root:proxynator`. Anyone who can talk to the service can redirect traffic.

## Repository layout (target)

```
src/
  Proxynator.Core/                 Config, migrations, validation, RuleEngine, proxy clients,
                                   chain dialer, Relay, DNS (sniff/fake-IP), connection tracking,
                                   platform abstractions (ICaptureBackend, IProcessInfoProvider,
                                   IPrivilegeChecker, IOriginalDestinationTable, ...)
  Proxynator.Platform.Windows/     WinDivert P/Invoke + capture, injection controller,
                                   process tracking, admin check, Windows service glue
  Proxynator.Platform.Linux/       (later) eBPF/nftables capture, preload controller, root check
  Proxynator.Ipc/                  .proto contracts, generated client/server, transport helpers
  Proxynator.Service/              proxynatord host: DI wiring, platform selection, service/systemd
  Proxynator.Cli/                  proxynator CLI (thin IPC client)
  Proxynator.Gui/                  (later) Avalonia GUI (thin IPC client)
native/
  windows/hook/                    C++ Detours hook DLL (x64 + x86)
  linux/preload/                   (later) LD_PRELOAD .so
  linux/bpf/                       (later) eBPF programs
tests/
  Proxynator.Core.Tests/           Pure unit tests, run on both OSes
  Proxynator.Platform.Windows.Tests/
  Proxynator.IntegrationTests/     Need admin/root; tagged [Trait("Category","Integration")]
schema/                            config JSON schema
docs/                              design notes, ADRs (docs/adr/NNNN-title.md)
.github/workflows/                 CI
```

## Tech stack and conventions

- **.NET 10 (LTS)**, C# latest. `Directory.Build.props` (shared settings) + `Directory.Packages.props` (central package management).
- `<Nullable>enable</Nullable>`, `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`, `<ImplicitUsings>enable</ImplicitUsings>`, analyzers on. `CA1416` (platform compatibility) is an error.
- Platform projects target `net10.0` and mark types with `[SupportedOSPlatform("windows")]` / `[SupportedOSPlatform("linux")]` so the **whole solution builds on both OSes**. The service chooses the platform module at runtime via `OperatingSystem.IsWindows()` / `IsLinux()`.
- Interop: `LibraryImport` (source-generated), `SafeHandle` for native handles, no `DllImport` unless unavoidable. Keep code AOT/trim-compatible (no reflection-based serialization).
- File-scoped namespaces, one public type per file, `async` all the way, `CancellationToken` on every async API, `System.IO.Pipelines`/`Socket` APIs on the hot path, avoid per-packet allocations (`ArrayPool`, `Span<T>`).
- Logging via `Microsoft.Extensions.Logging` (Event Log/file on Windows, journald on Linux). Use structured logging; never log proxy credentials.
- Native code: C++17, CMake, built in CI. Third-party binaries (WinDivert) are downloaded at build time with a pinned version and verified SHA-256, not committed.
- Tests: xUnit. Every proxy protocol client is tested against an in-process fake proxy server. The rule engine and config migration get table-driven tests.
- Architecture decisions that change any of the above get an ADR in `docs/adr/`.
- Commits: imperative mood, focused. Keep `README.md` and this file up to date when behaviour or layout changes.

## Build, test, run

> The solution does not exist yet. Update these commands when it lands.

```
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
dotnet test Proxynator.sln --filter "Category=Integration"   # elevated shell / root only
dotnet run --project src/Proxynator.Service -- --console --config ./samples/config.json
dotnet run --project src/Proxynator.Cli -- status
```

CI (GitHub Actions) builds and unit-tests on `windows-latest` and `ubuntu-latest`, builds the native hook DLL (x64 + x86) on Windows, and runs integration tests on Windows runners (which run as Administrator).

## Roadmap

- [x] Phase 0 — `README.md`, `CLAUDE.md`, license.
- [ ] Phase 1 — Solution scaffold, CI, Core: config model + schema + validation, rule engine, SOCKS4/4a/5 + HTTP CONNECT clients with auth, chain dialer, relay, `OriginalDestinationTable`. Fully unit-tested on both OSes.
- [ ] Phase 2 — Windows `windivert` TCP capture, PID attribution, exclusions, privilege check, `proxynatord` (console + Windows service), gRPC IPC, basic CLI (`status`, `config load|validate`, `rules list`, `connections`, `doctor`).
- [ ] Phase 3 — DNS modes (`sniff`, `remote`), UDP via SOCKS5, QUIC blocking, child-process matching.
- [ ] Phase 4 — Windows `injection` mode (Detours hook DLL x64/x86, `run`, `attach`, child propagation).
- [ ] Phase 5 — Linux: `ebpf` + `nftables` capture, `preload` mode, systemd unit, `.deb` packaging for Ubuntu/Kali.
- [ ] Phase 6 — Avalonia GUI.
- [ ] Later — connection log export, pcap output, statistics, `https` (TLS-to-proxy) hops, ARM64 (Linux first; WinDivert has no ARM64 build).
