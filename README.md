# Proxynator

**Force any application's traffic through a SOCKS or HTTP proxy, whether it supports proxies or not.**

Proxynator is an open-source, rule-based traffic redirector for Windows (and, later, Linux). It captures the outbound connections of the applications you choose and sends them through SOCKS4, SOCKS4a, SOCKS5 or HTTP `CONNECT` proxies. Proxy chains are supported too. Its main use is analysis: point a stubborn desktop app, CLI tool or game at Burp Suite, mitmproxy or a SOCKS pivot, even when that app has no proxy setting or ignores it.

> **Status: early development.** On Windows, TCP and UDP traffic can be captured and routed machine-wide
> (kernel-level `windivert` mode) or for the programs you start with `proxynator run` (`injection` mode), including
> fake-IP DNS for resolving internal names through a pivot, controlled with the `proxynator` CLI. Linux and the GUI
> are still to come. See [known limitations](#known-limitations) and the [roadmap](#roadmap).

## Why another proxy tool?

User-mode tricks (setting `HTTP_PROXY`, `LD_PRELOAD`/DLL hooking of `connect()`) only work for apps that cooperate. Apps that use their own network stack, their own DNS (DoH), static binaries, raw syscalls or sandboxed helper processes slip past them.

Proxynator's default mode captures traffic **at the kernel network layer** and transparently redirects it to a local relay. The application never knows a proxy is involved, so it doesn't matter whether it respects proxy settings.

## Features

✅ = available now, the rest is planned.

- ✅ **Per-application rules:** match by process name/path (wildcards), child processes, destination host/IP/CIDR, port and protocol. First match wins.
- ✅ **Different proxies per rule:** for example `test.exe` → SOCKS5 `127.0.0.1:5000`, and `test3.exe` → Burp at `127.0.0.1:8080`.
- ✅ **Proxy types:** SOCKS4, SOCKS4a, SOCKS5 (with username/password), HTTP `CONNECT` (with Basic auth). The HTTP type covers HTTPS traffic, so it works with Burp, mitmproxy and similar tools.
- ✅ **Proxy chains:** route through several proxies in sequence (A → B → C).
- ✅ **Actions:** `proxy`, `direct` or `block`.
- **Two capture modes on Windows**, chosen by the user:
  - ✅ `windivert` (default): kernel-level capture through the signed WinDivert driver. It catches everything, including apps that ignore proxy settings.
  - ✅ `injection`: user-mode hooking of Winsock through an injected DLL, only for the programs you start with `proxynator run` or attach to (and everything they start). Nothing machine-wide, but programs that bypass Winsock escape it.
- **Configurable DNS handling:**
  - ✅ `sniff` (default): recover hostnames from TLS SNI or the HTTP `Host` header.
  - ✅ `local`: send the IP address the app resolved.
  - ✅ `remote`: answer DNS with fake IPs and let the proxy do the real resolution, so internal names behind a pivot work.
- ✅ **UDP:** carried through SOCKS5 `UDP ASSOCIATE`; otherwise blocked or sent direct per rule. QUIC is blocked for proxied apps so browsers fall back to TCP.
- ✅ **Fails closed:** if a rule says *proxy* and the proxy is down, the connection fails. It is never silently sent direct.
- ✅ **Fail-safe for the host:** if the service stops or crashes, normal networking resumes.
- ✅ **Headless service + CLI**, with a cross-platform GUI planned.

## How it works

```
 app.exe ──connect()──►  capture backend  ──redirect──►  local relay  ──►  proxy / chain  ──►  destination
                         (WinDivert or       (records      │
                          injected hook)     original      └─ rule engine decides: proxy / direct / block
                                             destination
                                             + PID)
```

1. A **capture backend** sees a new outbound connection and records which process made it and where it was going. If the connection needs handling, the backend redirects it to Proxynator's local relay.
2. The **relay** looks up the original destination and asks the **rule engine** what to do.
3. The relay connects through the selected **proxy or chain** (or directly), then forwards data in both directions.

All proxy, rule and DNS logic is shared by every capture backend and every operating system. Only the capture layer is platform-specific.

## Components

| Component | Description |
|-----------|-------------|
| `proxynatord` | Privileged service/daemon that captures and relays traffic. Runs in the foreground or as a Windows service. |
| `proxynator` | CLI. Talks to the service over a local named pipe (`\\.\pipe\proxynator.v1`) or Unix socket (`/run/proxynator/proxynator.sock`). |
| GUI | Planned. A cross-platform Avalonia app built on the same API as the CLI. |

## Requirements

- **Windows 10/11 x64**. `proxynatord` must run as Administrator; it checks at startup and refuses to run otherwise. The CLI does not need elevation when the service runs in your own (elevated) console.
- Nothing else for the self-contained build; the **.NET 10 runtime** for a framework-dependent one.
- Linux (Ubuntu LTS, Kali rolling, x64) is planned. It will need root, or `CAP_NET_ADMIN` + `CAP_BPF`.

Security software may flag WinDivert or the injection DLL because they are packet-capture and hooking components. That is expected for this kind of tool. Proxynator does not try to evade detection.

## Configuration

Configuration is a single JSON file:

- Windows: `%ProgramData%\Proxynator\config.json`
- Linux: `/etc/proxynator/config.json`

The example below sends `test.exe` through a SOCKS5 proxy, sends `test3.exe` through Burp, sends `curl.exe` through a chain, and lets everything else go direct:

```json
{
  "version": 1,
  "settings": {
    "capture": { "mode": "windivert", "proxyLoopback": false },
    "dns": { "mode": "sniff", "fakeIpRange": "198.18.0.0/15" },
    "udp": { "blockQuic": true }
  },
  "proxies": [
    { "id": "socks-local", "type": "socks5", "host": "127.0.0.1", "port": 5000 },
    { "id": "burp", "type": "http", "host": "127.0.0.1", "port": 8080 },
    { "id": "pivot", "type": "socks5", "host": "10.0.0.5", "port": 1080,
      "auth": { "username": "user", "password": "pass" } }
  ],
  "chains": [
    { "id": "pivot-then-burp", "hops": ["pivot", "burp"] }
  ],
  "rules": [
    {
      "name": "test via SOCKS5",
      "match": { "processes": ["test.exe"], "includeChildren": true },
      "action": { "type": "proxy", "target": "socks-local" }
    },
    {
      "name": "test3 web traffic via Burp",
      "match": { "processes": ["test3.exe"], "ports": ["80", "443"] },
      "action": { "type": "proxy", "target": "burp", "udp": "block" }
    },
    {
      "name": "curl via chain",
      "match": { "processes": ["C:\\Tools\\curl.exe"] },
      "action": { "type": "proxy", "target": "pivot-then-burp" }
    },
    {
      "name": "default",
      "match": {},
      "action": { "type": "direct" }
    }
  ]
}
```

Rules are checked top to bottom, and the first match wins; connections that match no rule go direct. Connections to configured proxy endpoints are never redirected, so loops can't happen. If Burp itself would match one of your rules, exclude it by putting a `direct` rule for it first.

The full format is described by the JSON schema in [`schema/config.schema.json`](schema/config.schema.json), and [`samples/config.json`](samples/config.json) contains the example above. The loader is strict: unknown properties, typos in values, and references to proxies that don't exist are reported with their location, and an invalid file is never partly applied.

## Getting started (Windows)

1. **Get a build.** Download the `proxynator-win-x64` artifact from the latest successful
   [CI run](https://github.com/SieBRUM/proxynator/actions/workflows/ci.yml). It is self-contained and includes the
   WinDivert driver and the hook DLLs. Or build it yourself (see [Building](#building)).
2. **Start the service** from an elevated PowerShell (*Run as administrator*):
   ```
   .\proxynatord.exe --config .\config.json
   ```
   Without `--config` it uses `%ProgramData%\Proxynator\config.json`. Add `--verbose` to log every redirected
   connection. Stop it with Ctrl+C; normal networking is restored immediately.
3. **Load your rules** from a second prompt, then check that everything is healthy:
   ```
   .\proxynator.exe config load .\my-rules.json
   .\proxynator.exe doctor
   ```
   `config load` saves the file as the service configuration unless you pass `--no-save`.
4. **Watch traffic** while you use the application:
   ```
   .\proxynator.exe connections --follow
   ```

To run it as a Windows service instead (from an elevated prompt; use the full path to `proxynatord.exe`):

```
sc.exe create proxynatord binPath= "C:\Tools\Proxynator\proxynatord.exe" start= demand
sc.exe start proxynatord
```

When the service runs as LocalSystem, run the CLI from an elevated prompt.

## CLI

```
proxynator status                       # service state, capture mode, relay, active rules
proxynator doctor                       # privileges, driver files, capture, relay, proxy reachability
proxynator config validate <file>       # check a file without applying it (works without the service)
proxynator config load <file>           # validate and apply atomically; --no-save to not persist it
proxynator config show                  # print the active configuration
proxynator rules list                   # rules in evaluation order with their resolved routes
proxynator connections [--follow]       # relayed connections: process, destination, rule, route, bytes
proxynator run [--detach] -- <program> [args...]   # injection mode: start a program with the hook
proxynator attach <pid>                 # injection mode: hook a running program
```

Exit codes: `0` success, `1` failure (invalid config, failed checks), `2` service not reachable. `proxynator run`
returns the program's own exit code.

## Injection mode

In `injection` mode nothing is captured machine-wide. Instead, the programs you start with `proxynator run` (or hook
later with `proxynator attach`) load a small DLL that asks `proxynatord` before every outbound connection, and
connects to the relay when the rules say so. Everything those programs start is hooked too, including 32-bit
programs started by 64-bit ones and the other way around. Use it when you want to proxy one tool without touching the
rest of the machine, much like proxychains, but for Windows programs that ignore proxy settings.

1. Set the capture mode and (re)start the service. The capture mode only changes on a restart:
   ```json
   "settings": { "capture": { "mode": "injection" } }
   ```
2. Start programs through Proxynator. Put `--` before the program so its options aren't read as Proxynator's:
   ```
   .\proxynator.exe run -- nxc smb dc01.corp.local -u alice -p 'Passw0rd!'
   .\proxynator.exe run -- roadtx gettokens -u alice@corp.example
   .\proxynator.exe run --detach -- "C:\Program Files\App\app.exe"
   .\proxynator.exe attach 4321
   ```
   `run` finds the program on the `PATH` like a command prompt does (`.cmd`/`.bat` files run through `cmd.exe`),
   waits for it and returns its exit code. The CLI doesn't need elevation for either command.

The rules still decide what happens, but only hooked programs are affected, so a rule with an empty `match` means
"everything I start with `proxynator run`". See [`samples/injection-run.json`](samples/injection-run.json).

What is different from `windivert` mode:

- **Fails closed when the service is gone.** Hooked programs then get "connection refused" instead of going direct.
  A child process that can't be hooked isn't started.
- **Remote DNS is per process.** Only hooked programs get fake addresses for `remoteDomains`; the rest of the machine
  resolves normally and the DNS cache is not touched.
- **Hostnames come from the program's own lookups**, so the proxy also gets them for protocols that can't be sniffed
  (SMB, LDAP, Kerberos, ...). A hostname sniffed from TLS or HTTP still takes precedence.
- **UDP** is not relayed yet: it follows the rule's `udp` setting (`block` by default, or `direct`), and QUIC is
  blocked for proxied programs.
- **Programs that bypass Winsock escape the hook**: raw system calls, custom network stacks, and processes that only
  load Microsoft-signed DLLs (some browser sandboxes; a child the hook can't load into isn't started). Use
  `windivert` mode for those. Programs already running only follow the rules for connections they open after
  `proxynator attach`.

Set the environment variable `PROXYNATOR_HOOK_LOG` to a file path before `proxynator run` to get a log from every
hooked process (the hook also writes to the debugger output, visible in Sysinternals DebugView).

## Python tools (pipx, NetExec, roadtools)

The simplest way is the [injection mode](#injection-mode): `proxynator run -- nxc smb ...` hooks the launcher, the
Python interpreters it starts and everything else, with no rules about process names needed. With the machine-wide
`windivert` mode, read on.

Tools installed with pipx (or pip into a venv) don't run as their own process. `nxc.exe`, `roadrecon.exe` and
`roadtx.exe` are small launchers that start the venv's `python.exe`, which in turn starts the real interpreter. That
interpreter opens the connections. So match the launcher and set `includeChildren`:

```json
{ "name": "NetExec", "match": { "processes": ["nxc.exe", "netexec.exe"], "includeChildren": true }, "action": { "type": "proxy", "target": "pivot" } }
```

Child matching keeps working if the launcher exits early. Don't match plain `python.exe`: that would catch every
Python program. To match a script you run with `python script.py`, match its venv instead, for example
`"processes": ["*\\venvs\\netexec\\*"]` with `includeChildren`. CI tests exactly this launcher → `python.exe`
chain with a venv's `pip.exe`.

Tips per tool:

- **NetExec / impacket** speak SMB, LDAP, Kerberos, MSSQL and similar protocols, not HTTP. Route them through a
  **SOCKS** proxy (a pivot), not Burp. Burp only understands HTTP(S) inside a `CONNECT` tunnel.
- **Internal hostnames** (`dc01.corp.local`, needed for Kerberos) can't be resolved on your machine. Use
  `"dns": { "mode": "remote", "remoteDomains": ["corp.local", "*.corp.local"] }` so they resolve on the far side of
  the pivot. NetExec's own DNS queries (`--dns-server`) are UDP; many SOCKS servers (e.g. `ssh -D`) don't support
  UDP, so add `--dns-tcp` or use IP addresses.
- **roadtools** talk HTTPS to Entra ID and Graph, which works well through Burp. Python verifies TLS against its own
  CA bundle (certifi), not the Windows certificate store. To accept Burp's certificate, point `REQUESTS_CA_BUNDLE`
  at a PEM file containing Burp's CA. `roadtx` interactive logins start a browser through chromedriver, and
  `includeChildren` routes that browser too.

Ready-made configs: [`samples/netexec-socks-pivot.json`](samples/netexec-socks-pivot.json),
[`samples/roadtools-burp.json`](samples/roadtools-burp.json) and, for the injection mode,
[`samples/injection-run.json`](samples/injection-run.json).

## Known limitations

- **UDP** goes through a proxy only when the rule's target is a single SOCKS5 proxy. For HTTP or SOCKS4 proxies and
  chains, the rule's `udp` setting decides: `block` (default) or `direct`. QUIC (UDP/443) of proxied apps is
  blocked, so browsers fall back to TCP.
- In `injection` mode UDP is not relayed (only `block` or `direct`), and programs that bypass Winsock escape the
  hook; see [Injection mode](#injection-mode).
- **Remote DNS** in `windivert` mode is machine-wide: Windows resolves names centrally (the DNS Client service), so every program gets
  fake answers for the names in `remoteDomains`. Programs without a proxy rule still work, because their connections
  to fake addresses go direct through the relay. Keep `remoteDomains` as narrow as you can. DNS over TCP, DNS servers
  on loopback and encrypted DNS (DoH) are not intercepted. Proxynator flushes the DNS cache when it starts and stops.
- **Loopback** connections (to `127.0.0.1` or to the machine's own addresses) are never redirected.
- A rule that would also catch your proxy program's own outbound traffic (for example a catch-all rule while Burp
  runs on the same machine) creates a loop. Put a `direct` rule for the proxy program first.
- When Windows Defender Firewall is enabled, `proxynatord` adds inbound rules named "Proxynator relay" for its
  relay ports while it runs, and removes them on exit.

## Building

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
```

Building on Windows downloads the pinned WinDivert release (SHA-256 verified) and places it next to
`proxynatord`.

The injection mode's hook DLLs (`proxynator-hook64.dll`, `proxynator-hook32.dll`) are C++ and need
[CMake](https://cmake.org/) and Visual Studio or the Build Tools with the "Desktop development with C++" workload.
Build them first; the .NET build then copies them next to the executables (without them, everything except the
injection mode still works):

```
./build/build-native.ps1
```

For a self-contained Windows build:

```
dotnet publish src/Proxynator.Service -c Release -r win-x64 --self-contained -o out
dotnet publish src/Proxynator.Cli -c Release -r win-x64 --self-contained -o out
```

GitHub Actions builds and tests every push on Windows and Linux. On Windows it also builds the hook DLLs, runs
end-to-end tests that route real traffic through both capture modes (curl.exe 64- and 32-bit, nslookup, pip in a
venv, PowerShell, attaching to running programs; these need an elevated prompt:
`dotnet test tests/Proxynator.IntegrationTests`), and publishes the `proxynator-win-x64` build.

## Roadmap

1. ✅ Core: config, rule engine, proxy protocols, chaining, relay. Cross-platform and unit-tested.
2. ✅ Windows: kernel-level (`windivert`) TCP capture, service, IPC, basic CLI.
3. ✅ Remote (fake-IP) DNS, UDP via SOCKS5, QUIC blocking, child-process rules that survive launcher exit.
4. ✅ Windows: `injection` capture mode (`proxynator run` / `attach`, child processes, both bitnesses).
5. Linux: eBPF/nftables capture, `LD_PRELOAD` mode, systemd, `.deb` packages for Ubuntu and Kali.
6. Cross-platform GUI.
7. Later: connection log export, pcap output, statistics, TLS-to-proxy hops, ARM64.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) for the architecture, conventions and rules the codebase follows.

## License

Licensed under the [Apache License 2.0](LICENSE). If you redistribute Proxynator or a derivative of it, you must keep the [`NOTICE`](NOTICE) file, which credits this project. Third-party components keep their own licenses: WinDivert is LGPLv3/GPLv2 and loaded dynamically; Microsoft Detours is MIT.
