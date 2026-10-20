# Proxynator

**Behold, the PROXYNATOR! With it, I will force *every application in the tri-state area* through my proxy, whether it wants to go or not!**

*(Okay. Only the applications you pick. And only through proxies you own. Ahem.)*

Proxynator is an open-source, rule-based traffic redirector for **Windows** and **Linux**. It grabs the outbound
connections of the programs you choose and marches them through SOCKS4, SOCKS4a, SOCKS5 or HTTP `CONNECT` proxies,
or a whole chain of them. Its day job is analysis: point a stubborn desktop app, a CLI tool, NetExec, roadtools or a
game at Burp Suite, mitmproxy or a SOCKS pivot, *even when that app has no proxy setting or flat-out ignores it*.

> **Why "Proxynator"?** Because every respectable evil scientist names their inventions *something*-inator, and
> "Make-Apps-Use-My-Proxy-Whether-They-Like-It-Or-Not-inator" didn't fit on the CLI.

> **Status: early, but it works.** Windows: machine-wide kernel capture (`windivert`) or per-program hooking
> (`injection`). Linux (Ubuntu, Kali): machine-wide eBPF capture (`ebpf`) or per-program `LD_PRELOAD` (`preload`),
> as a `.deb` with a systemd unit. Fake-IP DNS for resolving internal names through a pivot, all driven by the
> `proxynator` CLI. A GUI is next. See the [known limitations](#self-destruct-buttons-known-limitations) and the
> [roadmap](#roadmap).

## The backstory (why this exists)

Back when I was a young pentester, I set `HTTP_PROXY`. The application ignored it. I set the system proxy. The
application ignored that too. I tried proxychains. Firefox laughed, spawned a sandboxed child process and
resolved its DNS over HTTPS. Go binaries never even noticed `LD_PRELOAD` was there.

*Curse you, applications-that-ignore-proxy-settings!*

So the Proxynator doesn't ask nicely. Its default modes capture connections **in the kernel** (WinDivert on Windows,
eBPF on Linux) and quietly redirect them to a local relay. The application never learns a proxy was involved, so it
doesn't matter what it thinks of proxy settings.

## Features

✅ = works today. Everything else is in the evil lair, under construction.

- ✅ **Per-application rules:** match by process name or path (wildcards), child processes, destination host/IP/CIDR,
  port and protocol. First match wins. Scripts count too: a rule for `nxc` matches `python3 nxc` as well.
- ✅ **Different proxies per rule:** `test.exe` → SOCKS5 `127.0.0.1:5000`, `test3.exe` → Burp at `127.0.0.1:8080`.
- ✅ **Proxy types:** SOCKS4, SOCKS4a, SOCKS5 (with username/password), HTTP `CONNECT` (with Basic auth). The HTTP
  type covers HTTPS traffic, so it works with Burp, mitmproxy and friends.
- ✅ **Proxy chains:** A → B → C. Because one proxy is never enough for a proper scheme.
- ✅ **Actions:** `proxy`, `direct` or `block`.
- ✅ **Four capture modes, two per platform** (you choose):

  | | Machine-wide, in the kernel (default) | Only what you start, user-mode |
  |---|---|---|
  | **Windows** | `windivert`: the signed WinDivert driver | `injection`: a hook DLL via `proxynator run` / `attach` |
  | **Linux** | `ebpf`: eBPF programs on the root cgroup | `preload`: an `LD_PRELOAD` library via `proxynator run` |

- ✅ **Configurable DNS:**
  - `sniff` (default): recover hostnames from TLS SNI or the HTTP `Host` header.
  - `local`: send the IP address the app resolved.
  - `remote`: answer DNS with fake IPs so the *proxy* resolves the real name. Internal names behind a pivot
    (`dc01.corp.local`) just work.
- ✅ **UDP:** through SOCKS5 `UDP ASSOCIATE` (windivert), otherwise blocked or sent direct per rule. QUIC is blocked
  for proxied apps so browsers fall back to TCP, where your proxy can see them.
- ✅ **Fails closed:** if a rule says *proxy* and the proxy is down, the connection fails. It is never quietly sent
  direct. Unlike most of my schemes, this one has no "oops, it leaked" ending.
- ✅ **A self-destruct button:** stop or crash the service and normal networking resumes on its own (WinDivert
  handles close, eBPF links detach). Every good -inator has one.
- ✅ **Headless service + CLI**, with a cross-platform GUI planned.

## The evil scheme (how it works)

```
 app ──connect()──►  capture backend  ──redirect──►  local relay  ──►  proxy / chain  ──►  destination
                     (WinDivert, eBPF,    (records      │
                      or a hook)          original      └─ rule engine decides: proxy / direct / block
                                          destination
                                          + PID)
```

1. A **capture backend** sees a new outbound connection, notes which process made it and where it was going, and
   (if the rules may care) redirects it to Proxynator's local relay.
2. The **relay** looks up the original destination and asks the **rule engine** what to do.
3. The relay connects through the chosen **proxy or chain** (or directly), then shovels bytes both ways.

All proxy, rule and DNS logic is shared by every backend on every OS. Only the capturing is platform-specific,
which is the one part of this plan that is actually well thought out.

## Components

| Component | Description |
|-----------|-------------|
| `proxynatord` | The privileged service/daemon that captures and relays. Foreground, Windows service or systemd unit. |
| `proxynator` | The CLI. Talks to the service over a local named pipe (`\\.\pipe\proxynator.v1`) or Unix socket (`/run/proxynator/proxynator.sock`). |
| GUI | Planned. A cross-platform Avalonia app on the same API as the CLI. |

## Requirements

- **Windows 10/11 x64.** `proxynatord` must run as Administrator; it checks at startup and refuses otherwise.
- **Linux x64:** Ubuntu 22.04+ or Kali rolling (other systemd distributions likely work). `proxynatord` needs root
  (or `CAP_NET_ADMIN` + `CAP_BPF` + `CAP_PERFMON`). The `ebpf` mode needs cgroup v2, kernel BTF and `libbpf`
  (`libbpf1`, or `libbpf0` on 22.04), all standard on those systems.
- Nothing else for the self-contained builds and the `.deb`.

Security software may flag WinDivert, the hook DLL or the preload library: they capture packets and hook functions,
which is exactly what they're for. Proxynator does not try to evade detection. It's evil in name only.

## Configuration

One JSON file, mostly harmless:

- Windows: `%ProgramData%\Proxynator\config.json`
- Linux: `/etc/proxynator/config.json`

The example below sends `test.exe` through a SOCKS5 proxy, sends `test3.exe` through Burp, sends `curl.exe` through a
chain, and lets everything else go direct:

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

Rules are checked top to bottom and the first match wins; whatever matches nothing goes direct. Connections to the
configured proxies themselves are never redirected, so the Proxynator can't trap itself in an infinite loop (a
mistake I have made with other inventions). If Burp itself would match one of your rules, put a `direct` rule for it
first.

On Linux, process names have no `.exe`: `curl`, `nxc`, `python3`. Patterns with a `/` match full paths, e.g.
`"*/pipx/venvs/netexec/*"`.

The format is described by [`schema/config.schema.json`](schema/config.schema.json); [`samples/`](samples/) has
ready-made configs. The loader is strict: unknown properties, typos and references to proxies that don't exist are
reported with their location, and an invalid file is never half applied.

## Getting started (Windows)

1. **Get a build.** Download the `proxynator-win-x64` artifact from the latest successful
   [CI run](https://github.com/SieBRUM/proxynator/actions/workflows/ci.yml). It is self-contained and includes the
   WinDivert driver and the hook DLLs. Or build it yourself (see [Building](#building)).
2. **Start the service** from an elevated PowerShell (*Run as administrator*):
   ```
   .\proxynatord.exe --config .\config.json
   ```
   Without `--config` it uses `%ProgramData%\Proxynator\config.json`. Add `--verbose` to log every redirected
   connection. Ctrl+C stops it, and normal networking is restored immediately.
3. **Load your rules** from a second prompt and check that all is well:
   ```
   .\proxynator.exe config load .\my-rules.json
   .\proxynator.exe doctor
   ```
   `config load` saves the file as the service configuration unless you pass `--no-save`.
4. **Watch the traffic** while you use the application:
   ```
   .\proxynator.exe connections --follow
   ```

To run it as a Windows service (elevated prompt, full path to `proxynatord.exe`):

```
sc.exe create proxynatord binPath= "C:\Tools\Proxynator\proxynatord.exe" start= demand
sc.exe start proxynatord
```

When the service runs as LocalSystem, run the CLI elevated.

## Getting started (Linux)

1. **Get the package.** Download the `proxynator-linux-x64-deb` artifact from the latest successful
   [CI run](https://github.com/SieBRUM/proxynator/actions/workflows/ci.yml) and install it:
   ```
   sudo apt install ./proxynator_0.1.0_amd64.deb
   ```
   It installs to `/opt/proxynator`, adds `proxynator` and `proxynatord` to the `PATH`, a systemd unit, a default
   `/etc/proxynator/config.json` and a `proxynator` group. It does *not* start anything on its own; even evil
   scientists ask first.
2. **Configure and start:**
   ```
   sudo cp /usr/share/doc/proxynator/samples/linux-pivot.json /etc/proxynator/config.json
   sudo systemctl enable --now proxynatord
   ```
3. **Use the CLI** as root, or add yourself to the group (log in again afterwards):
   ```
   sudo usermod -aG proxynator "$USER"
   proxynator doctor
   proxynator connections --follow
   ```

Without the package: `sudo ./proxynatord --config ./config.json` from a build directory works too.

## CLI

```
proxynator status                       # service state, capture mode, relay, active rules
proxynator doctor                       # privileges, drivers/eBPF/libraries, capture, relay, proxy reachability
proxynator config validate <file>       # check a file without applying it (works without the service)
proxynator config load <file>           # validate and apply atomically; --no-save to not persist it
proxynator config show                  # print the active configuration
proxynator rules list                   # rules in evaluation order with their resolved routes
proxynator connections [--follow]       # relayed connections: process, destination, rule, route, bytes
proxynator run [--detach] -- <program> [args...]   # injection/preload mode: start a program with the hook
proxynator attach <pid>                 # injection mode (Windows): hook a running program
```

Exit codes: `0` success, `1` failure (invalid config, failed checks), `2` service not reachable. `proxynator run`
returns the program's own exit code.

## Hooking just one program (injection and preload modes)

Sometimes you don't want to take over the whole tri-state area, just one tool. In `injection` (Windows) and
`preload` (Linux) mode nothing is captured machine-wide. The programs you start with `proxynator run` load a small
hook that asks `proxynatord` before every outbound connection and goes to the relay when the rules say so.
Everything those programs start is hooked too (on Windows, also 32-bit programs started by 64-bit ones and vice
versa). It's proxychains, but it also works on Windows programs that ignore proxy settings.

1. Set the capture mode and (re)start the service. The mode only changes on a restart:
   ```json
   "settings": { "capture": { "mode": "injection" } }
   ```
   (`"preload"` on Linux.)
2. Start programs through the Proxynator. The `--` keeps their options from being read as Proxynator's:
   ```
   proxynator run -- nxc smb dc01.corp.local -u alice -p 'Passw0rd!'
   proxynator run -- roadtx gettokens -u alice@corp.example
   proxynator run --detach -- "C:\Program Files\App\app.exe"
   proxynator attach 4321                     # Windows only
   ```
   `run` finds the program on the `PATH` (on Windows also `.cmd`/`.bat` through `cmd.exe`), waits for it and returns
   its exit code. No elevation or sudo needed for `run` or `attach`.

The rules still decide, but only hooked programs are affected, so a rule with an empty `match` means "everything I
start with `proxynator run`". See [`samples/injection-run.json`](samples/injection-run.json).

What's different from the machine-wide modes:

- **Fails closed when the service is gone.** Hooked programs get "connection refused" instead of going direct. A
  child process the hook can't load into isn't started.
- **Remote DNS is per process.** Only hooked programs get fake addresses; the rest of the machine resolves normally.
- **Hostnames come from the program's own lookups**, so the proxy also gets them for protocols that can't be sniffed
  (SMB, LDAP, Kerberos...). A hostname sniffed from TLS or HTTP still wins.
- **UDP is not relayed:** it follows the rule's `udp` setting (`block` by default, or `direct`). QUIC is blocked.
- **Some programs escape a user-mode hook** (see [limitations](#self-destruct-buttons-known-limitations)). The kernel
  modes catch those.

Set `PROXYNATOR_HOOK_LOG` to a file path before `proxynator run` to get a log from every hooked process. On Windows
the hook also writes to the debugger output (Sysinternals DebugView).

## Python tools (pipx, NetExec, roadtools)

**The easy way:** a hooking mode. `proxynator run -- nxc smb ...` hooks the tool, the Python interpreter and
everything they start, no process-name rules needed.

**The machine-wide way** (`windivert`, `ebpf`) needs a rule that matches the tool:

- **Windows:** pipx's `nxc.exe`, `roadrecon.exe` and `roadtx.exe` are small launchers that start the venv's
  `python.exe`, which starts the real interpreter. Match the launcher with `includeChildren`. This keeps working if
  the launcher exits early. Don't match plain `python.exe` unless you enjoy proxying every Python program on the
  machine.
  ```json
  { "name": "NetExec", "match": { "processes": ["nxc.exe", "netexec.exe"], "includeChildren": true }, "action": { "type": "proxy", "target": "pivot" } }
  ```
- **Linux:** pipx installs Python scripts; the kernel names the process after the script, so `"processes": ["nxc"]`
  matches. So does `python3 /path/to/nxc` (the script an interpreter runs counts).

Tips per tool:

- **NetExec / impacket** speak SMB, LDAP, Kerberos, MSSQL and friends, not HTTP. Send them through a **SOCKS** pivot,
  not Burp. Burp only understands HTTP(S) inside a `CONNECT` tunnel.
- **Internal hostnames** (`dc01.corp.local`, which Kerberos needs) don't resolve on your machine. Use
  `"dns": { "mode": "remote", "remoteDomains": ["corp.local", "*.corp.local"] }` so they resolve on the far side of
  the pivot. NetExec's own DNS queries (`--dns-server`) are UDP; many SOCKS servers (e.g. `ssh -D`) don't do UDP, so
  add `--dns-tcp` or use IP addresses.
- **roadtools** speak HTTPS to Entra ID and Graph, which works great through Burp. Python checks TLS against its own CA
  bundle (certifi), not the system store: point `REQUESTS_CA_BUNDLE` at a PEM file containing Burp's CA. `roadtx`
  interactive logins start a browser through chromedriver; `includeChildren` routes that browser too.

Ready-made configs: [`samples/netexec-socks-pivot.json`](samples/netexec-socks-pivot.json),
[`samples/roadtools-burp.json`](samples/roadtools-burp.json), [`samples/injection-run.json`](samples/injection-run.json)
and, for Linux, [`samples/linux-pivot.json`](samples/linux-pivot.json).

## Self-destruct buttons (known limitations)

Every -inator has a weakness. Here are this one's, so nobody has to find out the hard way:

- **UDP** goes through a proxy only in `windivert` mode, and only to a single SOCKS5 proxy. Otherwise the rule's
  `udp` setting decides: `block` (default) or `direct`. QUIC (UDP/443) of proxied apps is blocked.
- **Remote DNS in `windivert` mode is machine-wide:** Windows resolves names centrally, so every program gets fake
  answers for the names in `remoteDomains`. Programs without a proxy rule still work (their connections to fake
  addresses go direct through the relay), but keep `remoteDomains` narrow. Proxynator flushes the DNS cache when it
  starts and stops. In the other three modes, remote DNS is per process.
- **`ebpf` mode and `.local` names:** desktop Linux systems with mDNS (`mdns4_minimal` in `/etc/nsswitch.conf`)
  resolve `*.local` through Avahi, not DNS, so remote DNS can't fake them there. Use `preload` mode for `.local`
  domains (it answers before NSS), or remove `mdns4_minimal` from `nsswitch.conf`.
- **`ebpf` mode and rules without a process:** a rule that matches any process (e.g. "all port 443 to Burp") sends
  *every* program's TCP connections through the relay, which then decides. It works, but it's machine-wide.
- **Hooking modes can be escaped** by programs that bypass the system's socket library: raw system calls, their own
  network stack, statically linked or Go binaries on Linux, setuid programs and `sudo` (which drop `LD_PRELOAD`), and
  Windows processes that only load Microsoft-signed DLLs (some browser sandboxes). Use the kernel modes for those.
  `proxynator attach` doesn't exist on Linux: a library can't be preloaded into a running process.
- **Loopback** connections (`127.0.0.1`, `::1`, or the machine's own addresses on Windows) are never redirected.
- A rule that also catches your proxy program's own traffic (e.g. a catch-all while Burp runs on the same machine)
  makes a loop. Put a `direct` rule for the proxy program first.
- With Windows Defender Firewall enabled, `windivert` mode adds inbound rules named "Proxynator relay" while it runs,
  and removes them on exit.

## Building

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
```

Building on Windows downloads the pinned WinDivert release (SHA-256 verified) and puts it next to `proxynatord`.

The native capture parts are built separately, first; the .NET build then copies them next to the executables.
Without them everything still builds, and only the modes that need them stop working (`proxynator doctor` says so):

```
./build/build-native.ps1    # Windows: hook DLLs (needs CMake and Visual Studio's "Desktop development with C++")
./build/build-native.sh     # Linux: eBPF object and preload library (sudo apt install clang llvm libbpf-dev gcc)
```

Self-contained builds and the Debian package:

```
dotnet publish src/Proxynator.Service -c Release -r win-x64 --self-contained -o out
dotnet publish src/Proxynator.Cli -c Release -r win-x64 --self-contained -o out

dotnet publish src/Proxynator.Service -c Release -r linux-x64 --self-contained -o out
dotnet publish src/Proxynator.Cli -c Release -r linux-x64 --self-contained -o out
./build/package-deb.sh out 0.1.0
```

GitHub Actions builds and tests every push on Windows and Linux, including end-to-end tests that push real traffic
through all four capture modes (curl, nslookup, PowerShell, Python, pip in a venv, shell scripts, attaching to running
programs; Windows needs an elevated prompt and Linux needs root: `dotnet test tests/Proxynator.IntegrationTests`).
It publishes the `proxynator-win-x64` build and the `proxynator-linux-x64-deb` package.

## Roadmap

1. ✅ Core: config, rule engine, proxy protocols, chaining, relay. Cross-platform and unit-tested.
2. ✅ Windows: kernel-level (`windivert`) TCP capture, service, IPC, basic CLI.
3. ✅ Remote (fake-IP) DNS, UDP via SOCKS5, QUIC blocking, child-process rules that survive launcher exit.
4. ✅ Windows: `injection` capture mode (`proxynator run` / `attach`, child processes, both bitnesses).
5. ✅ Linux: `ebpf` and `preload` capture modes, systemd unit, `.deb` packages for Ubuntu and Kali.
6. Cross-platform GUI.
7. Later: connection log export, pcap output, statistics, TLS-to-proxy hops, UDP relaying in the other modes, ARM64.
   And maybe a self-destruct button that's actually labelled.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) for the architecture, conventions and rules the codebase follows. Pull requests welcome;
platypuses wearing fedoras will be viewed with suspicion.

## License

Licensed under the [Apache License 2.0](LICENSE). If you redistribute Proxynator or a derivative, keep the
[`NOTICE`](NOTICE) file, which credits this project. Third-party components keep their own licenses: WinDivert is
LGPLv3/GPLv2 and loaded dynamically; Microsoft Detours is MIT; libbpf (LGPL-2.1/BSD-2-Clause) is the system's,
loaded dynamically. The eBPF program (`native/linux/bpf`) is dual-licensed MIT/GPL-2.0, as the kernel requires.
