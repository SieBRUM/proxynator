# Proxynator

**Force any application's traffic through a SOCKS or HTTP proxy, whether it supports proxies or not.**

Proxynator is an open-source, rule-based traffic redirector for Windows (and, later, Linux). It captures the outbound connections of the applications you choose and sends them through SOCKS4, SOCKS4a, SOCKS5 or HTTP `CONNECT` proxies. Proxy chains are supported too. Its main use is analysis: point a stubborn desktop app, CLI tool or game at Burp Suite, mitmproxy or a SOCKS pivot, even when that app has no proxy setting or ignores it.

> **Status: early development.** The cross-platform core (configuration, rules, proxy protocols, chaining and the
> relay) is built and tested, but traffic capture is not, so Proxynator can't be used as a tool yet. See the
> [roadmap](#roadmap).

## Why another proxy tool?

User-mode tricks (setting `HTTP_PROXY`, `LD_PRELOAD`/DLL hooking of `connect()`) only work for apps that cooperate. Apps that use their own network stack, their own DNS (DoH), static binaries, raw syscalls or sandboxed helper processes slip past them.

Proxynator's default mode captures traffic **at the kernel network layer** and transparently redirects it to a local relay. The application never knows a proxy is involved, so it doesn't matter whether it respects proxy settings.

## Features (planned)

- **Per-application rules:** match by process name/path (wildcards), child processes, destination host/IP/CIDR, port and protocol. First match wins.
- **Different proxies per rule:** for example `test.exe` → SOCKS5 `127.0.0.1:5000`, and `test3.exe` → Burp at `127.0.0.1:8080`.
- **Proxy types:** SOCKS4, SOCKS4a, SOCKS5 (with username/password), HTTP `CONNECT` (with Basic auth). The HTTP type covers HTTPS traffic, so it works with Burp, mitmproxy and similar tools.
- **Proxy chains:** route through several proxies in sequence (A → B → C).
- **Actions:** `proxy`, `direct` or `block`.
- **Two capture modes on Windows**, chosen by the user:
  - `windivert` (default): kernel-level capture through the signed WinDivert driver. It catches everything, including apps that ignore proxy settings.
  - `injection`: user-mode hooking of Winsock through an injected DLL, for processes you launch or attach to. Lighter, but it can be bypassed.
- **Configurable DNS handling:**
  - `sniff` (default): recover hostnames from TLS SNI or the HTTP `Host` header.
  - `local`: send the IP address the app resolved.
  - `remote`: answer DNS with fake IPs and let the proxy do the real resolution.
- **UDP:** carried through SOCKS5 `UDP ASSOCIATE`; otherwise blocked or sent direct per rule. QUIC can be blocked so browsers fall back to TCP.
- **Fails closed:** if a rule says *proxy* and the proxy is down, the connection fails. It is never silently sent direct.
- **Fail-safe for the host:** if the service stops or crashes, normal networking resumes.
- **Headless service + CLI**, with a cross-platform GUI planned.

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
| `proxynatord` | Privileged service/daemon that captures and relays traffic. Runs as a Windows service or in the foreground with `--console`. |
| `proxynator` | Unprivileged CLI. Talks to the service over a local named pipe or Unix socket. |
| GUI | Planned. A cross-platform Avalonia app built on the same API as the CLI. |

## Requirements

- **Windows 10/11 x64**, run as Administrator. The service checks for this at startup and refuses to run without it.
- **.NET 10 runtime**, or a self-contained build.
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

## CLI (planned)

```
proxynator status                          # service state, capture mode, active rules
proxynator doctor                          # check privileges, driver, config, proxy reachability
proxynator config validate <file>          # validate without applying
proxynator config load <file>              # validate and apply atomically
proxynator rules list
proxynator connections [--follow]          # live connections: process, destination, rule, proxy
proxynator test-proxy <proxy-or-chain-id>  # dial a test connection through a proxy/chain
proxynator run --rule <name> -- app.exe    # launch with injection mode
proxynator attach <pid> --rule <name>      # inject into a running process
```

## Building

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```
dotnet build Proxynator.sln -c Release
dotnet test Proxynator.sln --filter "Category!=Integration"
```

GitHub Actions builds and tests every push on Windows and Linux. Later phases add integration tests, which need an elevated shell (Windows) or root (Linux), and the native injection DLL, built with CMake for x64 and x86.

## Roadmap

1. ✅ Core: config, rule engine, proxy protocols, chaining, relay. Cross-platform and unit-tested.
2. Windows: kernel-level (`windivert`) TCP capture, service, IPC, basic CLI.
3. DNS modes, UDP via SOCKS5, QUIC blocking, child-process rules.
4. Windows: `injection` capture mode.
5. Linux: eBPF/nftables capture, `LD_PRELOAD` mode, systemd, `.deb` packages for Ubuntu and Kali.
6. Cross-platform GUI.
7. Later: connection log export, pcap output, statistics, TLS-to-proxy hops, ARM64.

## Contributing

See [`CLAUDE.md`](CLAUDE.md) for the architecture, conventions and rules the codebase follows.

## License

Licensed under the [Apache License 2.0](LICENSE). If you redistribute Proxynator or a derivative of it, you must keep the [`NOTICE`](NOTICE) file, which credits this project. Third-party components keep their own licenses: WinDivert is LGPLv3/GPLv2 and loaded dynamically; Microsoft Detours is MIT.
