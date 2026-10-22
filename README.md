# Proxynator

**Behold, the PROXYNATOR! With it, I will force *every application in the tri-state area* through my proxy, whether it wants to go or not!**

*(Okay. Only the applications you pick. And only through proxies you own. Ahem.)*

Proxynator sends the network traffic of the programs you choose through SOCKS4/4a/5 or HTTP proxies, or a chain of
them, on **Windows** and **Linux**. Point a thick client at Burp Suite, run NetExec through a C2's SOCKS server, or
send everything for `corp.local` through a pivot. It works *even when the program has no proxy setting or ignores
it*: the default modes capture connections in the kernel, so the program never knows.

![The Proxynator GUI: rules](docs/images/gui-rules.png)

> **Why "Proxynator"?** Every respectable evil scientist names their inventions *something*-inator, and
> "Make-Apps-Use-My-Proxy-Whether-They-Like-It-Or-Not-inator" didn't fit on the CLI.

## Why

Back when I was a young pentester, I set `HTTP_PROXY`. The application ignored it. I set the system proxy. Ignored.
I tried proxychains: Firefox laughed, spawned a sandboxed child and resolved its DNS over HTTPS, and Go binaries never
noticed `LD_PRELOAD` was there. *Curse you, applications-that-ignore-proxy-settings!*

So the Proxynator doesn't ask nicely:

- **Rules per program, host or network:** match by process (with child processes and the scripts an interpreter
  runs), destination name (`*corp.local`), address range, port and protocol. Each rule picks a proxy, a chain,
  `direct` or `block`.
- **Every proxy you'll meet:** SOCKS4, SOCKS4a, SOCKS5 (with password), HTTP `CONNECT` (with Basic auth): Burp,
  mitmproxy, `ssh -D`, chisel and C2 SOCKS servers. Chains of any length.
- **DNS that works through pivots:** internal names resolve on the far side, without needing UDP through the proxy,
  including Active Directory's domain controller lookups.
- **Fails closed:** if a rule says *proxy* and the proxy is down, the connection fails. It never quietly goes direct.
- **A self-destruct button:** stop or crash the service and normal networking resumes on its own.
- **A GUI** for everything, a CLI for scripts, packages for Windows x64 and Linux x64/arm64.

## Install

Download the package for your system from the [latest release](https://github.com/SieBRUM/proxynator/releases/latest):

| System | Package | |
|---|---|---|
| Windows 10/11 x64 | `proxynator-<version>-win-x64.zip` | Unzip anywhere. |
| Ubuntu, Kali (x64 / arm64) | `proxynator_<version>_amd64.deb` / `_arm64.deb` | `sudo apt install ./proxynator_*.deb` |
| Other Linux (x64 / arm64) | `proxynator-<version>-linux-x64.tar.gz` / `-linux-arm64.tar.gz` | Unpack anywhere. |

Everything is self-contained (no .NET needed). The service needs Administrator (Windows) or root (Linux); the GUI and
CLI don't. Details: [Installation](docs/installation.md).

## Quick start (GUI)

1. **Open Proxynator** (`proxynator-gui.exe`, or *Proxynator* in the Linux menu) and click **Start proxynatord**.
   Confirm the Administrator / password prompt.
2. **Proxies:** add your proxy, e.g. **Add Burp (127.0.0.1:8080)**, or a SOCKS proxy with **Add proxy**. **Test
   connection** checks that it answers.
3. **Rules:** **Add** a rule. Fill in **Processes** (`app.exe`, `nxc`, ...) and/or **Hosts** (`*corp.local`) and pick
   the proxy under **Via**.
4. Press **Apply and save**.
5. Use the program as usual, and watch **Connections**.

Prefer files? Every setting is also JSON (the GUI's **JSON** page, or `proxynator config load my.json`):

```json
{
  "version": 1,
  "proxies": [ { "id": "burp", "type": "http", "host": "127.0.0.1", "port": 8080 } ],
  "rules": [
    { "name": "app via Burp", "match": { "processes": ["app.exe"], "includeChildren": true }, "action": { "type": "proxy", "target": "burp" } }
  ]
}
```

## Guides

Each guide shows the GUI steps and the JSON.

| I want to... | Guide |
|---|---|
| see one program's HTTP(S) in Burp | [A program through Burp](docs/guides/burp.md) |
| send only `corp.local` through a pivot, for every program | [Internal names through a pivot](docs/guides/internal-domain.md) |
| use a C2 framework's SOCKS server (and have DNS work) | [C2 SOCKS servers and DNS](docs/guides/c2-socks.md) |
| run NetExec, impacket, BloodHound, LDAP and Kerberos through a pivot | [Active Directory tooling](docs/guides/active-directory.md) |
| reach a network behind two pivots | [Proxy chains](docs/guides/chains.md) |
| capture just the programs I start, nothing else | [Hooking single programs](docs/guides/hooking.md) |

Reference: [GUI](docs/gui.md) · [Configuration](docs/configuration.md) · [CLI](docs/cli.md) ·
[Troubleshooting](docs/troubleshooting.md) · [Building](docs/building.md) · [All docs](docs/README.md)

## How it works

```
 program ──connect()──► capture ──redirect──► local relay ──► proxy / chain ──► destination
                        (kernel or hook)       │
                                               └─ the rules decide: proxy, direct or block
```

A **capture mode** redirects the connections the rules care about to Proxynator's local **relay**, remembering where
each was going and which program made it. The relay asks the **rules**, connects through the chosen proxy (handing it
the hostname, so it resolves on the far side), and passes the bytes along.

| | Machine-wide, in the kernel (default) | Only what you start, user-mode |
|---|---|---|
| **Windows** | `windivert`: the signed WinDivert driver | `injection`: a hook DLL |
| **Linux** | `ebpf`: eBPF programs | `preload`: an `LD_PRELOAD` library |

The kernel modes catch everything, including programs that resolve their own DNS, Go and static binaries and
sandboxed children. The user-mode ones only touch the programs you start through Proxynator ([guide](docs/guides/hooking.md)).

## Limitations

Every -inator has a weakness:

- **UDP** goes through a proxy only in `windivert` mode, and only through a single SOCKS5 proxy that supports it.
  Otherwise each rule blocks it (the default) or sends it direct. QUIC is blocked for proxied programs, so browsers
  use TCP.
- **Remote DNS on Windows is machine-wide** for the names you list: Windows resolves names centrally.
- **The user-mode modes can be escaped** by programs that make raw system calls, Go/static binaries on Linux, `sudo`,
  and Windows processes that only load Microsoft-signed DLLs. Use the kernel modes for those.
- **Loopback** traffic is never redirected.
- **Not supported:** macOS, and Windows on ARM (WinDivert has no ARM64 driver).

More, with workarounds: [Troubleshooting](docs/troubleshooting.md). Security software may flag WinDivert, the hook DLL
or the preload library: capturing packets and hooking functions is what they do. Proxynator does not try to evade
detection. It's evil in name only.

## Contributing and building

See [Building](docs/building.md) and [`CLAUDE.md`](CLAUDE.md) (architecture, conventions, design rules). Every push
is built and tested on Windows x64, Linux x64 and Linux arm64, including end-to-end tests that push real traffic through
all four capture modes; every push to `main` that passes becomes a release. Pull requests welcome; platypuses wearing
fedoras will be viewed with suspicion.

## License

[Apache License 2.0](LICENSE). Keep the [`NOTICE`](NOTICE) file when you redistribute Proxynator. Third-party
components keep their own licenses: WinDivert (LGPLv3/GPLv2, loaded dynamically), Microsoft Detours (MIT), the
system's libbpf (LGPL-2.1/BSD-2-Clause), Avalonia, SkiaSharp, HarfBuzzSharp and the CommunityToolkit (MIT), and the
Inter font (SIL OFL 1.1). The eBPF program is dual-licensed MIT/GPL-2.0, as the kernel requires.
