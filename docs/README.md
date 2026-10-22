# Proxynator documentation

New here? [Install](installation.md), then follow the [quick start](../README.md#quick-start-gui) or a guide below.
Every guide shows the steps in the GUI and the same setup as JSON; every complete JSON example is checked by the test
suite, so it is valid for the version these docs belong to. Ready-made files are in [`samples/`](../samples).

## Guides

| Guide | For |
|---|---|
| [A program through Burp](guides/burp.md) | Seeing the HTTP(S) traffic of a thick client, a CLI tool or a browser in Burp Suite or mitmproxy. |
| [Internal names through a pivot](guides/internal-domain.md) | Sending only `*corp.local` through a SOCKS pivot, for every program on the machine. |
| [C2 SOCKS servers and DNS](guides/c2-socks.md) | SOCKS servers of C2 frameworks, `ssh -D` and chisel, and the DNS problems that come with them. |
| [Active Directory tooling](guides/active-directory.md) | NetExec, impacket, BloodHound, LDAP and Kerberos through a pivot, including domain controller discovery. |
| [Proxy chains](guides/chains.md) | Networks behind more than one pivot, and combining a pivot with Burp. |
| [Hooking single programs](guides/hooking.md) | Capturing only the programs you start (or attach to), nothing else on the machine. |

## Reference

| Page | Contents |
|---|---|
| [Installation](installation.md) | Packages, starting the service, permissions, running it as a service. |
| [The GUI](gui.md) | Every page of the GUI and how changes are applied. |
| [Configuration](configuration.md) | Every setting of the configuration file. |
| [CLI](cli.md) | The `proxynator` command and `proxynatord`'s options. |
| [Troubleshooting](troubleshooting.md) | Symptoms, causes and fixes; logs; known limitations. |
| [Building](building.md) | Building from source, tests, packages. |

Design decisions are recorded in [`adr/`](adr).
