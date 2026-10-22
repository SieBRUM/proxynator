# Troubleshooting

Start with **Diagnostics** in the GUI (or `proxynator doctor`): it checks privileges, the capture driver or eBPF
support, the native parts, the relay, DNS and every proxy, and explains what it finds. **Connections** shows every
connection the relay handled, the rule that matched and the route it took.

## Logs

- **Windows, console:** the service's window; `--verbose` logs every redirected connection.
- **Windows service:** the Windows Application event log.
- **Linux:** `journalctl -u proxynatord` (`-f` to follow). For details, add `--verbose` to `ExecStart` with
  `sudo systemctl edit --full proxynatord`.
- **Hooking modes:** `PROXYNATOR_HOOK_LOG=<file>` before starting a program logs from every hooked process.

## Common problems

| Symptom | Likely cause | What to do |
|---|---|---|
| The GUI says it can't reach proxynatord | The service isn't running, or you may not talk to it. | **Start proxynatord**. Linux: be in the `proxynator` group (log in again after adding yourself). Windows service: run the GUI as Administrator. |
| Capture **FAILED** | Not elevated, driver or native part missing, unsupported kernel. | **Diagnostics** names the reason. Nothing is redirected in this state. |
| A program isn't captured | The rule doesn't match (wrong process name, a launcher starts the real program). | Check the name on **Connections** or in Task Manager / `ps`; use **Include child processes**; on Linux names have no `.exe`. In a hooking mode: was it started through Proxynator? |
| A connection is refused although the rule says proxy | The proxy is down or refused it. Proxynator fails closed. | **Diagnostics** probes every proxy; the service log says why. |
| Internal names don't resolve | Remote DNS is off or the name isn't in `remoteDomains`. | [Internal names through a pivot](guides/internal-domain.md). |
| Works by IP, fails by name through a pivot or C2 | The pivot can't resolve internal names, or the proxy is plain SOCKS4. | [C2 SOCKS servers and DNS](guides/c2-socks.md#common-problems): `resolveNames`, `socks4a`/`socks5`. |
| `nslookup` returns `198.18.x.x` | Remote DNS's placeholder address. | Expected. |
| HTTPS shows certificate errors in Burp setups | The program doesn't trust Burp's CA. | [Trusting Burp's certificate](guides/burp.md#tls-trusting-burps-certificate). |
| Burp shows its own requests twice, or hangs | A rule also matches Burp: a loop. | A `direct` rule for Burp first. |
| A browser bypasses Burp | QUIC (HTTP/3 over UDP). | Keep **QUIC** blocked. |
| Connections through a C2 time out | The implant's check-in interval. | Interactive mode / sleep 0; raise `relay.connectTimeoutMs`. |
| Every connection appears on **Connections** | A rule with only hosts, ports or no criteria: every connection must be looked at. | Expected (unmatched ones connect directly). Add **Processes** to narrow it. |
| `.local` names aren't faked on Linux (`ebpf`) | mDNS (`mdns4_minimal` in `/etc/nsswitch.conf`) resolves `*.local` through Avahi, not DNS. | Use `preload` mode, or remove `mdns4_minimal`. |
| Windows Firewall prompts or blocks | `windivert` mode adds an inbound rule *Proxynator relay* while it runs. | Allow it; it is removed when the service stops. |

## Known limitations

- **UDP** goes through a proxy only in `windivert` mode, through a single SOCKS5 proxy that supports `UDP ASSOCIATE`.
  Otherwise each rule blocks it (default) or sends it direct. Chains can't carry UDP.
- **Remote DNS on Windows is machine-wide** for the listed names: Windows resolves names centrally, so every program
  gets placeholder answers for them. Programs without a proxy rule still work (their connections to placeholders go
  direct through the relay), but keep `remoteDomains` narrow. The DNS cache is flushed when the service starts and
  stops. In the other modes, remote DNS is per program.
- **Hooking modes can be escaped** by programs that bypass the system's socket library: raw system calls, their own
  network stack, Go and static binaries on Linux, setuid programs and `sudo`, Windows processes that only load
  Microsoft-signed DLLs. The kernel modes catch those.
- **Loopback** connections are never redirected.
- **IPv6:** placeholder addresses are IPv4; AAAA lookups of `remoteDomains` get empty answers so programs use IPv4.
- **Not supported:** macOS, and Windows on ARM (WinDivert has no ARM64 driver).
- **Security software** may flag WinDivert, the hook DLL or the preload library. Proxynator doesn't try to evade
  detection; add an exclusion if your policy allows it.

Stopping the service, or a crash, always restores normal networking: the WinDivert handle closes and the eBPF programs
detach with the process.
