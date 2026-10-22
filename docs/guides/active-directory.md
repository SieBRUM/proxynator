# Active Directory tooling

Run NetExec, impacket, BloodHound collectors, `ldapsearch`, Kerberos tools or Windows' own AD tools against a domain
behind a pivot. This builds on [Internal names through a pivot](internal-domain.md) and, for C2 SOCKS servers,
[C2 SOCKS servers and DNS](c2-socks.md).

Active Directory tools need:

- **SOCKS, not Burp:** they speak SMB, LDAP, Kerberos, MSRPC and friends, not HTTP. Burp only understands HTTP(S)
  inside a `CONNECT` tunnel.
- **Names:** Kerberos works with hostnames (`dc01.corp.local`), which only the domain's DNS knows. Remote DNS handles
  that.
- **Domain controller discovery:** tools find DCs with SRV lookups (`_ldap._tcp.dc._msdcs.corp.local`). With
  `remoteServer` those go to a domain controller, through the pivot, as DNS over TCP.

LDAP (389), LDAPS (636), the global catalog (3268/3269), SMB (445), Kerberos over TCP (88), WinRM and RDP are ordinary
TCP and work in every capture mode. The test suite runs real LDAP clients through all four modes to a stand-in domain
controller behind a SOCKS proxy.

## In the GUI

1. **Proxies** → **Add proxy** `pivot`, `socks5`, `127.0.0.1`, `1080`.
2. **Settings** → **DNS mode** `remote`, **Remote domains** `corp.local, *.corp.local`, **Remote DNS server**:
   **Server address** = a DC's IP, **Via** `pivot`.
3. **Rules** → **Add**: **Processes** `nxc.exe, netexec.exe` (Windows) or `nxc, netexec` (Linux), tick **Include child
   processes**, **Action** `proxy`, **Via** `pivot`. Or use **Hosts** `*corp.local` to cover every tool at once.
4. **Apply and save**.

## As JSON (Windows)

Based on [`samples/netexec-socks-pivot.json`](../../samples/netexec-socks-pivot.json):

```json
{
  "version": 1,
  "settings": {
    "dns": {
      "mode": "remote",
      "remoteDomains": ["corp.local", "*.corp.local"],
      "remoteServer": { "address": "10.0.0.10", "via": "pivot" }
    }
  },
  "proxies": [ { "id": "pivot", "type": "socks5", "host": "127.0.0.1", "port": 1080 } ],
  "rules": [
    {
      "name": "NetExec through the pivot",
      "match": { "processes": ["nxc.exe", "netexec.exe", "nxcdb.exe"], "includeChildren": true },
      "action": { "type": "proxy", "target": "pivot", "udp": "block" }
    }
  ]
}
```

On Linux see [`samples/linux-pivot.json`](../../samples/linux-pivot.json) (NetExec, impacket and roadtools).

## Matching Python tools

- **Windows (pipx):** `nxc.exe` is a small launcher that starts the venv's `python.exe`, which starts the real
  interpreter. Match the launcher with **Include child processes**; this keeps working after the launcher exits.
  Don't match plain `python.exe` unless you want every Python program proxied.
- **Linux (pipx):** tools are Python scripts and the process is named after the script: `nxc` matches. So does
  `python3 /path/to/nxc` (the script an interpreter runs counts). Paths work too: `*/pipx/venvs/impacket/*`.
- **Or skip matching:** in a [hooking mode](hooking.md), `proxynator run -- nxc smb dc01.corp.local ...` (or the GUI's
  hooked terminal) captures the tool and everything it starts, no process names needed.

## Per tool

- **NetExec:** `nxc smb dc01.corp.local -u alice -p 'Passw0rd!'` works by name. For its own DNS queries
  (`--dns-server`), add `--dns-tcp`: UDP DNS can't cross most SOCKS servers.
- **impacket:** use names (`corp.local/alice@dc01.corp.local`); `-dc-ip` with an address works too. Kerberos uses
  TCP.
- **BloodHound (bloodhound-python / bloodhound-ce-python):** `-ns 10.0.0.10 --dns-tcp`, or rely on remote DNS and
  `remoteServer` without `-ns`.
- **ldapsearch / LDAP browsers:** `ldap://dc01.corp.local` or `ldaps://` by name.
- **Windows tools** (RSAT, PowerView, `runas /netonly`): remote DNS on Windows is machine-wide for the listed names, so
  domain lookups and SRV discovery work from any program. A rule with **Hosts** `*corp.local` covers them all.
- **Kerberos:** keep your clock within five minutes of the DC's (`faketime`, or sync your clock to the DC). Windows'
  Kerberos tries UDP first; through a pivot without UDP it falls back to TCP. Forcing TCP (`MaxPacketSize=1` under
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters`) saves the retry.

## When names don't resolve

If tools fail by name but work by IP, the pivot host probably can't resolve the domain's names. Set
`"resolveNames": true` on the `remoteServer`, which resolves through the DC instead
([details](c2-socks.md#the-pivot-cant-resolve-internal-names)). Also check:

- **Diagnostics** shows any warnings.
- **Connections** shows which rule and route each connection took.
