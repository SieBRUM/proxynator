# Internal names through a pivot

Send everything for `corp.local` through a SOCKS pivot, from every program on the machine, and leave the rest of the
internet alone: `curl http://dc01.corp.local/test.html` goes through the pivot, `curl https://google.com` doesn't.

You choose the names twice: once for **DNS** (which names the pivot resolves) and once for the **traffic** (which
connections go through the pivot).

## In the GUI

1. **Proxies** → **Add proxy**: **ID** `pivot`, **Type** `socks5`, **Host** `127.0.0.1`, **Port** `1080` (your SOCKS
   server or tunnel endpoint).
2. **Settings**:
   - **Capture mode**: `auto` (machine-wide).
   - **DNS mode**: `remote`, **Remote domains**: `*corp.local`.
   - Optional, for Active Directory: tick **Remote DNS server**, **Server address** `10.0.0.10` (a domain
     controller), **Via** `pivot`.
3. **Rules** → **Add**: **Name** `corp.local via the pivot`, **Hosts** `*corp.local`, **Action** `proxy`, **Via**
   `pivot`. Leave **Processes** empty: the rule then applies to every program.
4. **Apply and save**.

## As JSON

[`samples/internal-domain-via-pivot.json`](../../samples/internal-domain-via-pivot.json):

```json
{
  "version": 1,
  "settings": {
    "dns": {
      "mode": "remote",
      "remoteDomains": ["*corp.local"],
      "remoteServer": { "address": "10.0.0.10", "via": "pivot" }
    }
  },
  "proxies": [ { "id": "pivot", "type": "socks5", "host": "127.0.0.1", "port": 1080 } ],
  "rules": [
    { "name": "corp.local via the pivot", "match": { "hosts": ["*corp.local"] }, "action": { "type": "proxy", "target": "pivot" } }
  ]
}
```

## What happens

- **DNS.** Lookups of names matching `remoteDomains` never leave your machine: Proxynator answers them with a
  placeholder address (from `198.18.0.0/15`). When the program connects to that address, Proxynator sends the real
  name to the proxy, which resolves it on the far side. So `dc01.corp.local` works although only the target network
  knows it, and the SOCKS server needs no UDP support. Every other lookup (`google.com`) goes to your normal DNS
  server, untouched. With `remoteServer`, the other lookups for those names (SRV, TXT, MX) go to that DNS server as
  DNS over TCP through the pivot.
- **Traffic.** The rule sends connections to matching names through the pivot. Nothing else matches, so it goes
  direct. It isn't limited to the web: SMB, LDAP or RDP to `dc01.corp.local` match by name too.

`*corp.local` matches `corp.local` itself and every name under it; `*.corp.local` would skip the bare domain.

## Things to know

- **Connections by address** have no name to match (unless they're HTTP or TLS, where Proxynator reads the name).
  `\\10.0.0.5\share` doesn't match; add a rule with **Addresses** `10.0.0.0/8` for that.
- **Programs that do their own DNS** (DNS over HTTPS, `--dns-server` options) skip the placeholder answers. HTTP and
  TLS still match by name; for other tools, use their TCP DNS option against the DC, or addresses.
- **On Windows, remote DNS is machine-wide** for these names (Windows resolves names centrally). That's fine with a
  host-based rule like this one. In the Linux kernel mode and the hooking modes it is per program.
- **Every TCP connection briefly passes through the relay** in the kernel modes: a hostname rule can't know a
  connection's name when it starts, so the relay reads it (DNS mapping, TLS SNI, HTTP Host) and then connects the
  unmatched ones directly. They never touch the proxy.
- **The pivot must be able to resolve the names.** If it can't, see [C2 SOCKS servers and DNS](c2-socks.md#the-pivot-cant-resolve-internal-names).
- `nslookup dc01.corp.local` showing `198.18.x.x` is expected: that's the placeholder.

## Related

- [Active Directory tooling](active-directory.md): NetExec, impacket, BloodHound, Kerberos.
- [Proxy chains](chains.md): a second network behind a second pivot.
