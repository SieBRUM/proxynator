# C2 SOCKS servers and DNS

Most C2 frameworks can open a SOCKS server that tunnels through an implant, and `ssh -D` and chisel do the same over
SSH or HTTP. Pointing tools at them usually works for connections by IP address and breaks on names: DNS through
SOCKS is where these setups get painful. This guide shows the setup and the fixes for the usual DNS problems. Each
problem below is reproduced by an automated test (`C2SocksScenarioTests`) against fake SOCKS servers that behave like
the real ones.

## What these SOCKS servers usually can and can't do

| | Typical C2 SOCKS server, `ssh -D`, chisel |
|---|---|
| TCP connections | Yes |
| Names in the request (SOCKS4a, SOCKS5) | Usually; resolved by the implant's host |
| UDP (`UDP ASSOCIATE`) | Rarely |
| Speed | Bound to the implant's check-in interval |

Check which SOCKS version your listener speaks (most offer SOCKS4a and/or SOCKS5) and use that `type`. Avoid plain
`socks4`: it can't carry names.

Proxynator is built for exactly these limits: it never needs UDP through the proxy for DNS.

- **Lookups of internal names** are answered locally with a placeholder address.
- **The name** goes to the SOCKS server inside the connect request.
- **Domain controller lookups (SRV)** go as DNS over TCP through the tunnel to a DNS server you name.

## Setup

The C2's SOCKS server listens on `127.0.0.1:1080` (on the teamserver, reach it through an SSH tunnel:
`ssh -L 1080:127.0.0.1:1080 operator@teamserver`). The target domain is `corp.local`, a domain controller is
`10.0.0.10`.

### In the GUI

1. **Proxies** → **Add proxy**: **ID** `c2`, **Type** `socks4a` or `socks5` (what your listener speaks), **Host**
   `127.0.0.1`, **Port** `1080`.
2. **Settings** → **DNS mode** `remote`, **Remote domains** `*corp.local`, tick **Remote DNS server**: **Server
   address** `10.0.0.10`, **Via** `c2`. Tick **Also resolve names with this server** if the implant's host can't
   resolve internal names (see below). Set **Proxy connect timeout (ms)** to `60000` for a sleeping implant, and tick **Keep answers until cleared** under
   **DNS cache**, so each name costs one trip through the implant per session.
3. **Rules** → **Add**: **Hosts** `*corp.local`, **Action** `proxy`, **Via** `c2`. **Add** another with **Addresses**
   `10.0.0.0/8` for hosts you use by IP.
4. **Apply and save**, then check **Diagnostics**.

### As JSON

[`samples/c2-socks.json`](../../samples/c2-socks.json):

```json
{
  "version": 1,
  "settings": {
    "dns": {
      "mode": "remote",
      "remoteDomains": ["*corp.local"],
      "remoteServer": { "address": "10.0.0.10", "via": "c2", "resolveNames": true },
      "cacheSeconds": -1
    },
    "relay": { "connectTimeoutMs": 60000 }
  },
  "proxies": [
    { "id": "c2", "type": "socks4a", "host": "127.0.0.1", "port": 1080 }
  ],
  "rules": [
    { "name": "target network via the C2", "match": { "hosts": ["*corp.local"] }, "action": { "type": "proxy", "target": "c2" } },
    { "name": "target ranges via the C2", "match": { "addresses": ["10.0.0.0/8"] }, "action": { "type": "proxy", "target": "c2" } }
  ]
}
```

With `capture.mode` left at `auto`, this covers every program on the machine. To limit it to some tools, add
`"processes"` to the rules, or use a [hooking mode](hooking.md) and start the tools through Proxynator.

`"cacheSeconds": -1` keeps the DNS answers that came through the tunnel until you clear them
(**Clear DNS cache** in the GUI, `proxynator dns clear-cache`), instead of asking again every minute.

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `Name or service not known` for `dc01.corp.local` | Your DNS doesn't know internal names. | Remote DNS for the domain (setup above). |
| DNS through the SOCKS proxy times out (familiar from proxychains) | The SOCKS server has no UDP. | Nothing to do: Proxynator doesn't send DNS over UDP through SOCKS. |
| Works by IP, fails by name, even with remote DNS | The implant's host can't resolve internal names (not domain-joined, or a different DNS server). | `remoteServer.resolveNames` (below). |
| Fails with a `socks4` proxy | Plain SOCKS4 can't carry names; Proxynator refuses rather than sending a wrong address. | Use `socks4a` or `socks5`, or `resolveNames`. **Diagnostics** warns about this. |
| Domain controller discovery fails (`_ldap._tcp.dc._msdcs...`) | SRV lookups need a DNS server in the domain. | `remoteServer` with a DC's address. |
| A tool's own DNS option (`nxc --dns-server`, `bloodhound-python -ns`) times out | It sends UDP DNS straight to the DC, and the SOCKS server has no UDP. | Use its TCP option (`--dns-tcp`), which goes through the tunnel like any TCP connection. |
| Kerberos is slow or fails | UDP 88 can't cross the tunnel, so it is blocked (never sent direct). | Most clients retry over TCP (impacket uses TCP). Windows: force TCP with the `MaxPacketSize=1` Kerberos registry setting. Mind clock skew. |
| Connections time out | The SOCKS server answers only when the implant checks in. | Interactive mode / sleep 0 while tunnelling; raise `relay.connectTimeoutMs`. |
| Every connection waits for a DNS lookup through the tunnel | Answers are cached for only 60 seconds by default, and each lookup costs an implant round trip. | Raise `settings.dns.cacheSeconds`, or `-1` to keep answers for the session; clear them when something changes ([details](../configuration.md#clearing-the-dns-cache)). |
| `nslookup dc01.corp.local` returns `198.18.x.x` | That's the placeholder address; it's correct. | Nothing; connections to it go through the C2 with the real name. |

### The pivot can't resolve internal names

The SOCKS server resolves names on the implant's host, with that host's DNS settings. A Linux box in a DMZ, a
workstation outside the domain or a container often can't resolve `corp.local`, and every connection by name fails
(Proxynator fails closed; nothing leaks direct).

`"resolveNames": true` on the `remoteServer` fixes it. Proxynator asks that DNS server (a domain controller) for the
address, as DNS over TCP through the tunnel, and gives the SOCKS server the address instead of the name. Answers are
kept for `cacheSeconds` (default 60 seconds), so a burst of connections means one lookup. If the DNS server doesn't know the name, the
connection fails. It also makes plain SOCKS4 servers usable with internal names.

### What about UDP?

UDP through SOCKS needs `UDP ASSOCIATE`, which these servers rarely implement. Proxynator only tries it on Windows
(`windivert` mode) with a single SOCKS5 proxy; otherwise, and when the server refuses, UDP that a rule sends to the
proxy is blocked. Set the rule's **UDP** to `direct` only if sending it around the tunnel is acceptable.

## Related

- [Active Directory tooling](active-directory.md) for NetExec, impacket and BloodHound specifics.
- [Proxy chains](chains.md) for a SOCKS server behind another pivot.
- [Troubleshooting](../troubleshooting.md) and **Diagnostics** for everything else.
