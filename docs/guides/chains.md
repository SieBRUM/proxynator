# Proxy chains

A chain goes through several proxies in order: Proxynator connects to the first directly, asks it for a connection to
the second, and so on; the last one connects to the destination. Use it for a network behind more than one pivot.
Every hop can be SOCKS4/4a/5 or HTTP `CONNECT`, with its own credentials; the destination's name goes to the last hop.

## Two pivots

`ssh -D 1080 user@dmz-host` gives you a SOCKS server into the DMZ. From there, a second SOCKS server at
`172.16.20.5:1080` reaches the production network. `*prod.internal` should go through both, `*corp.local` only
through the first.

### In the GUI

1. **Proxies** → **Add proxy** `dmz` (`socks5`, `127.0.0.1`, `1080`) and `prod` (`socks5`, `172.16.20.5`, `1080`,
   with **Username** and **Password** if it needs them). `prod`'s address is the one the DMZ host uses; **Test
   connection** can't reach it from your machine, that's expected.
2. **Chains** → **Add chain**: **ID** `dmz-then-prod`, **Hops** `dmz, prod`.
3. **Settings** → **DNS mode** `remote`, **Remote domains** `*corp.local, *prod.internal`.
4. **Rules**: **Hosts** `*prod.internal` → **Via** `dmz-then-prod`; **Hosts** `*corp.local` → **Via** `dmz`.
5. **Apply and save**.

### As JSON

[`samples/two-pivots.json`](../../samples/two-pivots.json):

```json
{
  "version": 1,
  "settings": { "dns": { "mode": "remote", "remoteDomains": ["*corp.local", "*prod.internal"] } },
  "proxies": [
    { "id": "dmz", "type": "socks5", "host": "127.0.0.1", "port": 1080 },
    { "id": "prod", "type": "socks5", "host": "172.16.20.5", "port": 1080, "auth": { "username": "op", "password": "change-me" } }
  ],
  "chains": [ { "id": "dmz-then-prod", "hops": ["dmz", "prod"] } ],
  "rules": [
    { "name": "production network through both pivots", "match": { "hosts": ["*prod.internal"] }, "action": { "type": "proxy", "target": "dmz-then-prod" } },
    { "name": "corp network through the first pivot", "match": { "hosts": ["*corp.local"] }, "action": { "type": "proxy", "target": "dmz" } }
  ]
}
```

UDP can't cross a chain (each hop is a TCP tunnel): rules through a chain block UDP, or send it direct with **UDP**
`direct`.

## Burp behind a pivot

To inspect web applications inside the target network with Burp, let Proxynator send the browser (or tool) to Burp, and
let **Burp** use the pivot as its upstream proxy:

1. In Proxynator: a rule that sends the program to Burp ([guide](burp.md)). Keep the DNS mode `sniff` or `remote`, so
   Burp receives hostnames.
2. In Burp: *Settings → Network → Connections → SOCKS proxy*: the pivot's host and port, and tick *Do DNS lookups over
   SOCKS proxy*, so the pivot resolves the internal names.

A chain `[burp, pivot]` would hand Burp a SOCKS tunnel it can't read, and `[pivot, burp]` would need Burp to run on
the far side, so neither is what you want here.

## Related

- [C2 SOCKS servers and DNS](c2-socks.md): a C2 server can be any hop of a chain.
- [Configuration](../configuration.md#chains).
