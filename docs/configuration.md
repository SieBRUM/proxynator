# Configuration

One JSON file holds everything; the GUI's **Rules**, **Proxies**, **Settings** and **JSON** pages edit the same file.

- Windows: `%ProgramData%\Proxynator\config.json`
- Linux: `/etc/proxynator/config.json`
- Elsewhere: `proxynatord --config <file>`

Comments (`//`) and trailing commas are allowed. The loader is strict: unknown properties, typos and references to
proxies that don't exist are reported with their location (`$.rules[1].action.target: Unknown proxy or chain
'brup'.`), and an invalid configuration is never applied, not even partly. Check a file without the service:
`proxynator config validate my.json`. The JSON schema
[`schema/config.schema.json`](../schema/config.schema.json) gives editors completion and checks (add
`"$schema": "<path>/config.schema.json"`).

A complete example:

```json
{
  "version": 1,
  "settings": {
    "capture": { "mode": "auto" },
    "dns": {
      "mode": "remote",
      "remoteDomains": ["*corp.local"],
      "remoteServer": { "address": "10.0.0.10", "port": 53, "via": "pivot", "resolveNames": false },
      "cacheSeconds": 60
    },
    "udp": { "blockQuic": true },
    "relay": { "connectTimeoutMs": 10000 }
  },
  "proxies": [
    { "id": "pivot", "type": "socks5", "host": "127.0.0.1", "port": 1080, "auth": { "username": "op", "password": "secret" } },
    { "id": "burp", "type": "http", "host": "127.0.0.1", "port": 8080 }
  ],
  "chains": [
    { "id": "pivot-then-burp", "hops": ["pivot", "burp"] }
  ],
  "rules": [
    { "name": "Burp goes direct", "match": { "processes": ["BurpSuite*"] }, "action": { "type": "direct" } },
    { "name": "web app via Burp", "match": { "processes": ["app.exe"], "includeChildren": true, "ports": ["80", "443"] }, "action": { "type": "proxy", "target": "burp" } },
    { "name": "corp.local via the pivot", "match": { "hosts": ["*corp.local"] }, "action": { "type": "proxy", "target": "pivot", "udp": "block" } },
    { "name": "no telemetry", "match": { "hosts": ["*.telemetry.example"] }, "action": { "type": "block" } }
  ]
}
```

## `version`

The configuration format version, currently `1`. Older versions are upgraded automatically when loaded.

## `settings.capture`

| Setting | Default | |
|---|---|---|
| `mode` | `auto` | `auto` (`windivert` on Windows, `ebpf` on Linux), `windivert`, `injection` (Windows), `ebpf`, `preload` (Linux). Changes take effect when the service restarts. |
| `proxyLoopback` | `false` | Reserved: loopback connections are never redirected yet. |

## `settings.dns`

| Setting | Default | |
|---|---|---|
| `mode` | `sniff` | `sniff`: programs resolve names themselves; the proxy gets the name read from the TLS/HTTP request. `local`: the proxy gets the address. `remote`: names in `remoteDomains` get placeholder answers and the proxy resolves them. |
| `remoteDomains` | `["*"]` | The names `remote` mode answers with placeholders (wildcards; `*corp.local` includes `corp.local`). Keep it narrow: everything else uses your normal DNS. |
| `fakeIpRange` | `198.18.0.0/15` | Where placeholder addresses come from (IPv4, at least a /24). Changes take effect when the service restarts. |
| `remoteServer` | none | A DNS server inside the target network: other lookups for `remoteDomains` (SRV, TXT, MX) go there as DNS over TCP. |
| `remoteServer.address` | | Its IP address, e.g. a domain controller. |
| `remoteServer.port` | `53` | |
| `remoteServer.via` | | The proxy or chain that reaches it. |
| `remoteServer.resolveNames` | `false` | Also resolve `remoteDomains` names there and give proxies the address instead of the name: for proxies that can't resolve internal names, and plain SOCKS4 ([details](guides/c2-socks.md#the-pivot-cant-resolve-internal-names)). |
| `sniffTimeoutMs` | `250` | How long the relay waits for a TLS/HTTP request to read the name from (0-10000). |
| `cacheSeconds` | `60` | How long Proxynator reuses the DNS answers it looked up itself: answers from `remoteServer` (SRV, TXT, `resolveNames` addresses) and its own lookups for direct connections and proxy hostnames. `0` turns caching off, `-1` keeps answers until you [clear the cache](#clearing-the-dns-cache) or the service stops, otherwise up to `604800` (a week). Changes apply at once, also to answers already cached. |

Names without a dot, `*.localhost`, reverse lookups and the proxies' own hostnames are never answered with
placeholders.

### Clearing the DNS cache

- **GUI:** **Clear DNS cache** on the **Overview** page, or **Clear DNS cache now** on **Settings**. Tick **also the
  system's** to clear the operating system's cache too.
- **CLI:** `proxynator dns clear-cache` (add `--system` for the operating system's cache).

It takes effect at once, without applying a configuration: new connections look names up again. Failed lookups
are never cached, but answers are: when the target network changes (a host moves, a DNS record is fixed), clear the
cache, or use a short `cacheSeconds`. Placeholder addresses of remote DNS are kept, because open connections and
programs' own caches still use them. The operating system's cache is the Windows DNS client cache, or
systemd-resolved on Linux (`resolvectl flush-caches`).

## `settings.udp`

| Setting | Default | |
|---|---|---|
| `blockQuic` | `true` | Drop UDP/443 of proxied programs, so browsers fall back to TCP, which the proxy can see. |

## `settings.relay`

| Setting | Default | |
|---|---|---|
| `connectTimeoutMs` | `10000` | How long connecting through a proxy (or directly) may take (100-300000). Raise it for C2 SOCKS servers with sleeping implants. |

## `proxies`

| Field | |
|---|---|
| `id` | Unique name (proxies and chains share one namespace), used by rules, chains and `remoteServer.via`. |
| `type` | `socks4` (addresses only), `socks4a`, `socks5`, `http` (`CONNECT`; covers HTTPS, e.g. Burp). |
| `host`, `port` | Where the proxy listens. Connections to it are never redirected. |
| `auth` | Optional `{ "username", "password" }`: SOCKS5 username/password, HTTP Basic, or the SOCKS4 user ID (`username` only). |

## `chains`

| Field | |
|---|---|
| `id` | Unique name. |
| `hops` | Proxy IDs in order: the first is connected to directly, each next through the previous ([guide](guides/chains.md)). |

## `rules`

Evaluated top to bottom for every new connection; the first enabled rule that matches decides. A connection no rule
matches goes direct. Changing rules never affects open connections.

| Field | |
|---|---|
| `name` | Shown in the GUI, `connections` and logs. |
| `enabled` | Default `true`. |
| `match` | The criteria below. All given criteria must match; within a list, any entry may match. An empty `match` matches everything. |
| `action.type` | `proxy`, `direct` or `block` (TCP is reset, UDP dropped). |
| `action.target` | For `proxy`: a proxy or chain ID. |
| `action.udp` | For `proxy`, UDP the route can't carry: `block` (default, fail closed) or `direct`. |

| `match` field | |
|---|---|
| `processes` | Program names (`curl.exe`, `nxc`, `chrome*`) or full paths when the pattern contains a path separator (`C:\Tools\*`, `*/pipx/venvs/netexec/*`). Case-insensitive; `*` and `?` wildcards. Scripts count: `nxc` also matches `python3 nxc`. |
| `includeChildren` | Also match everything started by matching programs, even after they exit. |
| `hosts` | Destination names (`*corp.local`, `api.example.com`). A connection has a name from remote DNS, from the program's own lookups (hooking modes) or from its TLS/HTTP request. |
| `addresses` | Destination addresses and ranges (`10.0.0.0/8`, `192.168.1.10`, `fd00::/8`). |
| `ports` | Destination ports and ranges (`443`, `8000-8100`). |
| `protocols` | `tcp`, `udp`; empty means both. |

## Applying a configuration

- **GUI:** **Apply** (until restart) or **Apply and save**.
- **CLI:** `proxynator config load my.json` (saves it too; `--no-save` doesn't).
- **File:** edit it while the service is stopped. The service reads it at start and refuses to start with an invalid
  one.

In every case the service validates it again and swaps it in one step. New connections use it; open ones keep their
route.
