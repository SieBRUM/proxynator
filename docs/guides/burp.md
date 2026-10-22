# A program through Burp

See the HTTP(S) traffic of a program that ignores proxy settings (a thick client, a CLI tool, an updater) in Burp
Suite, mitmproxy or any HTTP proxy. Proxynator redirects the program's connections to Burp as `CONNECT host:port`
requests, so Burp sees the real hostname even though the program never asked for a proxy.

## In the GUI

1. **Proxies** → **Add Burp (127.0.0.1:8080)**. Change the port if your Burp listener uses another one, and use **Test
   connection** with Burp running.
2. **Rules** → **Add**:
   - **Name**: `thick client via Burp`
   - **Processes**: `thickclient.exe` (on Linux without `.exe`). Tick **Include child processes** to also catch its
     helpers, updaters and embedded browsers.
   - **Ports** (optional): `80, 443` to send only web traffic to Burp.
   - **Action**: `proxy`, **Via**: `burp`
3. **Settings**: keep **QUIC** blocked, so the program uses TLS over TCP, which Burp can see.
4. **Apply and save**, start the program, and watch **Connections** and Burp's HTTP history.

## As JSON

[`samples/burp-one-app.json`](../../samples/burp-one-app.json):

```json
{
  "version": 1,
  "settings": {
    "capture": { "mode": "auto" },
    "udp": { "blockQuic": true }
  },
  "proxies": [
    { "id": "burp", "type": "http", "host": "127.0.0.1", "port": 8080 }
  ],
  "rules": [
    {
      "name": "thick client via Burp",
      "match": { "processes": ["thickclient.exe", "thickclient"], "includeChildren": true },
      "action": { "type": "proxy", "target": "burp" }
    }
  ]
}
```

## Whole browsers

Browsers have proxy settings, but extensions, sandboxed helpers and DoH can get in the way.
[`samples/browser-to-burp.json`](../../samples/browser-to-burp.json) sends the web traffic of Firefox, Chrome and Edge
to Burp, with a first rule that keeps Burp's own connections direct.

**Don't proxy Burp itself.** A rule that would also match Burp (a catch-all, or `java*` when Burp runs on Java) sends
Burp's upstream connections back into Burp: a loop. Put a `direct` rule for Burp first. Connections *to* the configured
proxies are never redirected, so this only concerns rules that match Burp's own connections elsewhere.

## TLS: trusting Burp's certificate

Proxynator only routes traffic; Burp does the TLS interception, so the program must trust Burp's CA certificate
(Burp: *Proxy → Proxy settings → Import / export CA certificate*):

- **Windows programs** using the system store: import it into *Trusted Root Certification Authorities*
  (`certmgr.msc`, or `certutil -addstore -user Root burp.der`).
- **Linux**: `sudo cp burp.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
- **Python** (`requests`, httpx) uses its own bundle (certifi): set `REQUESTS_CA_BUNDLE` (and `SSL_CERT_FILE`) to a PEM
  file containing Burp's CA.
- **Java** uses its own keystore: `keytool -importcert -cacerts -file burp.der`.
- **Node.js**: `NODE_EXTRA_CA_CERTS=/path/burp.pem`.
- Programs that **pin** certificates fail the handshake; the traffic still reaches Burp, but you'll need to bypass
  the pinning to read it.

## Non-HTTP traffic

Burp only understands HTTP(S) inside a `CONNECT` tunnel. Send other protocols (SMB, LDAP, databases, custom TCP)
direct or through a SOCKS proxy with a second rule, for example by port, or limit the Burp rule to **Ports** `80, 443`.

## Related

- [Proxy chains](chains.md) for Burp behind a pivot.
- [Hooking single programs](hooking.md) to capture only programs you start.
