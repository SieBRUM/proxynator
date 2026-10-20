# ADR 0001: One shared relay, pluggable capture backends

- Status: accepted
- Date: 2026-10-20

## Context

Proxynator must route traffic from chosen applications through SOCKS4/4a/5 and HTTP `CONNECT` proxies on Windows
now and Linux later. Some applications ignore proxy settings or escape user-mode hooking, so there will be several
ways to capture traffic: kernel-level (WinDivert, eBPF, nftables) and user-mode (DLL injection, `LD_PRELOAD`). The
user chooses which.

## Decision

- All routing logic lives in `Proxynator.Core` and is platform-agnostic. This covers config, rules, proxy
  protocols, chains, hostname sniffing, the relay and connection tracking.
- A capture backend only does two things. It redirects a connection to the local relay, and it registers the
  original destination (plus PID and hostname if known) in `IOriginalDestinationTable`. The key is the client
  endpoint that the relay will see as the peer.
- The relay evaluates rules once per connection, then connects direct, through a proxy route, or resets the client.
  When a proxy fails, the connection fails. It is never silently sent direct.
- Backends call `RuleEngine.RequiresRelay` to decide whether a connection needs the relay at all, so unmatched
  traffic never pays for the relay. Hostname rules count as "maybe" while the hostname is still unknown.
- The default DNS mode is `sniff`: hostnames come from TLS SNI or the HTTP `Host` header. The relay sniffs only
  when the decision is `proxy` or some rule matches on hostnames. If the client sends nothing before the timeout,
  the outstanding read is kept and completed later rather than cancelled, so server-first protocols such as SMTP
  and SSH still work.

## Consequences

- A new platform needs a capture backend, a process-info provider and a privilege checker. Nothing else changes.
- Any feature built into the relay works with every backend.
- The relay is a hop on the data path for proxied connections. The extra cost is one local TCP connection.
