# ADR 0007: DNS through C2 and pivot SOCKS servers

- Status: accepted
- Date: 2026-10-22

## Context

Remote DNS (ADR 0003) answers lookups of internal names with fake addresses and hands the proxy the real name, which
works with any SOCKS4a/SOCKS5/HTTP proxy without UDP. Two situations common with C2 frameworks and pivots broke it:

1. The SOCKS server resolves names on the implant's host, which often can't resolve the target domain's names (not
   domain-joined, a DMZ host, a container). Every connection by name failed.
2. Plain SOCKS4 can't carry names. `Socks4Protocol` then resolved the name locally: on Windows (remote DNS is
   machine-wide) that returned the fake address, which went to the proxy; elsewhere internal names didn't resolve.

## Decision

- **`settings.dns.remoteServer.resolveNames`** (optional, default false). When set, the TCP relay resolves proxied
  connections' remote-domain names with the remote DNS server: an A query as DNS over TCP through `remoteServer.via`,
  the same path SRV lookups already take (`RemoteDnsClient.ResolveAsync`). The proxy then receives the address.
  Answers are cached for 60 seconds per server and name, so a burst of connections costs one lookup. Unknown name or
  unreachable server: the connection fails (closed), never direct.
- **Plain SOCKS4 never resolves a remote-domain name locally.** A name-only target whose route ends in a `socks4` hop
  (and no `resolveNames`) is refused with a log message that names the fixes (`socks4a`/`socks5`, `resolveNames`).
  Earlier hops of a chain still resolve proxy hostnames locally; those are never faked. `doctor` warns about remote
  DNS with routes ending in plain SOCKS4.
- The scenarios (SOCKS5 without UDP, SOCKS4a, plain SOCKS4, pivots that can't resolve, `resolveNames` for SOCKS5,
  SOCKS4 and HTTP, proxied UDP without UDP support) are reproduced against fake proxies in `C2SocksScenarioTests`.

## Consequences

- One option fixes both situations, and the default behaviour (the proxy resolves) is unchanged.
- With `resolveNames`, the proxy sees addresses only, which is what such pivots need; logs and rules still use names.
- The DNS server must be reachable through `via` and know the names: in AD setups, a domain controller.
