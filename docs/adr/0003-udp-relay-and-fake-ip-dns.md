# ADR 0003: UDP relay and fake-IP DNS

- Status: accepted
- Date: 2026-10-20

## Context

Phase 3 adds UDP and the `remote` DNS mode. The main use case is reaching internal hosts through a SOCKS pivot with
tools such as NetExec, where names like `dc01.corp.local` cannot be resolved on the analyst's machine.

## Decision

- **UDP follows the TCP design (ADR 0001).**
  - The capture reflects UDP flows to a UDP relay port, using the same NAT key `(B, pa)`.
  - A Core `UdpRelayServer` turns each flow into a session. A session can go direct, through a SOCKS5 UDP ASSOCIATE,
    to the DNS responder, or be dropped.
  - Rules, process lookup and connection tracking are shared with TCP. The UDP relay can be tested on any OS.
- **UDP through a proxy needs a single SOCKS5 hop.**
  - UDP datagrams cannot be tunnelled through a chain of TCP proxies, and HTTP/SOCKS4 proxies cannot carry UDP.
  - In those cases the rule's `udp` setting decides. The default is `block`, so traffic fails closed.
- **QUIC is blocked for proxied apps** (`udp.blockQuic`), so browsers fall back to TCP/TLS, which the proxy can see.
- **Fake-IP DNS lives in the UDP relay**, not in packet-crafting code.
  - The capture redirects UDP/53 in remote mode. The relay answers matching A queries from `FakeIpPool` and forwards
    everything else.
  - It returns empty AAAA/SVCB/HTTPS answers, so clients use the fake IPv4 address and get no real IP hints.
- **Faking is machine-wide but limited by name.** On Windows, the DNS Client service makes queries on behalf of all
  programs, so a query cannot be tied to the program that wanted the answer. To limit the impact:
  - Only names in `remoteDomains` are faked. Proxy hostnames, single-label names and reverse lookups never are.
  - Connections from programs without a proxy rule still work: the relay resolves the real address and connects
    directly.
  - The service resolves names itself with `UpstreamDnsResolver`, which queries the DNS servers directly, so it never
    sees its own fake answers.
  - The DNS cache is flushed on start and stop, and fake answers have a TTL of 10 seconds.
- **Timeout invariant:** a capture NAT entry for a UDP flow must expire before the relay session it feeds.

## Consequences

- With the default `remoteDomains: ["*"]`, every TCP connection on the machine passes through the relay. The
  documentation tells users to narrow it.
- NetExec's own DNS queries over UDP only work through SOCKS servers that support UDP ASSOCIATE. Otherwise users
  need `--dns-tcp` or IP addresses.
- DNS over TCP, DNS servers on loopback and DoH are not intercepted.
