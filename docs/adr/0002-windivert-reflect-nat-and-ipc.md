# ADR 0002: WinDivert "reflect" NAT, and gRPC over local IPC

- Status: accepted
- Date: 2026-10-20

## Context

Phase 2 needs a Windows capture backend that redirects TCP connections from unmodified applications to the relay
(ADR 0001), plus a control channel between the privileged service and an unprivileged CLI (and later the GUI).

## Decision

### Capture

- Use WinDivert 2.2 rather than writing a driver. It is signed, and closing its handle (on stop, or when the process
  dies) restores normal packet flow on its own.
- Redirect with the "reflect" NAT from WinDivert's `streamdump` sample, and do not rewrite to loopback:
  - A client packet `A:pa → B:pb` becomes `B:pa → A:relay` and is injected inbound on the same interface.
  - The relay's replies `A:relay → B:pa` become `B:pb → A:pa`.
  - The relay sees the peer `B:pa`. This is both the NAT key and the key in the `OriginalDestinationTable`.
- The relay listens on `[::]` (dual mode) on an ephemeral port, because reflected packets arrive on the client's
  interface address.
  - Windows Firewall would treat these packets as unsolicited inbound traffic, so the service adds an inbound
    allow rule for the relay port while it runs.
  - Packets that really come from the network to the relay port are dropped, so nothing outside the machine can
    use the relay.
- The NAT is pure managed code. It works on a `Span<byte>`, uses no allocations on the per-packet path, and is
  unit-tested on every OS. Only the handle I/O and checksum calculation call WinDivert.
- Each new connection is attributed to a process when it starts:
  - A sniffing SOCKET-layer handle reports which process made each `connect()`.
  - Because those events arrive asynchronously, the TCP table (`GetExtendedTcpTable`) is the fallback.
- Process details are cached by (PID, creation time), so a reused PID is never mistaken for an old process.
  Parent processes are only accepted if they are older than their child.

### Control channel

- Use gRPC with Kestrel and HTTP/2 over a named pipe on Windows and a Unix domain socket elsewhere. It gives a typed,
  versioned contract (`proxynator.v1`), server streaming for `connections --follow`, and clients for every .NET UI.
- Exchange configuration as JSON text, so the file format stays the single source of truth.
- Pipe ACL: SYSTEM, Administrators, and the account running the service.

## Consequences

- Loopback destinations are not redirected (this is not supported yet).
- Two connections from the same client port to the same server on different ports would collide in the NAT key. The
  second one is left alone (passed through).
- Windows-only code paths are verified by CI's elevated Windows job, which runs real `curl.exe` traffic through the
  capture.
- The gRPC stack adds ASP.NET Core to `proxynatord`. This is acceptable for a service; the CLI only needs the client.
