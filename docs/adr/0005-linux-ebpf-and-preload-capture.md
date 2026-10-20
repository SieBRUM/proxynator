# ADR 0005: Linux capture with eBPF and LD_PRELOAD

- Status: accepted
- Date: 2026-10-20

## Context

Phase 5 brings Proxynator to Linux (Ubuntu 22.04+, Kali rolling). As on Windows there should be a machine-wide mode
that catches programs that ignore proxy settings and escape user-mode hooks (static and Go binaries, raw syscalls),
and a lighter per-program mode for `proxynator run`. The relay, rules, DNS handling and hook protocol already exist
in Core (ADR 0001, 0003, 0004).

## Decision

- **`ebpf` (default)**: one BPF object on the root cgroup v2 (`cgroup/connect4/6`, `sendmsg4/6`, `recvmsg4/6`,
  `sockops`, `tp_btf/sched_process_fork|exec|exit`), loaded with the system libbpf, attached as links owned by the
  service so the kernel detaches them when it exits.
  - **The kernel can't ask the service per connection**, so processes are classified up front into a BPF map:
    *candidate* (a non-direct rule may apply, judging by process criteria) or *ignore*. Fork inherits the
    classification in BPF; exec clears it and notifies the service through a ring buffer; exit removes it.
  - **Relay-first for unknown processes**: a TCP connect from a process the service has not classified yet goes to
    the relay too, which classifies it on the spot (and connects direct if no rule applies). This closes the race
    between exec and classification without blocking in the kernel.
  - The original destination is recorded by socket cookie in `connect4/6` and re-keyed by the source port in
    `sockops` (`TCP_CONNECT_CB`), where the relay looks it up through a new `IOriginalDestinationSource` seam of the
    `OriginalDestinationTable`.
  - UDP is blocked or passed per process (no relaying: unconnected sockets have no stable key the relay could use).
    Remote DNS redirects candidates' UDP/53 (also to the local stub) to a `DnsForwarder`; `recvmsg` restores the
    reply's source address. Remote DNS is therefore per process.
  - No CO-RE beyond two `task_struct` fields; classic tracepoint records are not parsed (their layout changed in 6.x).
- **`preload`**: a C `LD_PRELOAD` library speaking the hook protocol of ADR 0004 over a Unix socket (PID from
  `SO_PEERCRED`), served by the shared `HookRequestHandler`. Children inherit it through the environment.
- **`nftables` is not implemented.** Its design needed moving processes between cgroups; every supported
  distribution has BPF and BTF.
- **Process identity**: rules also match the script an interpreter runs (`ProcessInfo.ScriptPath`), because on
  Linux tools are often scripts (pipx installs `nxc` as a Python script).
- **Packaging**: self-contained build in `/opt/proxynator`, systemd unit (`Type=notify`), conffile
  `/etc/proxynator/config.json`, a `proxynator` group owning the control socket. Nothing starts automatically.

## Consequences

- Linux has the same two-mode choice as Windows, and the hook protocol now has two native clients.
- Rules without process criteria make every process a candidate: all TCP goes through the relay (correct, slower).
- `.local` names resolved through mDNS (Avahi via NSS) can't be faked in `ebpf` mode; `preload` handles them.
- Linux integration tests run for real in CI under sudo and in root containers with BPF.
