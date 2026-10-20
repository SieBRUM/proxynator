// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// Proxynator's kernel-level capture for Linux ("ebpf" mode). Attached to the root cgroup (v2), so it sees every
// socket on the machine. proxynatord (Proxynator.Platform.Linux, BpfCaptureBackend) loads it, fills the maps and
// owns the links: when the service exits, the kernel detaches everything and networking is back to normal.
//
// TCP: connect() of a candidate process is rewritten to the local relay; the original destination is recorded by
//      socket cookie, then (once the source port is known, in sockops) by local port, where the relay looks it up.
//      Processes the service has not classified yet also go to the relay, which decides and classifies them, so a
//      process can never slip past before the service knows it.
// UDP: not relayed; candidates' datagrams are blocked or passed per their rules. In remote DNS mode their DNS
//      queries go to the service's DNS forwarder, and recvmsg() makes replies look like they came from the server
//      the program asked.
// Processes: fork copies the parent's classification, exec clears it and tells the service (ring buffer), exit
//      removes it.
//
// Only stable UAPI context fields are used (no CO-RE), so one object works on every supported kernel.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

// Classification of a process (value of the "decisions" map), set by the service.
#define DECISION_TARGET 1         // connections may need the relay
#define DECISION_IGNORE 2         // no rule can apply: leave it alone
#define DECISION_UDP_BLOCK_QUIC 4 // drop UDP to port 443
#define DECISION_UDP_BLOCK 8      // drop other UDP (not to loopback)
#define DECISION_DNS_REDIRECT 16  // send DNS queries (UDP 53) to the service's forwarder

// Ports are in network byte order. A zero port means "not available".
struct config {
    __u32 service_tgid;
    __u16 relay4_port;
    __u16 relay6_port;
    __u16 dns4_port;
    __u16 dns6_port;
};

// Addresses are stored as IPv6; IPv4 as ::ffff:a.b.c.d.
struct origin {
    __u32 tgid;
    __u16 family; // of the original destination as given to connect()
    __u16 port;   // network byte order
    __u32 addr[4];
};

struct endpoint_key {
    __u32 addr[4];
    __u16 port; // network byte order
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // tgid
    __type(value, __u32);
} decisions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); // socket cookie
    __type(value, struct origin);
} cookies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); // local port of the client socket, host byte order
    __type(value, struct origin);
} ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); // socket cookie
    __type(value, struct origin);
} dns_peers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct endpoint_key);
    __type(value, __u8);
} excluded SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline struct config *get_config(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&config, &zero);
}

static __always_inline __u32 current_tgid(void)
{
    return bpf_get_current_pid_tgid() >> 32;
}

static __always_inline int is_v4_mapped(const __u32 *addr)
{
    return addr[0] == 0 && addr[1] == 0 && addr[2] == bpf_htonl(0xffff);
}

static __always_inline int is_local_or_unspecified(const __u32 *addr)
{
    if (is_v4_mapped(addr)) {
        __u32 v4 = bpf_ntohl(addr[3]);
        return (v4 >> 24) == 127 || v4 == 0;
    }
    if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0) {
        return addr[3] == 0 || addr[3] == bpf_htonl(1); // :: or ::1
    }
    return 0;
}

static __always_inline int is_excluded(const struct origin *o)
{
    struct endpoint_key key = {};
    key.addr[0] = o->addr[0];
    key.addr[1] = o->addr[1];
    key.addr[2] = o->addr[2];
    key.addr[3] = o->addr[3];
    key.port = o->port;
    return bpf_map_lookup_elem(&excluded, &key) != 0;
}

static __always_inline __u32 decision_of(__u32 tgid)
{
    __u32 *d = bpf_map_lookup_elem(&decisions, &tgid);
    return d ? *d : 0;
}

// TCP: should this connect() go to the relay? Records the original destination when it should.
static __always_inline int redirect_tcp(void *ctx, const struct config *cfg, struct origin *o)
{
    if (o->tgid == cfg->service_tgid || is_local_or_unspecified(o->addr) || is_excluded(o)) {
        return 0;
    }
    if (decision_of(o->tgid) & DECISION_IGNORE) {
        return 0;
    }
    __u64 cookie = bpf_get_socket_cookie(ctx);
    bpf_map_update_elem(&cookies, &cookie, o, BPF_ANY);
    return 1;
}

#define UDP_PASS 0
#define UDP_BLOCK 1
#define UDP_DNS 2

static __always_inline int udp_action(const struct config *cfg, const struct origin *o)
{
    if (o->tgid == cfg->service_tgid) {
        return UDP_PASS;
    }
    __u32 decision = decision_of(o->tgid);
    if (!(decision & DECISION_TARGET)) {
        return UDP_PASS;
    }
    __u16 port = bpf_ntohs(o->port);
    if (port == 53 && (decision & DECISION_DNS_REDIRECT)) {
        return UDP_DNS;
    }
    if (is_local_or_unspecified(o->addr) || is_excluded(o)) {
        return UDP_PASS;
    }
    if (port == 443) {
        return (decision & DECISION_UDP_BLOCK_QUIC) ? UDP_BLOCK : UDP_PASS;
    }
    return (decision & DECISION_UDP_BLOCK) ? UDP_BLOCK : UDP_PASS;
}

static __always_inline void origin_v4(struct origin *o, __u32 ip, __u32 port)
{
    o->tgid = current_tgid();
    o->family = AF_INET;
    o->port = (__u16)port;
    o->addr[0] = 0;
    o->addr[1] = 0;
    o->addr[2] = bpf_htonl(0xffff);
    o->addr[3] = ip;
}

static __always_inline void origin_v6(struct origin *o, struct bpf_sock_addr *ctx)
{
    o->tgid = current_tgid();
    o->family = AF_INET6;
    o->port = (__u16)ctx->user_port;
    o->addr[0] = ctx->user_ip6[0];
    o->addr[1] = ctx->user_ip6[1];
    o->addr[2] = ctx->user_ip6[2];
    o->addr[3] = ctx->user_ip6[3];
}

static __always_inline void set_v6(struct bpf_sock_addr *ctx, int mapped_loopback, __u16 port)
{
    if (mapped_loopback) {
        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = bpf_htonl(0xffff);
        ctx->user_ip6[3] = bpf_htonl(0x7f000001);
    } else {
        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = 0;
        ctx->user_ip6[3] = bpf_htonl(1);
    }
    ctx->user_port = port;
}

// Shared by connect4 and sendmsg4: 1 = allow, 0 = deny (EPERM).
static __always_inline int udp4(struct bpf_sock_addr *ctx, const struct config *cfg)
{
    struct origin o = {};
    origin_v4(&o, ctx->user_ip4, ctx->user_port);
    switch (udp_action(cfg, &o)) {
    case UDP_BLOCK:
        return 0;
    case UDP_DNS:
        if (cfg->dns4_port) {
            __u64 cookie = bpf_get_socket_cookie(ctx);
            bpf_map_update_elem(&dns_peers, &cookie, &o, BPF_ANY);
            ctx->user_ip4 = bpf_htonl(0x7f000001);
            ctx->user_port = cfg->dns4_port;
        }
        return 1;
    default:
        return 1;
    }
}

static __always_inline int udp6(struct bpf_sock_addr *ctx, const struct config *cfg)
{
    struct origin o = {};
    origin_v6(&o, ctx);
    switch (udp_action(cfg, &o)) {
    case UDP_BLOCK:
        return 0;
    case UDP_DNS: {
        int mapped = is_v4_mapped(o.addr);
        __u16 port = mapped ? cfg->dns4_port : cfg->dns6_port;
        if (port) {
            __u64 cookie = bpf_get_socket_cookie(ctx);
            bpf_map_update_elem(&dns_peers, &cookie, &o, BPF_ANY);
            set_v6(ctx, mapped, port);
        }
        return 1;
    }
    default:
        return 1;
    }
}

SEC("cgroup/connect4")
int proxynator_connect4(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    if (!cfg || !cfg->relay4_port) {
        return 1;
    }
    if (ctx->type == SOCK_DGRAM) {
        return udp4(ctx, cfg);
    }
    if (ctx->type != SOCK_STREAM) {
        return 1;
    }
    struct origin o = {};
    origin_v4(&o, ctx->user_ip4, ctx->user_port);
    if (redirect_tcp(ctx, cfg, &o)) {
        ctx->user_ip4 = bpf_htonl(0x7f000001);
        ctx->user_port = cfg->relay4_port;
    }
    return 1;
}

SEC("cgroup/connect6")
int proxynator_connect6(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    if (!cfg || !cfg->relay4_port) {
        return 1;
    }
    if (ctx->type == SOCK_DGRAM) {
        return udp6(ctx, cfg);
    }
    if (ctx->type != SOCK_STREAM) {
        return 1;
    }
    struct origin o = {};
    origin_v6(&o, ctx);
    int mapped = is_v4_mapped(o.addr);
    __u16 port = mapped ? cfg->relay4_port : cfg->relay6_port;
    if (port && redirect_tcp(ctx, cfg, &o)) {
        set_v6(ctx, mapped, port);
    }
    return 1;
}

SEC("cgroup/sendmsg4")
int proxynator_sendmsg4(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    return cfg && cfg->relay4_port ? udp4(ctx, cfg) : 1;
}

SEC("cgroup/sendmsg6")
int proxynator_sendmsg6(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    return cfg && cfg->relay4_port ? udp6(ctx, cfg) : 1;
}

// Replies from the DNS forwarder appear to come from the server the program sent its query to.
SEC("cgroup/recvmsg4")
int proxynator_recvmsg4(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    if (!cfg || !cfg->dns4_port || ctx->user_port != cfg->dns4_port || ctx->user_ip4 != bpf_htonl(0x7f000001)) {
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct origin *o = bpf_map_lookup_elem(&dns_peers, &cookie);
    if (o && is_v4_mapped(o->addr)) {
        ctx->user_ip4 = o->addr[3];
        ctx->user_port = o->port;
    }
    return 1;
}

SEC("cgroup/recvmsg6")
int proxynator_recvmsg6(struct bpf_sock_addr *ctx)
{
    struct config *cfg = get_config();
    if (!cfg) {
        return 1;
    }
    __u32 port = ctx->user_port;
    int from_dns4 = cfg->dns4_port && port == cfg->dns4_port && ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
                    ctx->user_ip6[2] == bpf_htonl(0xffff) && ctx->user_ip6[3] == bpf_htonl(0x7f000001);
    int from_dns6 = cfg->dns6_port && port == cfg->dns6_port && ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
                    ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1);
    if (!from_dns4 && !from_dns6) {
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct origin *o = bpf_map_lookup_elem(&dns_peers, &cookie);
    if (o) {
        ctx->user_ip6[0] = o->addr[0];
        ctx->user_ip6[1] = o->addr[1];
        ctx->user_ip6[2] = o->addr[2];
        ctx->user_ip6[3] = o->addr[3];
        ctx->user_port = o->port;
    }
    return 1;
}

// The source port is known when the SYN is about to be sent: re-key the original destination by it.
SEC("sockops")
int proxynator_sockops(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB) {
        return 1;
    }
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct origin *o = bpf_map_lookup_elem(&cookies, &cookie);
    if (o) {
        __u32 port = skops->local_port;
        bpf_map_update_elem(&ports, &port, o, BPF_ANY);
        bpf_map_delete_elem(&cookies, &cookie);
    }
    return 1;
}

// BTF-enabled tracepoints (kernel BTF is required; Ubuntu and Kali ship it). Only the two task_struct fields used
// are declared: libbpf relocates them against the running kernel (CO-RE), so no vmlinux.h is needed.
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

SEC("tp_btf/sched_process_fork")
int BPF_PROG(proxynator_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 parent_tgid = parent->tgid;
    __u32 child_tgid = child->tgid;
    if (child->pid != child_tgid) {
        return 0; // a new thread, not a new process
    }
    __u32 *d = bpf_map_lookup_elem(&decisions, &parent_tgid);
    if (d) {
        __u32 value = *d;
        bpf_map_update_elem(&decisions, &child_tgid, &value, BPF_ANY);
    } else {
        bpf_map_delete_elem(&decisions, &child_tgid);
    }
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(proxynator_exec)
{
    __u32 tgid = current_tgid();
    bpf_map_delete_elem(&decisions, &tgid);
    __u32 *event = bpf_ringbuf_reserve(&events, sizeof(__u32), 0);
    if (event) {
        *event = tgid;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(proxynator_exit)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if ((__u32)id == tgid) {
        bpf_map_delete_elem(&decisions, &tgid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
