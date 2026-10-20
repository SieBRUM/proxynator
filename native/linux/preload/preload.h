// Proxynator preload library ("preload" capture mode on Linux). Loaded into programs started with
// `proxynator run` through LD_PRELOAD; asks proxynatord over a Unix socket before every connect, like the Windows
// injection hook (native/windows/hook). Inactive unless PROXYNATOR_HOOK_ENDPOINT names the service's hook socket.
#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

// ---- protocol.c: the registration protocol (src/Proxynator.Core/Hooking/HookProtocol.cs; keep in sync) ----------

#define PN_PROTOCOL_VERSION 1
#define PN_MAX_BODY 1024
#define PN_MAX_HOSTNAME 255

enum pn_type { PN_HELLO = 1, PN_CONNECT = 2, PN_RESOLVE = 3 };
enum pn_verdict { PN_DIRECT = 0, PN_RELAY = 1, PN_BLOCK = 2 };
enum pn_transport { PN_TCP = 6, PN_UDP = 17 };

// A socket address in protocol form; port in host byte order.
struct pn_endpoint {
    uint8_t family; // 4 or 6
    uint8_t address[16];
    uint32_t scope_id;
    uint16_t port;
};

struct pn_writer {
    uint8_t frame[4 + PN_MAX_BODY];
    size_t length; // of the body
    bool ok;
};

void pn_writer_init(struct pn_writer *writer, enum pn_type type);
void pn_write_u8(struct pn_writer *writer, uint8_t value);
void pn_write_endpoint(struct pn_writer *writer, const struct pn_endpoint *endpoint);
void pn_write_string(struct pn_writer *writer, const char *utf8);
size_t pn_frame_length(const struct pn_writer *writer);

struct pn_reader {
    const uint8_t *data;
    size_t length;
    size_t position;
};

bool pn_read_header(struct pn_reader *reader, enum pn_type expected);
bool pn_read_u8(struct pn_reader *reader, uint8_t *value);
bool pn_read_bytes(struct pn_reader *reader, void *data, size_t length);
bool pn_read_endpoint(struct pn_reader *reader, struct pn_endpoint *endpoint);

bool pn_endpoint_from_sockaddr(const struct sockaddr *address, socklen_t length, struct pn_endpoint *endpoint);
// Converts to a socket address of the family; IPv4 becomes IPv4-mapped for AF_INET6.
bool pn_endpoint_to_sockaddr(const struct pn_endpoint *endpoint, int family, struct sockaddr_storage *address, socklen_t *length);
bool pn_endpoint_is_loopback(const struct pn_endpoint *endpoint);
bool pn_endpoint_is_unspecified(const struct pn_endpoint *endpoint);

// ---- client.c: the connection to proxynatord ----------------------------------------------------------------------

struct pn_connect_answer {
    enum pn_verdict verdict;
    struct pn_endpoint relay;
};

// False when the service cannot be reached; callers then fail closed (connect) or resolve normally (names).
bool pn_query_connect(enum pn_transport transport, const struct pn_endpoint *local, const struct pn_endpoint *remote,
                      const char *hostname, struct pn_connect_answer *answer);
bool pn_query_resolve(const char *hostname, bool *faked, uint8_t address[4]);
void pn_client_init(const char *socket_path);
void pn_client_after_fork(void);

// ---- caches.c -----------------------------------------------------------------------------------------------------

void pn_remember_hostname(const struct sockaddr *address, const char *name);
bool pn_lookup_hostname(const struct sockaddr *address, socklen_t length, char *buffer, size_t size);
void pn_remember_peer(int fd, const struct sockaddr *address, socklen_t length);
bool pn_lookup_peer(int fd, struct sockaddr_storage *address, socklen_t *length);
void pn_forget_peer(int fd);
// UDP verdicts per destination, cached for 30 s.
bool pn_cached_udp_verdict(const struct pn_endpoint *remote, enum pn_verdict *verdict);
void pn_cache_udp_verdict(const struct pn_endpoint *remote, enum pn_verdict verdict);
void pn_caches_after_fork(void);

// ---- log.c --------------------------------------------------------------------------------------------------------

void pn_log_init(void);
void pn_log(const char *format, ...) __attribute__((format(printf, 1, 2)));

// ---- hooks.c: the real libc functions ------------------------------------------------------------------------------

int pn_real_connect(int fd, const struct sockaddr *address, socklen_t length);
int pn_real_close(int fd);
