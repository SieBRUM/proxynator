// The hooked libc functions. Every TCP connect is decided by proxynatord (direct, relay or block); UDP sends are
// checked (direct or block; UDP is not relayed in this mode); name lookups give fake addresses in remote DNS mode
// and remember hostnames as hints otherwise. Programs that do not use libc for networking (static binaries, Go)
// are not affected; use the ebpf mode for those.
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "preload.h"

#define EXPORT __attribute__((visibility("default")))

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*close_fn)(int);
typedef int (*getpeername_fn)(int, struct sockaddr *, socklen_t *);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef int (*sendmmsg_fn)(int, struct mmsghdr *, unsigned int, int);
typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
typedef struct hostent *(*gethostbyname_fn)(const char *);

static connect_fn real_connect;
static close_fn real_close;
static getpeername_fn real_getpeername;
static sendto_fn real_sendto;
static sendmsg_fn real_sendmsg;
static sendmmsg_fn real_sendmmsg;
static getaddrinfo_fn real_getaddrinfo;
static gethostbyname_fn real_gethostbyname;

static bool active;
static __thread int depth;

static void resolve_real(void)
{
    real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
    real_close = (close_fn)dlsym(RTLD_NEXT, "close");
    real_getpeername = (getpeername_fn)dlsym(RTLD_NEXT, "getpeername");
    real_sendto = (sendto_fn)dlsym(RTLD_NEXT, "sendto");
    real_sendmsg = (sendmsg_fn)dlsym(RTLD_NEXT, "sendmsg");
    real_sendmmsg = (sendmmsg_fn)dlsym(RTLD_NEXT, "sendmmsg");
    real_getaddrinfo = (getaddrinfo_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    real_gethostbyname = (gethostbyname_fn)dlsym(RTLD_NEXT, "gethostbyname");
}

static void after_fork_in_child(void)
{
    pn_client_after_fork();
    pn_caches_after_fork();
}

__attribute__((constructor)) static void initialize(void)
{
    resolve_real();
    const char *endpoint = getenv("PROXYNATOR_HOOK_ENDPOINT");
    if (endpoint == NULL || *endpoint == '\0' || real_connect == NULL || real_close == NULL) {
        return;
    }
    pn_log_init();
    pn_client_init(endpoint);
    pthread_atfork(NULL, NULL, after_fork_in_child);
    active = true;
    pn_log("loaded; proxynatord at %s", endpoint);
}

int pn_real_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (real_connect == NULL) {
        resolve_real();
    }
    return real_connect(fd, address, length);
}

int pn_real_close(int fd)
{
    if (real_close == NULL) {
        resolve_real();
    }
    return real_close(fd);
}

static int socket_type(int fd)
{
    int type = 0;
    socklen_t length = sizeof(type);
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 ? type : 0;
}

// The endpoint the socket will connect to the relay from (the key the relay looks the destination up by). Unbound
// sockets are bound to the wildcard address first, so a "direct" answer still works; a wildcard-bound socket
// connects to the loopback relay from the loopback address.
static bool local_endpoint_for_relay(int fd, int family, struct pn_endpoint *local)
{
    struct sockaddr_storage bound;
    socklen_t length = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &length) != 0 || !pn_endpoint_from_sockaddr((struct sockaddr *)&bound, length, local)) {
        return false;
    }
    if (local->port == 0) {
        struct sockaddr_storage any;
        memset(&any, 0, sizeof(any));
        any.ss_family = (sa_family_t)family;
        socklen_t any_length = family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
        length = sizeof(bound);
        if (bind(fd, (struct sockaddr *)&any, any_length) != 0 || getsockname(fd, (struct sockaddr *)&bound, &length) != 0 ||
            !pn_endpoint_from_sockaddr((struct sockaddr *)&bound, length, local)) {
            return false;
        }
    }
    if (pn_endpoint_is_unspecified(local)) {
        uint16_t port = local->port;
        memset(local->address, 0, sizeof(local->address));
        if (local->family == 4) {
            local->address[0] = 127;
            local->address[3] = 1;
        } else {
            local->address[15] = 1;
        }
        local->scope_id = 0;
        local->port = port;
    }
    return true;
}

static enum pn_verdict decide_tcp(int fd, const struct sockaddr *address, socklen_t length, struct sockaddr_storage *relay, socklen_t *relay_length)
{
    struct pn_endpoint remote;
    if (!pn_endpoint_from_sockaddr(address, length, &remote) || pn_endpoint_is_loopback(&remote) || pn_endpoint_is_unspecified(&remote)) {
        return PN_DIRECT;
    }
    struct pn_endpoint local;
    if (!local_endpoint_for_relay(fd, address->sa_family, &local)) {
        pn_log("cannot bind a socket before redirecting it (errno %d); refusing the connection", errno);
        return PN_BLOCK;
    }
    char hostname[PN_MAX_HOSTNAME + 1];
    bool has_hostname = pn_lookup_hostname(address, length, hostname, sizeof(hostname));
    struct pn_connect_answer answer;
    if (!pn_query_connect(PN_TCP, &local, &remote, has_hostname ? hostname : NULL, &answer)) {
        return PN_BLOCK; // fail closed
    }
    if (answer.verdict == PN_RELAY && !pn_endpoint_to_sockaddr(&answer.relay, address->sa_family, relay, relay_length)) {
        return PN_BLOCK;
    }
    return answer.verdict;
}

static enum pn_verdict decide_udp(const struct sockaddr *address, socklen_t length)
{
    struct pn_endpoint remote;
    if (address == NULL || !pn_endpoint_from_sockaddr(address, length, &remote) || pn_endpoint_is_loopback(&remote) ||
        pn_endpoint_is_unspecified(&remote)) {
        return PN_DIRECT;
    }
    enum pn_verdict verdict;
    if (pn_cached_udp_verdict(&remote, &verdict)) {
        return verdict;
    }
    struct pn_endpoint local;
    memset(&local, 0, sizeof(local));
    local.family = remote.family;
    char hostname[PN_MAX_HOSTNAME + 1];
    bool has_hostname = pn_lookup_hostname(address, length, hostname, sizeof(hostname));
    struct pn_connect_answer answer;
    verdict = pn_query_connect(PN_UDP, &local, &remote, has_hostname ? hostname : NULL, &answer) && answer.verdict == PN_DIRECT ? PN_DIRECT : PN_BLOCK;
    pn_cache_udp_verdict(&remote, verdict);
    return verdict;
}

static bool blocked_udp(int fd, const struct sockaddr *address, socklen_t length)
{
    return address != NULL && (address->sa_family == AF_INET || address->sa_family == AF_INET6) && socket_type(fd) == SOCK_DGRAM &&
           decide_udp(address, length) == PN_BLOCK;
}

EXPORT int connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (!active || depth > 0 || address == NULL || (address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
        return pn_real_connect(fd, address, length);
    }
    depth++;
    int result;
    int type = socket_type(fd);
    if (type == SOCK_DGRAM) {
        if (decide_udp(address, length) == PN_BLOCK) {
            errno = ENETUNREACH;
            result = -1;
        } else {
            result = pn_real_connect(fd, address, length);
        }
    } else if (type != SOCK_STREAM) {
        result = pn_real_connect(fd, address, length);
    } else {
        struct sockaddr_storage relay;
        socklen_t relay_length = 0;
        switch (decide_tcp(fd, address, length, &relay, &relay_length)) {
        case PN_DIRECT:
            result = pn_real_connect(fd, address, length);
            break;
        case PN_BLOCK:
            errno = ECONNREFUSED;
            result = -1;
            break;
        default: {
            result = pn_real_connect(fd, (struct sockaddr *)&relay, relay_length);
            int error = errno;
            if (result == 0 || error == EINPROGRESS) {
                pn_remember_peer(fd, address, length);
            }
            errno = error;
            break;
        }
        }
    }
    depth--;
    return result;
}

EXPORT int getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    if (real_getpeername == NULL) {
        resolve_real();
    }
    int result = real_getpeername(fd, address, length);
    if (result != 0 || !active || address == NULL || length == NULL) {
        return result;
    }
    // Report the original destination, not the relay.
    struct sockaddr_storage original;
    socklen_t original_length = 0;
    if (pn_lookup_peer(fd, &original, &original_length) && original_length <= *length) {
        memcpy(address, &original, original_length);
        *length = original_length;
    }
    return result;
}

EXPORT int close(int fd)
{
    if (active) {
        int saved = errno;
        pn_forget_peer(fd);
        errno = saved;
    }
    return pn_real_close(fd);
}

EXPORT ssize_t sendto(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *address, socklen_t length)
{
    if (real_sendto == NULL) {
        resolve_real();
    }
    if (active && depth == 0 && address != NULL) {
        depth++;
        bool blocked = blocked_udp(fd, address, length);
        depth--;
        if (blocked) {
            errno = ENETUNREACH;
            return -1;
        }
    }
    return real_sendto(fd, buffer, size, flags, address, length);
}

EXPORT ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
    if (real_sendmsg == NULL) {
        resolve_real();
    }
    if (active && depth == 0 && message != NULL && message->msg_name != NULL) {
        depth++;
        bool blocked = blocked_udp(fd, (const struct sockaddr *)message->msg_name, message->msg_namelen);
        depth--;
        if (blocked) {
            errno = ENETUNREACH;
            return -1;
        }
    }
    return real_sendmsg(fd, message, flags);
}

EXPORT int sendmmsg(int fd, struct mmsghdr *messages, unsigned int count, int flags)
{
    if (real_sendmmsg == NULL) {
        resolve_real();
    }
    if (active && depth == 0 && messages != NULL) {
        depth++;
        bool blocked = false;
        for (unsigned int i = 0; i < count && !blocked; i++) {
            blocked = messages[i].msg_hdr.msg_name != NULL &&
                      blocked_udp(fd, (const struct sockaddr *)messages[i].msg_hdr.msg_name, messages[i].msg_hdr.msg_namelen);
        }
        depth--;
        if (blocked) {
            errno = ENETUNREACH;
            return -1;
        }
    }
    return real_sendmmsg(fd, messages, count, flags);
}

// ---- name resolution ------------------------------------------------------------------------------------------------

enum fake_result { FAKE_NONE, FAKE_ANSWER, FAKE_NODATA };

static bool is_numeric(const char *name)
{
    struct in6_addr buffer;
    return inet_pton(AF_INET, name, &buffer) == 1 || inet_pton(AF_INET6, name, &buffer) == 1;
}

// Names without a dot and numeric addresses are never faked; the service applies the rest (remoteDomains, ...).
static enum fake_result check_fake(const char *name, int family, int flags, char fake[INET_ADDRSTRLEN])
{
    if (name == NULL || *name == '\0' || (flags & AI_NUMERICHOST) != 0 || strchr(name, '.') == NULL || strlen(name) > PN_MAX_HOSTNAME ||
        is_numeric(name)) {
        return FAKE_NONE;
    }
    bool faked = false;
    uint8_t address[4];
    if (!pn_query_resolve(name, &faked, address) || !faked) {
        return FAKE_NONE;
    }
    if (family == AF_INET6) {
        return FAKE_NODATA; // fake addresses are IPv4
    }
    snprintf(fake, INET_ADDRSTRLEN, "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
    return FAKE_ANSWER;
}

EXPORT int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result)
{
    if (real_getaddrinfo == NULL) {
        resolve_real();
    }
    if (!active || depth > 0 || node == NULL) {
        return real_getaddrinfo(node, service, hints, result);
    }
    depth++;
    char fake[INET_ADDRSTRLEN];
    int status;
    switch (check_fake(node, hints != NULL ? hints->ai_family : AF_UNSPEC, hints != NULL ? hints->ai_flags : 0, fake)) {
    case FAKE_NODATA:
        status = EAI_NONAME;
        break;
    case FAKE_ANSWER: {
        // The real resolver builds the result from the numeric address, so the program frees it as usual.
        struct addrinfo numeric;
        memset(&numeric, 0, sizeof(numeric));
        if (hints != NULL) {
            numeric.ai_flags = hints->ai_flags;
            numeric.ai_family = hints->ai_family;
            numeric.ai_socktype = hints->ai_socktype;
            numeric.ai_protocol = hints->ai_protocol;
        }
        numeric.ai_flags |= AI_NUMERICHOST;
        status = real_getaddrinfo(fake, service, &numeric, result);
        break;
    }
    default:
        status = real_getaddrinfo(node, service, hints, result);
        if (status == 0 && result != NULL && !is_numeric(node)) {
            for (struct addrinfo *entry = *result; entry != NULL; entry = entry->ai_next) {
                if (entry->ai_addr != NULL && (entry->ai_family == AF_INET || entry->ai_family == AF_INET6)) {
                    pn_remember_hostname(entry->ai_addr, node);
                }
            }
        }
        break;
    }
    depth--;
    return status;
}

EXPORT struct hostent *gethostbyname(const char *name)
{
    if (real_gethostbyname == NULL) {
        resolve_real();
    }
    if (!active || depth > 0 || name == NULL) {
        return real_gethostbyname(name);
    }
    depth++;
    char fake[INET_ADDRSTRLEN];
    struct hostent *host;
    if (check_fake(name, AF_INET, 0, fake) == FAKE_ANSWER) {
        host = real_gethostbyname(fake);
    } else {
        host = real_gethostbyname(name);
        if (host != NULL && host->h_addrtype == AF_INET && host->h_length == 4 && !is_numeric(name)) {
            for (char **address = host->h_addr_list; *address != NULL; address++) {
                struct sockaddr_in v4;
                memset(&v4, 0, sizeof(v4));
                v4.sin_family = AF_INET;
                memcpy(&v4.sin_addr, *address, 4);
                pn_remember_hostname((struct sockaddr *)&v4, name);
            }
        }
    }
    depth--;
    return host;
}
