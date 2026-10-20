// Small fixed-size caches: hostnames the program resolved (hints for the proxy), original destinations of relayed
// sockets (for getpeername) and recent UDP verdicts. All are best effort; losing an entry only costs a hint or a
// round trip to the service.
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "preload.h"

#define HOSTNAME_SLOTS 4096
#define PEER_SLOTS 4096
#define UDP_SLOTS 512
#define UDP_LIFETIME_SECONDS 30

struct hostname_slot {
    bool used;
    uint8_t key[16];
    char name[PN_MAX_HOSTNAME + 1];
};

struct peer_slot {
    int fd; // -1 = free
    struct sockaddr_storage address;
    socklen_t length;
};

struct udp_slot {
    bool used;
    uint8_t key[18];
    enum pn_verdict verdict;
    time_t expires;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct hostname_slot *hostnames;
static struct peer_slot *peers;
static struct udp_slot udp[UDP_SLOTS];
static size_t next_udp;

void pn_caches_after_fork(void) { pthread_mutex_init(&lock, NULL); }

static uint32_t hash(const uint8_t *data, size_t length)
{
    uint32_t value = 2166136261u;
    for (size_t i = 0; i < length; i++) {
        value = (value ^ data[i]) * 16777619u;
    }
    return value;
}

// 16 bytes; IPv4 and IPv4-mapped addresses share a key.
static bool address_key(const struct sockaddr *address, socklen_t length, uint8_t key[16])
{
    struct pn_endpoint endpoint;
    if (!pn_endpoint_from_sockaddr(address, length, &endpoint)) {
        return false;
    }
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    memset(key, 0, 16);
    if (endpoint.family == 4) {
        memcpy(key, mapped, 12);
        memcpy(key + 12, endpoint.address, 4);
    } else {
        memcpy(key, endpoint.address, 16);
    }
    return true;
}

void pn_remember_hostname(const struct sockaddr *address, const char *name)
{
    uint8_t key[16];
    socklen_t length = address->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (name == NULL || strlen(name) > PN_MAX_HOSTNAME || !address_key(address, length, key)) {
        return;
    }
    pthread_mutex_lock(&lock);
    if (hostnames == NULL) {
        hostnames = calloc(HOSTNAME_SLOTS, sizeof(*hostnames));
    }
    if (hostnames != NULL) {
        struct hostname_slot *slot = &hostnames[hash(key, 16) % HOSTNAME_SLOTS];
        slot->used = true;
        memcpy(slot->key, key, 16);
        strcpy(slot->name, name);
    }
    pthread_mutex_unlock(&lock);
}

bool pn_lookup_hostname(const struct sockaddr *address, socklen_t length, char *buffer, size_t size)
{
    uint8_t key[16];
    if (!address_key(address, length, key)) {
        return false;
    }
    bool found = false;
    pthread_mutex_lock(&lock);
    if (hostnames != NULL) {
        struct hostname_slot *slot = &hostnames[hash(key, 16) % HOSTNAME_SLOTS];
        if (slot->used && memcmp(slot->key, key, 16) == 0 && strlen(slot->name) < size) {
            strcpy(buffer, slot->name);
            found = true;
        }
    }
    pthread_mutex_unlock(&lock);
    return found;
}

void pn_remember_peer(int fd, const struct sockaddr *address, socklen_t length)
{
    if (fd < 0 || length > (socklen_t)sizeof(struct sockaddr_storage)) {
        return;
    }
    pthread_mutex_lock(&lock);
    if (peers == NULL && (peers = malloc(PEER_SLOTS * sizeof(*peers))) != NULL) {
        for (size_t i = 0; i < PEER_SLOTS; i++) {
            peers[i].fd = -1;
        }
    }
    if (peers != NULL) {
        struct peer_slot *slot = &peers[(unsigned)fd % PEER_SLOTS];
        slot->fd = fd;
        memcpy(&slot->address, address, length);
        slot->length = length;
    }
    pthread_mutex_unlock(&lock);
}

bool pn_lookup_peer(int fd, struct sockaddr_storage *address, socklen_t *length)
{
    bool found = false;
    pthread_mutex_lock(&lock);
    if (peers != NULL && fd >= 0 && peers[(unsigned)fd % PEER_SLOTS].fd == fd) {
        *address = peers[(unsigned)fd % PEER_SLOTS].address;
        *length = peers[(unsigned)fd % PEER_SLOTS].length;
        found = true;
    }
    pthread_mutex_unlock(&lock);
    return found;
}

void pn_forget_peer(int fd)
{
    pthread_mutex_lock(&lock);
    if (peers != NULL && fd >= 0 && peers[(unsigned)fd % PEER_SLOTS].fd == fd) {
        peers[(unsigned)fd % PEER_SLOTS].fd = -1;
    }
    pthread_mutex_unlock(&lock);
}

static void udp_key(const struct pn_endpoint *remote, uint8_t key[18])
{
    memset(key, 0, 18);
    memcpy(key, remote->address, remote->family == 4 ? 4 : 16);
    key[16] = (uint8_t)remote->port;
    key[17] = (uint8_t)(remote->port >> 8);
}

bool pn_cached_udp_verdict(const struct pn_endpoint *remote, enum pn_verdict *verdict)
{
    uint8_t key[18];
    udp_key(remote, key);
    time_t now = time(NULL);
    bool found = false;
    pthread_mutex_lock(&lock);
    for (size_t i = 0; i < UDP_SLOTS && !found; i++) {
        if (udp[i].used && udp[i].expires > now && memcmp(udp[i].key, key, 18) == 0) {
            *verdict = udp[i].verdict;
            found = true;
        }
    }
    pthread_mutex_unlock(&lock);
    return found;
}

void pn_cache_udp_verdict(const struct pn_endpoint *remote, enum pn_verdict verdict)
{
    pthread_mutex_lock(&lock);
    struct udp_slot *slot = &udp[next_udp++ % UDP_SLOTS];
    slot->used = true;
    udp_key(remote, slot->key);
    slot->verdict = verdict;
    slot->expires = time(NULL) + UDP_LIFETIME_SECONDS;
    pthread_mutex_unlock(&lock);
}
