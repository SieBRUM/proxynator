// The preload library's connection to proxynatord: one Unix socket per process, requests serialized. The service
// identifies the process with SO_PEERCRED, so a forked child reconnects (pn_client_after_fork).
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "preload.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int service_fd = -1;
static struct sockaddr_un service_address;
static bool reported_failure;

void pn_client_init(const char *socket_path)
{
    memset(&service_address, 0, sizeof(service_address));
    service_address.sun_family = AF_UNIX;
    strncpy(service_address.sun_path, socket_path, sizeof(service_address.sun_path) - 1);
}

void pn_client_after_fork(void)
{
    pthread_mutex_init(&lock, NULL);
    if (service_fd >= 0) {
        pn_real_close(service_fd); // the parent's session; the child gets its own
        service_fd = -1;
    }
}

static bool transfer(bool write, uint8_t *data, size_t length)
{
    size_t done = 0;
    while (done < length) {
        ssize_t count = write ? send(service_fd, data + done, length - done, MSG_NOSIGNAL) : recv(service_fd, data + done, length - done, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        done += (size_t)count;
    }
    return true;
}

static bool exchange(const struct pn_writer *request, enum pn_type type, uint8_t *response, size_t *response_length)
{
    if (!request->ok || !transfer(true, (uint8_t *)request->frame, pn_frame_length(request))) {
        return false;
    }
    uint8_t header[4];
    if (!transfer(false, header, 4)) {
        return false;
    }
    uint32_t length = (uint32_t)header[0] | ((uint32_t)header[1] << 8) | ((uint32_t)header[2] << 16) | ((uint32_t)header[3] << 24);
    if (length < 2 || length > PN_MAX_BODY || !transfer(false, response, length)) {
        return false;
    }
    *response_length = length;
    return response[0] == PN_PROTOCOL_VERSION && response[1] == (uint8_t)type;
}

static void disconnect(void)
{
    if (service_fd >= 0) {
        pn_real_close(service_fd);
        service_fd = -1;
    }
}

static bool connect_service(void)
{
    service_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (service_fd < 0) {
        return false;
    }
    struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
    setsockopt(service_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(service_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (pn_real_connect(service_fd, (struct sockaddr *)&service_address, sizeof(service_address)) != 0) {
        disconnect();
        return false;
    }
    struct pn_writer hello;
    pn_writer_init(&hello, PN_HELLO);
    pn_write_u8(&hello, (uint8_t)(sizeof(void *) * 8));
    uint8_t response[PN_MAX_BODY];
    size_t length = 0;
    if (!exchange(&hello, PN_HELLO, response, &length)) {
        disconnect();
        return false;
    }
    return true;
}

// Sends the request (connecting, or reconnecting once) and returns the response body.
static bool request(const struct pn_writer *writer, enum pn_type type, uint8_t *response, size_t *length)
{
    int saved = errno;
    bool ok = false;
    pthread_mutex_lock(&lock);
    for (int attempt = 0; attempt < 2 && !ok; attempt++) {
        if (service_fd < 0 && !connect_service()) {
            break;
        }
        ok = exchange(writer, type, response, length);
        if (!ok) {
            disconnect();
        }
    }
    if (!ok && !reported_failure) {
        reported_failure = true;
        pn_log("proxynatord is not reachable at %s; new connections are refused", service_address.sun_path);
    } else if (ok) {
        reported_failure = false;
    }
    pthread_mutex_unlock(&lock);
    errno = saved;
    return ok;
}

bool pn_query_connect(enum pn_transport transport, const struct pn_endpoint *local, const struct pn_endpoint *remote,
                      const char *hostname, struct pn_connect_answer *answer)
{
    struct pn_writer writer;
    pn_writer_init(&writer, PN_CONNECT);
    pn_write_u8(&writer, (uint8_t)transport);
    pn_write_endpoint(&writer, local);
    pn_write_endpoint(&writer, remote);
    pn_write_string(&writer, hostname);
    uint8_t response[PN_MAX_BODY];
    size_t length = 0;
    if (!request(&writer, PN_CONNECT, response, &length)) {
        return false;
    }
    struct pn_reader reader = {response, length, 0};
    uint8_t verdict = 0;
    if (!pn_read_header(&reader, PN_CONNECT) || !pn_read_u8(&reader, &verdict) || verdict > PN_BLOCK) {
        return false;
    }
    answer->verdict = (enum pn_verdict)verdict;
    if (answer->verdict == PN_RELAY) {
        // The relay is always local; anything else would send this program's traffic somewhere unexpected.
        if (!pn_read_endpoint(&reader, &answer->relay) || !pn_endpoint_is_loopback(&answer->relay)) {
            return false;
        }
    }
    return reader.position == reader.length;
}

bool pn_query_resolve(const char *hostname, bool *faked, uint8_t address[4])
{
    struct pn_writer writer;
    pn_writer_init(&writer, PN_RESOLVE);
    pn_write_string(&writer, hostname);
    uint8_t response[PN_MAX_BODY];
    size_t length = 0;
    if (!request(&writer, PN_RESOLVE, response, &length)) {
        return false;
    }
    struct pn_reader reader = {response, length, 0};
    uint8_t result = 0;
    if (!pn_read_header(&reader, PN_RESOLVE) || !pn_read_u8(&reader, &result) || result > 1) {
        return false;
    }
    *faked = result == 1;
    if (*faked && !pn_read_bytes(&reader, address, 4)) {
        return false;
    }
    return reader.position == reader.length;
}
