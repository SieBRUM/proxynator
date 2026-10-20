#include <string.h>

#include "preload.h"

static const uint8_t mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static void put_length(struct pn_writer *writer)
{
    uint32_t length = (uint32_t)writer->length;
    for (int i = 0; i < 4; i++) {
        writer->frame[i] = (uint8_t)(length >> (8 * i));
    }
}

static void write_bytes(struct pn_writer *writer, const void *data, size_t length)
{
    if (!writer->ok || length > PN_MAX_BODY - writer->length) {
        writer->ok = false;
        return;
    }
    memcpy(writer->frame + 4 + writer->length, data, length);
    writer->length += length;
    put_length(writer);
}

static void write_u16(struct pn_writer *writer, uint16_t value)
{
    uint8_t bytes[2] = {(uint8_t)value, (uint8_t)(value >> 8)};
    write_bytes(writer, bytes, 2);
}

static void write_u32(struct pn_writer *writer, uint32_t value)
{
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    write_bytes(writer, bytes, 4);
}

void pn_writer_init(struct pn_writer *writer, enum pn_type type)
{
    writer->length = 0;
    writer->ok = true;
    pn_write_u8(writer, PN_PROTOCOL_VERSION);
    pn_write_u8(writer, (uint8_t)type);
}

void pn_write_u8(struct pn_writer *writer, uint8_t value) { write_bytes(writer, &value, 1); }

void pn_write_endpoint(struct pn_writer *writer, const struct pn_endpoint *endpoint)
{
    pn_write_u8(writer, endpoint->family);
    write_bytes(writer, endpoint->address, endpoint->family == 4 ? 4 : 16);
    if (endpoint->family == 6) {
        write_u32(writer, endpoint->scope_id);
    }
    write_u16(writer, endpoint->port);
}

void pn_write_string(struct pn_writer *writer, const char *utf8)
{
    size_t length = utf8 == NULL ? 0 : strlen(utf8);
    if (length > PN_MAX_HOSTNAME) {
        length = 0;
    }
    write_u16(writer, (uint16_t)length);
    if (length > 0) {
        write_bytes(writer, utf8, length);
    }
}

size_t pn_frame_length(const struct pn_writer *writer) { return 4 + writer->length; }

bool pn_read_bytes(struct pn_reader *reader, void *data, size_t length)
{
    if (length > reader->length - reader->position) {
        return false;
    }
    memcpy(data, reader->data + reader->position, length);
    reader->position += length;
    return true;
}

bool pn_read_u8(struct pn_reader *reader, uint8_t *value) { return pn_read_bytes(reader, value, 1); }

bool pn_read_header(struct pn_reader *reader, enum pn_type expected)
{
    uint8_t version = 0;
    uint8_t type = 0;
    return pn_read_u8(reader, &version) && version == PN_PROTOCOL_VERSION && pn_read_u8(reader, &type) && type == (uint8_t)expected;
}

bool pn_read_endpoint(struct pn_reader *reader, struct pn_endpoint *endpoint)
{
    memset(endpoint, 0, sizeof(*endpoint));
    if (!pn_read_u8(reader, &endpoint->family) || (endpoint->family != 4 && endpoint->family != 6)) {
        return false;
    }
    if (!pn_read_bytes(reader, endpoint->address, endpoint->family == 4 ? 4 : 16)) {
        return false;
    }
    uint8_t bytes[4];
    if (endpoint->family == 6) {
        if (!pn_read_bytes(reader, bytes, 4)) {
            return false;
        }
        endpoint->scope_id = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
    }
    if (!pn_read_bytes(reader, bytes, 2)) {
        return false;
    }
    endpoint->port = (uint16_t)(bytes[0] | (bytes[1] << 8));
    return true;
}

bool pn_endpoint_from_sockaddr(const struct sockaddr *address, socklen_t length, struct pn_endpoint *endpoint)
{
    memset(endpoint, 0, sizeof(*endpoint));
    if (address == NULL) {
        return false;
    }
    if (address->sa_family == AF_INET && length >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)address;
        endpoint->family = 4;
        memcpy(endpoint->address, &v4->sin_addr, 4);
        endpoint->port = ntohs(v4->sin_port);
        return true;
    }
    if (address->sa_family == AF_INET6 && length >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)address;
        endpoint->family = 6;
        memcpy(endpoint->address, &v6->sin6_addr, 16);
        endpoint->scope_id = v6->sin6_scope_id;
        endpoint->port = ntohs(v6->sin6_port);
        return true;
    }
    return false;
}

bool pn_endpoint_to_sockaddr(const struct pn_endpoint *endpoint, int family, struct sockaddr_storage *address, socklen_t *length)
{
    memset(address, 0, sizeof(*address));
    if (family == AF_INET) {
        if (endpoint->family != 4) {
            return false;
        }
        struct sockaddr_in *v4 = (struct sockaddr_in *)address;
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr, endpoint->address, 4);
        v4->sin_port = htons(endpoint->port);
        *length = sizeof(*v4);
        return true;
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address;
        v6->sin6_family = AF_INET6;
        if (endpoint->family == 4) {
            memcpy(&v6->sin6_addr, mapped_prefix, 12);
            memcpy((uint8_t *)&v6->sin6_addr + 12, endpoint->address, 4);
        } else {
            memcpy(&v6->sin6_addr, endpoint->address, 16);
            v6->sin6_scope_id = endpoint->scope_id;
        }
        v6->sin6_port = htons(endpoint->port);
        *length = sizeof(*v6);
        return true;
    }
    return false;
}

bool pn_endpoint_is_loopback(const struct pn_endpoint *endpoint)
{
    if (endpoint->family == 4) {
        return endpoint->address[0] == 127;
    }
    static const uint8_t loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(endpoint->address, loopback6, 16) == 0) {
        return true;
    }
    return memcmp(endpoint->address, mapped_prefix, 12) == 0 && endpoint->address[12] == 127;
}

bool pn_endpoint_is_unspecified(const struct pn_endpoint *endpoint)
{
    static const uint8_t zero[16] = {0};
    if (memcmp(endpoint->address, zero, endpoint->family == 4 ? 4 : 16) == 0) {
        return true;
    }
    return endpoint->family == 6 && memcmp(endpoint->address, mapped_prefix, 12) == 0 && memcmp(endpoint->address + 12, zero, 4) == 0;
}
