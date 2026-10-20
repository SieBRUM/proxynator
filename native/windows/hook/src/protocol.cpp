#include "protocol.h"

#include <cstring>

namespace proxynator {

namespace {

const uint8_t kMappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

}  // namespace

bool EndpointFromSockaddr(const sockaddr* address, int length, Endpoint* endpoint) {
    if (address == nullptr) {
        return false;
    }
    if (address->sa_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
        endpoint->family = 4;
        memcpy(endpoint->address, &v4->sin_addr, 4);
        endpoint->scopeId = 0;
        endpoint->port = ntohs(v4->sin_port);
        return true;
    }
    if (address->sa_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
        endpoint->family = 6;
        memcpy(endpoint->address, &v6->sin6_addr, 16);
        endpoint->scopeId = v6->sin6_scope_id;
        endpoint->port = ntohs(v6->sin6_port);
        return true;
    }
    return false;
}

bool EndpointToSockaddr(const Endpoint& endpoint, int family, sockaddr_storage* address, int* length) {
    memset(address, 0, sizeof(*address));
    if (family == AF_INET) {
        if (endpoint.family != 4) {
            return false;
        }
        auto* v4 = reinterpret_cast<sockaddr_in*>(address);
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr, endpoint.address, 4);
        v4->sin_port = htons(endpoint.port);
        *length = sizeof(sockaddr_in);
        return true;
    }
    if (family == AF_INET6) {
        auto* v6 = reinterpret_cast<sockaddr_in6*>(address);
        v6->sin6_family = AF_INET6;
        if (endpoint.family == 4) {
            memcpy(&v6->sin6_addr, kMappedPrefix, 12);
            memcpy(reinterpret_cast<uint8_t*>(&v6->sin6_addr) + 12, endpoint.address, 4);
        } else {
            memcpy(&v6->sin6_addr, endpoint.address, 16);
            v6->sin6_scope_id = endpoint.scopeId;
        }
        v6->sin6_port = htons(endpoint.port);
        *length = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

bool IsLoopback(const Endpoint& endpoint) {
    if (endpoint.family == 4) {
        return endpoint.address[0] == 127;
    }
    static const uint8_t kLoopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (memcmp(endpoint.address, kLoopback6, 16) == 0) {
        return true;
    }
    return memcmp(endpoint.address, kMappedPrefix, 12) == 0 && endpoint.address[12] == 127;
}

Writer::Writer(MessageType type) {
    U8(kProtocolVersion);
    U8(static_cast<uint8_t>(type));
}

void Writer::U8(uint8_t value) { Bytes(&value, 1); }

void Writer::U16(uint16_t value) {
    uint8_t bytes[2] = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8)};
    Bytes(bytes, 2);
}

void Writer::U32(uint32_t value) {
    uint8_t bytes[4] = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value >> 16),
                        static_cast<uint8_t>(value >> 24)};
    Bytes(bytes, 4);
}

void Writer::Bytes(const void* data, size_t length) {
    if (!ok_ || length > kMaxBody - length_) {
        ok_ = false;
        return;
    }
    memcpy(frame_ + 4 + length_, data, length);
    length_ += length;
    uint32_t total = static_cast<uint32_t>(length_);
    memcpy(frame_, &total, 4);  // x86/x64 are little-endian
}

void Writer::Address(const Endpoint& endpoint) {
    U8(endpoint.family);
    Bytes(endpoint.address, endpoint.family == 4 ? 4 : 16);
    if (endpoint.family == 6) {
        U32(endpoint.scopeId);
    }
    U16(endpoint.port);
}

void Writer::String(const char* utf8) {
    size_t length = utf8 == nullptr ? 0 : strlen(utf8);
    if (length > kMaxHostname) {
        length = 0;
    }
    U16(static_cast<uint16_t>(length));
    if (length > 0) {
        Bytes(utf8, length);
    }
}

bool Reader::Header(MessageType expected) {
    uint8_t version = 0;
    uint8_t type = 0;
    return U8(&version) && version == kProtocolVersion && U8(&type) && type == static_cast<uint8_t>(expected);
}

bool Reader::U8(uint8_t* value) { return Bytes(value, 1); }

bool Reader::I32(int32_t* value) {
    uint8_t bytes[4];
    if (!Bytes(bytes, 4)) {
        return false;
    }
    *value = static_cast<int32_t>(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (static_cast<uint32_t>(bytes[3]) << 24));
    return true;
}

bool Reader::Bytes(void* data, size_t length) {
    if (length > length_ - position_) {
        return false;
    }
    memcpy(data, data_ + position_, length);
    position_ += length;
    return true;
}

bool Reader::Address(Endpoint* endpoint) {
    if (!U8(&endpoint->family) || (endpoint->family != 4 && endpoint->family != 6)) {
        return false;
    }
    if (!Bytes(endpoint->address, endpoint->family == 4 ? 4 : 16)) {
        return false;
    }
    endpoint->scopeId = 0;
    if (endpoint->family == 6) {
        int32_t scope = 0;
        if (!I32(&scope)) {
            return false;
        }
        endpoint->scopeId = static_cast<uint32_t>(scope);
    }
    uint8_t port[2];
    if (!Bytes(port, 2)) {
        return false;
    }
    endpoint->port = static_cast<uint16_t>(port[0] | (port[1] << 8));
    return true;
}

}  // namespace proxynator
