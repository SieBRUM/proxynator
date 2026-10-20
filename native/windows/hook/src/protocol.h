// The hook registration protocol. Mirrors src/Proxynator.Core/Hooking/HookProtocol.cs; keep both in sync.
//
// frame    = u32 length, body
// body     = u8 version (1), u8 type, payload
// requests:  Hello   u8 pointerBits
//            Connect u8 protocol (6 tcp, 17 udp), endpoint local, endpoint remote, string hostname
//            Resolve string hostname
// responses: Hello   i32 servicePid
//            Connect u8 verdict (0 direct, 1 relay, 2 block), endpoint relay (verdict 1 only)
//            Resolve u8 faked (0 or 1), 4 bytes IPv4 address (faked only)
// endpoint = u8 family (4 or 6), 4 or 16 address bytes, u32 scope id (family 6 only), u16 port
// string   = u16 length, UTF-8 bytes (length 0 = absent)
// All integers are little-endian.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstddef>
#include <cstdint>

namespace proxynator {

inline constexpr uint8_t kProtocolVersion = 1;
inline constexpr size_t kMaxBody = 1024;
inline constexpr size_t kMaxHostname = 255;

enum class MessageType : uint8_t { Hello = 1, Connect = 2, Resolve = 3 };
enum class Verdict : uint8_t { Direct = 0, Relay = 1, Block = 2 };

// A socket address in protocol form. port is in host byte order.
struct Endpoint {
    uint8_t family = 0;  // 4 or 6
    uint8_t address[16] = {};
    uint32_t scopeId = 0;
    uint16_t port = 0;
};

bool EndpointFromSockaddr(const sockaddr* address, int length, Endpoint* endpoint);
// Converts to a socket address of the given family; an IPv4 endpoint becomes IPv4-mapped for AF_INET6.
bool EndpointToSockaddr(const Endpoint& endpoint, int family, sockaddr_storage* address, int* length);
bool IsLoopback(const Endpoint& endpoint);

class Writer {
public:
    explicit Writer(MessageType type);
    void U8(uint8_t value);
    void U16(uint16_t value);
    void U32(uint32_t value);
    void Bytes(const void* data, size_t length);
    void Address(const Endpoint& endpoint);
    void String(const char* utf8);  // nullptr or "" = absent; longer than kMaxHostname = absent
    bool Ok() const { return ok_; }
    // The frame: length prefix followed by the body.
    const uint8_t* Frame() const { return frame_; }
    size_t FrameLength() const { return 4 + length_; }

private:
    uint8_t frame_[4 + kMaxBody] = {};
    size_t length_ = 0;
    bool ok_ = true;
};

class Reader {
public:
    Reader(const uint8_t* body, size_t length) : data_(body), length_(length) {}
    // Reads and checks the version and type.
    bool Header(MessageType expected);
    bool U8(uint8_t* value);
    bool I32(int32_t* value);
    bool Bytes(void* data, size_t length);
    bool Address(Endpoint* endpoint);
    bool AtEnd() const { return position_ == length_; }

private:
    const uint8_t* data_;
    size_t length_;
    size_t position_ = 0;
};

}  // namespace proxynator
