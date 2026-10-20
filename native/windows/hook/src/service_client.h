// The hook's connection to proxynatord (one named pipe per process, requests serialized).
#pragma once

#include <cstdint>

#include "protocol.h"

namespace proxynator {

enum class Transport : uint8_t { Tcp = 6, Udp = 17 };

struct ConnectQuery {
    Transport transport;
    Endpoint local;
    Endpoint remote;
    const char* hostname;  // UTF-8, may be null
};

struct ConnectAnswer {
    Verdict verdict = Verdict::Block;
    Endpoint relay;
};

// Asks the service what to do with a connection. Returns false when the service cannot be reached or answered
// nonsense; callers then fail closed.
bool QueryConnect(const ConnectQuery& query, ConnectAnswer* answer);

// Asks the service whether a name gets a fake address. Returns false when the service cannot be reached (callers
// then resolve normally); *faked tells whether fakeAddress (4 bytes, network order) was filled.
bool QueryResolve(const char* hostname, bool* faked, uint8_t fakeAddress[4]);

}  // namespace proxynator
