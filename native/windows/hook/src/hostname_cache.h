// Remembers which name the process resolved to which address, so connections can carry the hostname to the
// service (a hint: several names can share an address, so the relay still prefers a sniffed TLS SNI / HTTP Host).
#pragma once

#include <winsock2.h>

namespace proxynator {

void RememberHostname(const sockaddr* address, const char* utf8Name);
// Copies the name into buffer (null-terminated); false when unknown.
bool LookupHostname(const sockaddr* address, int length, char* buffer, size_t size);

}  // namespace proxynator
