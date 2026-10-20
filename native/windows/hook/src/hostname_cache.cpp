#include "hostname_cache.h"

#include <windows.h>

#include <cstring>
#include <string>
#include <unordered_map>

#include "protocol.h"

namespace proxynator {

namespace {

constexpr size_t kMaxEntries = 4096;

SRWLOCK g_lock = SRWLOCK_INIT;
std::unordered_map<std::string, std::string>* g_names = nullptr;

// 4 or 16 address bytes; IPv4-mapped IPv6 addresses use the IPv4 key.
bool Key(const sockaddr* address, int length, std::string* key) {
    Endpoint endpoint;
    if (!EndpointFromSockaddr(address, length, &endpoint)) {
        return false;
    }
    static const uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (endpoint.family == 6 && memcmp(endpoint.address, kMapped, 12) == 0) {
        key->assign(reinterpret_cast<const char*>(endpoint.address + 12), 4);
    } else {
        key->assign(reinterpret_cast<const char*>(endpoint.address), endpoint.family == 4 ? 4 : 16);
    }
    return true;
}

}  // namespace

void RememberHostname(const sockaddr* address, const char* utf8Name) {
    if (utf8Name == nullptr || *utf8Name == '\0' || strlen(utf8Name) > kMaxHostname) {
        return;
    }
    std::string key;
    int length = address->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    if (!Key(address, length, &key)) {
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    if (g_names == nullptr) {
        g_names = new std::unordered_map<std::string, std::string>();
    }
    if (g_names->size() >= kMaxEntries) {
        g_names->clear();
    }
    (*g_names)[key] = utf8Name;
    ReleaseSRWLockExclusive(&g_lock);
}

bool LookupHostname(const sockaddr* address, int length, char* buffer, size_t size) {
    std::string key;
    if (!Key(address, length, &key)) {
        return false;
    }
    bool found = false;
    AcquireSRWLockShared(&g_lock);
    if (g_names != nullptr) {
        auto entry = g_names->find(key);
        if (entry != g_names->end() && entry->second.size() < size) {
            memcpy(buffer, entry->second.c_str(), entry->second.size() + 1);
            found = true;
        }
    }
    ReleaseSRWLockShared(&g_lock);
    return found;
}

}  // namespace proxynator
