// Resolver hooks: in remote DNS mode, names in remoteDomains resolve to fake addresses handed out by proxynatord
// (the proxy resolves the real name later); otherwise the results are remembered as hostname hints for connects.
// Fake answers are produced by the real resolver from the numeric fake address, so the result structures are
// allocated by Winsock itself and the application frees them as usual.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <unordered_map>

#include "hook_state.h"
#include "hooks.h"
#include "hostname_cache.h"
#include "protocol.h"
#include "service_client.h"

namespace proxynator {

namespace {

decltype(&getaddrinfo) Real_getaddrinfo = getaddrinfo;
decltype(&GetAddrInfoW) Real_GetAddrInfoW = GetAddrInfoW;
decltype(&GetAddrInfoExW) Real_GetAddrInfoExW = GetAddrInfoExW;
decltype(&gethostbyname) Real_gethostbyname = gethostbyname;

constexpr size_t kNameBuffer = kMaxHostname + 1;
constexpr size_t kFakeText = 16;

enum class FakeResult { NotFaked, Faked, NoData };

bool WideToUtf8(PCWSTR wide, char* utf8, size_t size) {
    return WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, static_cast<int>(size), nullptr, nullptr) > 0;
}

bool AnsiToUtf8(PCSTR ansi, char* utf8, size_t size) {
    wchar_t wide[kNameBuffer];
    return MultiByteToWideChar(CP_ACP, 0, ansi, -1, wide, kNameBuffer) > 0 && WideToUtf8(wide, utf8, size);
}

bool IsNumericAddress(const char* name) {
    in6_addr buffer;
    return inet_pton(AF_INET, name, &buffer) == 1 || inet_pton(AF_INET6, name, &buffer) == 1;
}

// Asks the service whether name gets a fake address. Names without a dot, numeric addresses and AI_NUMERICHOST
// lookups never do (the service applies the full rules: remoteDomains, proxy hostnames, *.localhost, ...).
FakeResult CheckFake(const char* name, int family, int flags, char fakeText[kFakeText]) {
    if (name == nullptr || *name == '\0' || (flags & AI_NUMERICHOST) != 0 || strchr(name, '.') == nullptr ||
        strlen(name) > kMaxHostname || IsNumericAddress(name)) {
        return FakeResult::NotFaked;
    }
    LastErrorScope preserve;
    bool faked = false;
    uint8_t address[4];
    if (!QueryResolve(name, &faked, address) || !faked) {
        return FakeResult::NotFaked;
    }
    if (family == AF_INET6) {
        // Fake addresses are IPv4; an IPv6-only lookup gets no answer (like the AAAA answer in windivert mode).
        return FakeResult::NoData;
    }
    sprintf_s(fakeText, kFakeText, "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
    return FakeResult::Faked;
}

template <typename Info>
void RememberResults(const Info* results, const char* name) {
    LastErrorScope preserve;
    for (const Info* entry = results; entry != nullptr; entry = entry->ai_next) {
        if (entry->ai_addr != nullptr && (entry->ai_family == AF_INET || entry->ai_family == AF_INET6)) {
            RememberHostname(entry->ai_addr, name);
        }
    }
}

template <typename Hints>
Hints NumericHints(const Hints* hints) {
    Hints numeric = {};
    if (hints != nullptr) {
        numeric.ai_flags = hints->ai_flags;
        numeric.ai_family = hints->ai_family;
        numeric.ai_socktype = hints->ai_socktype;
        numeric.ai_protocol = hints->ai_protocol;
    }
    numeric.ai_flags = (numeric.ai_flags | AI_NUMERICHOST) & ~(AI_FQDN | AI_FILESERVER);
    return numeric;
}

// Wide copies of fake addresses that outlive asynchronous GetAddrInfoExW calls. Never freed: there are only as
// many as the service hands out.
SRWLOCK g_internLock = SRWLOCK_INIT;
std::unordered_map<std::string, std::wstring>* g_interned = nullptr;

PCWSTR InternWide(const char* text) {
    AcquireSRWLockExclusive(&g_internLock);
    if (g_interned == nullptr) {
        g_interned = new std::unordered_map<std::string, std::wstring>();
    }
    std::wstring& wide = (*g_interned)[text];
    if (wide.empty()) {
        for (const char* c = text; *c != '\0'; ++c) {
            wide.push_back(static_cast<wchar_t>(*c));
        }
    }
    PCWSTR result = wide.c_str();
    ReleaseSRWLockExclusive(&g_internLock);
    return result;
}

PCWSTR WideFake(const char* fakeText, wchar_t* buffer, size_t size) {
    size_t i = 0;
    for (; fakeText[i] != '\0' && i + 1 < size; ++i) {
        buffer[i] = static_cast<wchar_t>(fakeText[i]);
    }
    buffer[i] = L'\0';
    return buffer;
}

INT WSAAPI Hook_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) {
    ReentrancyGuard guard;
    char name[kNameBuffer];
    if (guard.Nested() || node == nullptr || !AnsiToUtf8(node, name, sizeof(name))) {
        return Real_getaddrinfo(node, service, hints, result);
    }
    char fake[kFakeText];
    switch (CheckFake(name, hints != nullptr ? hints->ai_family : AF_UNSPEC, hints != nullptr ? hints->ai_flags : 0, fake)) {
        case FakeResult::NoData:
            WSASetLastError(WSANO_DATA);
            return WSANO_DATA;
        case FakeResult::Faked: {
            ADDRINFOA numeric = NumericHints(hints);
            return Real_getaddrinfo(fake, service, &numeric, result);
        }
        default: {
            INT error = Real_getaddrinfo(node, service, hints, result);
            if (error == 0 && result != nullptr && !IsNumericAddress(name)) {
                RememberResults(*result, name);
            }
            return error;
        }
    }
}

int ResolveWideCore(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) {
    char name[kNameBuffer];
    if (node == nullptr || !WideToUtf8(node, name, sizeof(name))) {
        return Real_GetAddrInfoW(node, service, hints, result);
    }
    char fake[kFakeText];
    switch (CheckFake(name, hints != nullptr ? hints->ai_family : AF_UNSPEC, hints != nullptr ? hints->ai_flags : 0, fake)) {
        case FakeResult::NoData:
            WSASetLastError(WSANO_DATA);
            return WSANO_DATA;
        case FakeResult::Faked: {
            ADDRINFOW numeric = NumericHints(hints);
            wchar_t wide[kFakeText];
            return Real_GetAddrInfoW(WideFake(fake, wide, kFakeText), service, &numeric, result);
        }
        default: {
            INT error = Real_GetAddrInfoW(node, service, hints, result);
            if (error == 0 && result != nullptr && !IsNumericAddress(name)) {
                RememberResults(*result, name);
            }
            return error;
        }
    }
}

INT WSAAPI Hook_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) {
    ReentrancyGuard guard;
    if (guard.Nested()) {
        return Real_GetAddrInfoW(node, service, hints, result);
    }
    return ResolveWideCore(node, service, hints, result);
}

INT WSAAPI Hook_GetAddrInfoExW(PCWSTR name, PCWSTR service, DWORD nameSpace, LPGUID provider, const ADDRINFOEXW* hints,
                               PADDRINFOEXW* result, struct timeval* timeout, LPOVERLAPPED overlapped,
                               LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE handle) {
    ReentrancyGuard guard;
    char utf8[kNameBuffer];
    if (guard.Nested() || name == nullptr || (nameSpace != NS_ALL && nameSpace != NS_DNS) || !WideToUtf8(name, utf8, sizeof(utf8))) {
        return Real_GetAddrInfoExW(name, service, nameSpace, provider, hints, result, timeout, overlapped, completion, handle);
    }
    char fake[kFakeText];
    switch (CheckFake(utf8, hints != nullptr ? hints->ai_family : AF_UNSPEC, hints != nullptr ? hints->ai_flags : 0, fake)) {
        case FakeResult::NoData:
            WSASetLastError(WSANO_DATA);
            return WSANO_DATA;
        case FakeResult::Faked: {
            ADDRINFOEXW numeric = NumericHints(hints);
            // An asynchronous call may use the name after returning, so it gets a copy that is never freed.
            return Real_GetAddrInfoExW(InternWide(fake), service, nameSpace, provider, &numeric, result, timeout, overlapped, completion,
                                       handle);
        }
        default: {
            INT error = Real_GetAddrInfoExW(name, service, nameSpace, provider, hints, result, timeout, overlapped, completion, handle);
            // Asynchronous results arrive later and are not seen here; the relay still sniffs TLS SNI / HTTP Host.
            if (error == 0 && overlapped == nullptr && result != nullptr && !IsNumericAddress(utf8)) {
                RememberResults(*result, utf8);
            }
            return error;
        }
    }
}

hostent* WSAAPI Hook_gethostbyname(const char* name) {
    ReentrancyGuard guard;
    char utf8[kNameBuffer];
    if (guard.Nested() || name == nullptr || !AnsiToUtf8(name, utf8, sizeof(utf8))) {
        return Real_gethostbyname(name);
    }
    char fake[kFakeText];
    if (CheckFake(utf8, AF_INET, 0, fake) == FakeResult::Faked) {
        return Real_gethostbyname(fake);
    }
    hostent* host = Real_gethostbyname(name);
    if (host != nullptr && host->h_addrtype == AF_INET && host->h_length == 4 && !IsNumericAddress(utf8)) {
        LastErrorScope preserve;
        for (char** address = host->h_addr_list; *address != nullptr; ++address) {
            sockaddr_in v4 = {};
            v4.sin_family = AF_INET;
            memcpy(&v4.sin_addr, *address, 4);
            RememberHostname(reinterpret_cast<sockaddr*>(&v4), utf8);
        }
    }
    return host;
}

static_assert(std::is_same_v<decltype(&Hook_getaddrinfo), decltype(Real_getaddrinfo)>);
static_assert(std::is_same_v<decltype(&Hook_GetAddrInfoW), decltype(Real_GetAddrInfoW)>);
static_assert(std::is_same_v<decltype(&Hook_GetAddrInfoExW), decltype(Real_GetAddrInfoExW)>);
static_assert(std::is_same_v<decltype(&Hook_gethostbyname), decltype(Real_gethostbyname)>);

#define PROXYNATOR_HOOK(function) {reinterpret_cast<PVOID*>(&Real_##function), reinterpret_cast<PVOID>(&Hook_##function), L## #function}

const HookEntry kEntries[] = {
    PROXYNATOR_HOOK(getaddrinfo),
    PROXYNATOR_HOOK(GetAddrInfoW),
    PROXYNATOR_HOOK(GetAddrInfoExW),
    PROXYNATOR_HOOK(gethostbyname),
};

}  // namespace

const HookEntry* ResolverHooks(size_t* count) {
    *count = sizeof(kEntries) / sizeof(kEntries[0]);
    return kEntries;
}

int ResolveForConnect(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* results) {
    return ResolveWideCore(node, service, hints, results);
}

}  // namespace proxynator
