// Winsock hooks: every TCP connect is decided by proxynatord (direct, relay or block); UDP sends are checked
// (direct or block, UDP is not relayed in injection mode yet).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <detours.h>

#include <cstring>
#include <string>
#include <type_traits>
#include <unordered_map>

#include "hook_state.h"
#include "hooks.h"
#include "hostname_cache.h"
#include "log.h"
#include "protocol.h"
#include "service_client.h"

namespace proxynator {

namespace {

decltype(&connect) Real_connect = connect;
decltype(&WSAConnect) Real_WSAConnect = WSAConnect;
decltype(&WSAConnectByNameW) Real_WSAConnectByNameW = WSAConnectByNameW;
decltype(&WSAConnectByNameA) Real_WSAConnectByNameA = WSAConnectByNameA;
decltype(&WSAIoctl) Real_WSAIoctl = WSAIoctl;
decltype(&getpeername) Real_getpeername = getpeername;
decltype(&closesocket) Real_closesocket = closesocket;
decltype(&sendto) Real_sendto = sendto;
decltype(&WSASendTo) Real_WSASendTo = WSASendTo;
decltype(&WSASendMsg) Real_WSASendMsg = WSASendMsg;

// ---------------------------------------------------------------------------------------------------------------
// Bookkeeping: the original destination of relayed sockets (for getpeername) and recent UDP decisions.

SRWLOCK g_peersLock = SRWLOCK_INIT;
std::unordered_map<SOCKET, sockaddr_storage>* g_peers = nullptr;

void RememberPeer(SOCKET s, const sockaddr* name, int length) {
    if (length <= 0 || length > static_cast<int>(sizeof(sockaddr_storage))) {
        return;
    }
    sockaddr_storage copy = {};
    memcpy(&copy, name, length);
    AcquireSRWLockExclusive(&g_peersLock);
    if (g_peers == nullptr) {
        g_peers = new std::unordered_map<SOCKET, sockaddr_storage>();
    }
    (*g_peers)[s] = copy;
    ReleaseSRWLockExclusive(&g_peersLock);
}

bool LookupPeer(SOCKET s, sockaddr_storage* address) {
    bool found = false;
    AcquireSRWLockShared(&g_peersLock);
    if (g_peers != nullptr) {
        auto entry = g_peers->find(s);
        if (entry != g_peers->end()) {
            *address = entry->second;
            found = true;
        }
    }
    ReleaseSRWLockShared(&g_peersLock);
    return found;
}

void ForgetPeer(SOCKET s) {
    AcquireSRWLockExclusive(&g_peersLock);
    if (g_peers != nullptr) {
        g_peers->erase(s);
    }
    ReleaseSRWLockExclusive(&g_peersLock);
}

constexpr ULONGLONG kUdpDecisionLifetimeMs = 30000;
constexpr size_t kMaxUdpDecisions = 1024;

struct UdpDecision {
    Verdict verdict;
    ULONGLONG expires;
};

SRWLOCK g_udpLock = SRWLOCK_INIT;
std::unordered_map<std::string, UdpDecision>* g_udpDecisions = nullptr;

std::string UdpKey(const Endpoint& endpoint) {
    std::string key(reinterpret_cast<const char*>(endpoint.address), endpoint.family == 4 ? 4 : 16);
    key.push_back(static_cast<char>(endpoint.port & 0xff));
    key.push_back(static_cast<char>(endpoint.port >> 8));
    return key;
}

// ---------------------------------------------------------------------------------------------------------------
// Decisions

int SocketType(SOCKET s) {
    int type = 0;
    int length = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &length) == 0 ? type : 0;
}

bool IsUnspecified(const Endpoint& endpoint) {
    static const uint8_t kZero[16] = {};
    return memcmp(endpoint.address, kZero, endpoint.family == 4 ? 4 : 16) == 0;
}

void SetLoopback(Endpoint* endpoint) {
    memset(endpoint->address, 0, sizeof(endpoint->address));
    if (endpoint->family == 4) {
        endpoint->address[0] = 127;
        endpoint->address[3] = 1;
    } else {
        endpoint->address[15] = 1;
        endpoint->scopeId = 0;
    }
}

// The endpoint the socket will connect to the relay from: the relay looks the original destination up by it.
// Unbound sockets are bound to the wildcard address first, so the socket still works if the answer is "direct";
// connecting a wildcard-bound socket to the loopback relay uses the loopback address.
bool LocalEndpointForRelay(SOCKET s, int family, Endpoint* local) {
    sockaddr_storage bound = {};
    int length = sizeof(bound);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
        if (WSAGetLastError() != WSAEINVAL) {
            return false;
        }
        sockaddr_storage any = {};
        any.ss_family = static_cast<ADDRESS_FAMILY>(family);
        int anyLength = family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        if (bind(s, reinterpret_cast<sockaddr*>(&any), anyLength) != 0) {
            return false;
        }
        length = sizeof(bound);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
            return false;
        }
    }
    if (!EndpointFromSockaddr(reinterpret_cast<sockaddr*>(&bound), length, local)) {
        return false;
    }
    if (IsUnspecified(*local)) {
        SetLoopback(local);
    }
    return true;
}

struct TcpDecision {
    Verdict verdict = Verdict::Direct;
    sockaddr_storage relay = {};
    int relayLength = 0;
};

// Asks the service about a TCP connect. Anything that is not an IPv4/IPv6 destination, and loopback, goes direct
// without asking; if the service cannot be reached, the connection is refused (fail closed).
TcpDecision DecideTcp(SOCKET s, const sockaddr* name, int length) {
    TcpDecision decision;
    Endpoint remote;
    if (!EndpointFromSockaddr(name, length, &remote) || IsLoopback(remote) || IsUnspecified(remote)) {
        return decision;
    }

    LastErrorScope preserve;
    decision.verdict = Verdict::Block;
    ConnectQuery query = {};
    query.transport = Transport::Tcp;
    query.remote = remote;
    if (!LocalEndpointForRelay(s, name->sa_family, &query.local)) {
        Log(L"Cannot bind a socket before redirecting it (error %d); refusing the connection", WSAGetLastError());
        return decision;
    }
    char hostname[kMaxHostname + 1];
    query.hostname = LookupHostname(name, length, hostname, sizeof(hostname)) ? hostname : nullptr;

    ConnectAnswer answer;
    if (!QueryConnect(query, &answer)) {
        return decision;
    }
    decision.verdict = answer.verdict;
    if (answer.verdict == Verdict::Relay && !EndpointToSockaddr(answer.relay, name->sa_family, &decision.relay, &decision.relayLength)) {
        decision.verdict = Verdict::Block;
    }
    return decision;
}

// UDP: direct or block. Decisions are cached per destination for a short while (sends are frequent).
Verdict DecideUdp(const sockaddr* to, int length) {
    Endpoint remote;
    if (!EndpointFromSockaddr(to, length, &remote) || IsLoopback(remote) || IsUnspecified(remote)) {
        return Verdict::Direct;
    }

    LastErrorScope preserve;
    std::string key = UdpKey(remote);
    ULONGLONG now = GetTickCount64();
    AcquireSRWLockShared(&g_udpLock);
    if (g_udpDecisions != nullptr) {
        auto entry = g_udpDecisions->find(key);
        if (entry != g_udpDecisions->end() && entry->second.expires > now) {
            Verdict cached = entry->second.verdict;
            ReleaseSRWLockShared(&g_udpLock);
            return cached;
        }
    }
    ReleaseSRWLockShared(&g_udpLock);

    ConnectQuery query = {};
    query.transport = Transport::Udp;
    query.local.family = remote.family;
    query.remote = remote;
    char hostname[kMaxHostname + 1];
    query.hostname = LookupHostname(to, length, hostname, sizeof(hostname)) ? hostname : nullptr;
    ConnectAnswer answer;
    Verdict verdict = QueryConnect(query, &answer) && answer.verdict == Verdict::Direct ? Verdict::Direct : Verdict::Block;

    AcquireSRWLockExclusive(&g_udpLock);
    if (g_udpDecisions == nullptr) {
        g_udpDecisions = new std::unordered_map<std::string, UdpDecision>();
    }
    if (g_udpDecisions->size() >= kMaxUdpDecisions) {
        g_udpDecisions->clear();
    }
    (*g_udpDecisions)[key] = UdpDecision{verdict, now + kUdpDecisionLifetimeMs};
    ReleaseSRWLockExclusive(&g_udpLock);
    return verdict;
}

// The common connect path: call(target, length) performs the real connect variant.
template <typename Call>
int ConnectCommon(SOCKET s, const sockaddr* name, int length, Call call) {
    int type = SocketType(s);
    if (type == SOCK_DGRAM) {
        if (DecideUdp(name, length) == Verdict::Block) {
            WSASetLastError(WSAENETUNREACH);
            return SOCKET_ERROR;
        }
        return call(name, length);
    }
    if (type != SOCK_STREAM) {
        return call(name, length);
    }

    TcpDecision decision = DecideTcp(s, name, length);
    switch (decision.verdict) {
        case Verdict::Direct:
            return call(name, length);
        case Verdict::Block:
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        default: {
            int result = call(reinterpret_cast<const sockaddr*>(&decision.relay), decision.relayLength);
            int error = WSAGetLastError();
            if (result == 0 || error == WSAEWOULDBLOCK) {
                RememberPeer(s, name, length);
            }
            WSASetLastError(error);
            return result;
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Hooks

int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    ReentrancyGuard guard;
    if (guard.Nested() || name == nullptr) {
        return Real_connect(s, name, namelen);
    }
    return ConnectCommon(s, name, namelen, [&](const sockaddr* target, int length) { return Real_connect(s, target, length); });
}

int WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos,
                           LPQOS gqos) {
    ReentrancyGuard guard;
    if (guard.Nested() || name == nullptr) {
        return Real_WSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
    }
    return ConnectCommon(s, name, namelen, [&](const sockaddr* target, int length) {
        return Real_WSAConnect(s, target, length, callerData, calleeData, sqos, gqos);
    });
}

// Waits for a non-blocking connect started by ConnectCommon.
int CompleteConnect(SOCKET s, int result, const timeval* timeout) {
    if (result == 0 || WSAGetLastError() != WSAEWOULDBLOCK) {
        return result;
    }
    fd_set writable;
    fd_set failed;
    FD_ZERO(&writable);
    FD_ZERO(&failed);
    FD_SET(s, &writable);
    FD_SET(s, &failed);
    int ready = select(0, nullptr, &writable, &failed, timeout);
    if (ready <= 0) {
        WSASetLastError(ready == 0 ? WSAETIMEDOUT : WSAGetLastError());
        return SOCKET_ERROR;
    }
    int error = 0;
    int length = sizeof(error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0 || error != 0) {
        WSASetLastError(error != 0 ? error : WSAGetLastError());
        return SOCKET_ERROR;
    }
    return 0;
}

void CopyAddress(const sockaddr* source, int sourceLength, LPDWORD length, LPSOCKADDR destination) {
    if (length == nullptr || destination == nullptr) {
        return;
    }
    DWORD copied = static_cast<DWORD>(sourceLength) < *length ? static_cast<DWORD>(sourceLength) : *length;
    memcpy(destination, source, copied);
    *length = copied;
}

// WSAConnectByName resolves and connects inside Winsock, so it is reimplemented on top of the hooked paths.
BOOL ConnectByName(SOCKET s, PCWSTR node, PCWSTR service, LPDWORD localLength, LPSOCKADDR localAddress, LPDWORD remoteLength,
                   LPSOCKADDR remoteAddress, const timeval* timeout) {
    WSAPROTOCOL_INFOW info = {};
    int infoLength = sizeof(info);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, reinterpret_cast<char*>(&info), &infoLength) != 0) {
        return FALSE;
    }
    int family = info.iAddressFamily;
    ADDRINFOW hints = {};
    hints.ai_family = family == AF_INET6 ? AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    PADDRINFOW results = nullptr;
    int error = ResolveForConnect(node, service, &hints, &results);
    if (error != 0) {
        WSASetLastError(error);
        return FALSE;
    }

    int lastError = WSAHOST_NOT_FOUND;
    BOOL connected = FALSE;
    for (PADDRINFOW entry = results; entry != nullptr && !connected; entry = entry->ai_next) {
        Endpoint endpoint;
        sockaddr_storage target;
        int targetLength = 0;
        if (!EndpointFromSockaddr(entry->ai_addr, static_cast<int>(entry->ai_addrlen), &endpoint) ||
            !EndpointToSockaddr(endpoint, family, &target, &targetLength)) {
            continue;
        }
        const auto* address = reinterpret_cast<const sockaddr*>(&target);
        int result = ConnectCommon(s, address, targetLength, [&](const sockaddr* to, int length) { return Real_connect(s, to, length); });
        if (CompleteConnect(s, result, timeout) == 0) {
            connected = TRUE;
            sockaddr_storage local = {};
            int length = sizeof(local);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &length) == 0) {
                CopyAddress(reinterpret_cast<sockaddr*>(&local), length, localLength, localAddress);
            }
            CopyAddress(address, targetLength, remoteLength, remoteAddress);
        } else {
            lastError = WSAGetLastError();
        }
    }
    FreeAddrInfoW(results);
    if (!connected) {
        WSASetLastError(lastError);
    }
    return connected;
}

BOOL WSAAPI Hook_WSAConnectByNameW(SOCKET s, LPWSTR nodename, LPWSTR servicename, LPDWORD LocalAddressLength,
                                   LPSOCKADDR LocalAddress, LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                   const struct timeval* timeout, LPWSAOVERLAPPED Reserved) {
    ReentrancyGuard guard;
    if (guard.Nested() || nodename == nullptr || servicename == nullptr) {
        return Real_WSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress,
                                      timeout, Reserved);
    }
    return ConnectByName(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout);
}

#ifdef __MINGW32__
using ConnectByNameAString = LPSTR;  // older SDK declaration; only used to syntax-check the sources with MinGW
#else
using ConnectByNameAString = LPCSTR;
#endif

BOOL WSAAPI Hook_WSAConnectByNameA(SOCKET s, ConnectByNameAString nodename, ConnectByNameAString servicename, LPDWORD LocalAddressLength,
                                   LPSOCKADDR LocalAddress, LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress,
                                   const struct timeval* timeout, LPWSAOVERLAPPED Reserved) {
    ReentrancyGuard guard;
    wchar_t node[NI_MAXHOST];
    wchar_t service[NI_MAXSERV];
    if (guard.Nested() || nodename == nullptr || servicename == nullptr ||
        MultiByteToWideChar(CP_ACP, 0, nodename, -1, node, NI_MAXHOST) == 0 ||
        MultiByteToWideChar(CP_ACP, 0, servicename, -1, service, NI_MAXSERV) == 0) {
        return Real_WSAConnectByNameA(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress,
                                      timeout, Reserved);
    }
    return ConnectByName(s, node, service, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout);
}

// ConnectEx comes from WSAIoctl as a function pointer. Each distinct implementation found is detoured into a slot.
constexpr int kConnectExSlots = 4;
LPFN_CONNECTEX g_connectExReal[kConnectExSlots] = {};
void* g_connectExTarget[kConnectExSlots] = {};
SRWLOCK g_connectExLock = SRWLOCK_INIT;

template <int Slot>
BOOL PASCAL Hook_ConnectEx(SOCKET s, const sockaddr* name, int namelen, PVOID sendBuffer, DWORD sendLength, LPDWORD bytesSent,
                           LPOVERLAPPED overlapped) {
    ReentrancyGuard guard;
    LPFN_CONNECTEX real = g_connectExReal[Slot];
    if (guard.Nested() || name == nullptr) {
        return real(s, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
    }
    TcpDecision decision = DecideTcp(s, name, namelen);
    switch (decision.verdict) {
        case Verdict::Direct:
            return real(s, name, namelen, sendBuffer, sendLength, bytesSent, overlapped);
        case Verdict::Block:
            WSASetLastError(WSAECONNREFUSED);
            return FALSE;
        default: {
            BOOL result = real(s, reinterpret_cast<const sockaddr*>(&decision.relay), decision.relayLength, sendBuffer, sendLength,
                               bytesSent, overlapped);
            int error = WSAGetLastError();
            if (result || error == ERROR_IO_PENDING) {
                RememberPeer(s, name, namelen);
            }
            WSASetLastError(error);
            return result;
        }
    }
}

const PVOID kConnectExHooks[kConnectExSlots] = {
    reinterpret_cast<PVOID>(&Hook_ConnectEx<0>),
    reinterpret_cast<PVOID>(&Hook_ConnectEx<1>),
    reinterpret_cast<PVOID>(&Hook_ConnectEx<2>),
    reinterpret_cast<PVOID>(&Hook_ConnectEx<3>),
};

void HookConnectEx(void* target) {
    if (target == nullptr || !HooksActive()) {
        return;
    }
    AcquireSRWLockExclusive(&g_connectExLock);
    int free = -1;
    for (int i = 0; i < kConnectExSlots; ++i) {
        if (g_connectExTarget[i] == target) {
            ReleaseSRWLockExclusive(&g_connectExLock);
            return;
        }
        if (g_connectExTarget[i] == nullptr && free < 0) {
            free = i;
        }
    }
    if (free < 0) {
        Log(L"Too many ConnectEx implementations; one at %p is not hooked", target);
    } else {
        g_connectExReal[free] = reinterpret_cast<LPFN_CONNECTEX>(target);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<PVOID*>(&g_connectExReal[free]), kConnectExHooks[free]);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR) {
            g_connectExTarget[free] = target;
        } else {
            g_connectExReal[free] = nullptr;
            Log(L"Cannot hook ConnectEx at %p: Detours error %ld", target, error);
        }
    }
    ReleaseSRWLockExclusive(&g_connectExLock);
}

void HookConnectExFrom(SOCKET s) {
    GUID guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX function = nullptr;
    DWORD bytes = 0;
    if (Real_WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &function, sizeof(function), &bytes, nullptr, nullptr) ==
        0) {
        HookConnectEx(reinterpret_cast<void*>(function));
    }
}

DWORD WINAPI DiscoverConnectEx(LPVOID) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return 0;
    }
    for (int family : {AF_INET, AF_INET6}) {
        SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            HookConnectExFrom(s);
            Real_closesocket(s);
        }
    }
    WSACleanup();
    return 0;
}

int WSAAPI Hook_WSAIoctl(SOCKET s, DWORD code, LPVOID inBuffer, DWORD inLength, LPVOID outBuffer, DWORD outLength, LPDWORD returned,
                         LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    int result = Real_WSAIoctl(s, code, inBuffer, inLength, outBuffer, outLength, returned, overlapped, completion);
    if (result == 0 && code == SIO_GET_EXTENSION_FUNCTION_POINTER && inBuffer != nullptr && inLength >= sizeof(GUID) &&
        outBuffer != nullptr && outLength >= sizeof(void*)) {
        GUID connectEx = WSAID_CONNECTEX;
        if (memcmp(inBuffer, &connectEx, sizeof(GUID)) == 0) {
            LastErrorScope preserve;
            HookConnectEx(*static_cast<void**>(outBuffer));
        }
    }
    return result;
}

int WSAAPI Hook_getpeername(SOCKET s, sockaddr* name, int* namelen) {
    int result = Real_getpeername(s, name, namelen);
    if (result != 0 || name == nullptr || namelen == nullptr) {
        return result;
    }
    LastErrorScope preserve;
    sockaddr_storage original;
    if (LookupPeer(s, &original)) {
        // Report the original destination, not the relay. It has the socket's family, like the relay address.
        int length = original.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        if (length <= *namelen) {
            memcpy(name, &original, length);
            *namelen = length;
        }
    }
    return result;
}

int WSAAPI Hook_closesocket(SOCKET s) {
    {
        LastErrorScope preserve;
        ForgetPeer(s);
    }
    return Real_closesocket(s);
}

bool BlockedUdp(SOCKET s, const sockaddr* to, int length) {
    return to != nullptr && SocketType(s) == SOCK_DGRAM && DecideUdp(to, length) == Verdict::Block;
}

int WSAAPI Hook_sendto(SOCKET s, const char* buffer, int length, int flags, const sockaddr* to, int tolen) {
    ReentrancyGuard guard;
    if (!guard.Nested() && BlockedUdp(s, to, tolen)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    return Real_sendto(s, buffer, length, flags, to, tolen);
}

int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD sent, DWORD flags, const sockaddr* to, int tolen,
                          LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    ReentrancyGuard guard;
    if (!guard.Nested() && BlockedUdp(s, to, tolen)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    return Real_WSASendTo(s, buffers, count, sent, flags, to, tolen, overlapped, completion);
}

int WSAAPI Hook_WSASendMsg(SOCKET s, LPWSAMSG message, DWORD flags, LPDWORD sent, LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    ReentrancyGuard guard;
    if (!guard.Nested() && message != nullptr && BlockedUdp(s, message->name, message->namelen)) {
        WSASetLastError(WSAENETUNREACH);
        return SOCKET_ERROR;
    }
    return Real_WSASendMsg(s, message, flags, sent, overlapped, completion);
}

// The hooks must have exactly the signatures of the functions they replace.
static_assert(std::is_same_v<decltype(&Hook_connect), decltype(Real_connect)>);
static_assert(std::is_same_v<decltype(&Hook_WSAConnect), decltype(Real_WSAConnect)>);
static_assert(std::is_same_v<decltype(&Hook_WSAConnectByNameW), decltype(Real_WSAConnectByNameW)>);
static_assert(std::is_same_v<decltype(&Hook_WSAConnectByNameA), decltype(Real_WSAConnectByNameA)>);
static_assert(std::is_same_v<decltype(&Hook_WSAIoctl), decltype(Real_WSAIoctl)>);
static_assert(std::is_same_v<decltype(&Hook_getpeername), decltype(Real_getpeername)>);
static_assert(std::is_same_v<decltype(&Hook_closesocket), decltype(Real_closesocket)>);
static_assert(std::is_same_v<decltype(&Hook_sendto), decltype(Real_sendto)>);
static_assert(std::is_same_v<decltype(&Hook_WSASendTo), decltype(Real_WSASendTo)>);
static_assert(std::is_same_v<decltype(&Hook_WSASendMsg), decltype(Real_WSASendMsg)>);
static_assert(std::is_same_v<decltype(&Hook_ConnectEx<0>), LPFN_CONNECTEX>);

#define PROXYNATOR_HOOK(function) {reinterpret_cast<PVOID*>(&Real_##function), reinterpret_cast<PVOID>(&Hook_##function), L## #function}

const HookEntry kEntries[] = {
    PROXYNATOR_HOOK(connect),
    PROXYNATOR_HOOK(WSAConnect),
    PROXYNATOR_HOOK(WSAConnectByNameW),
    PROXYNATOR_HOOK(WSAConnectByNameA),
    PROXYNATOR_HOOK(WSAIoctl),
    PROXYNATOR_HOOK(getpeername),
    PROXYNATOR_HOOK(closesocket),
    PROXYNATOR_HOOK(sendto),
    PROXYNATOR_HOOK(WSASendTo),
    PROXYNATOR_HOOK(WSASendMsg),
};

}  // namespace

const HookEntry* SocketHooks(size_t* count) {
    *count = sizeof(kEntries) / sizeof(kEntries[0]);
    return kEntries;
}

void StartConnectExDiscovery() {
    HANDLE thread = CreateThread(nullptr, 0, DiscoverConnectEx, nullptr, 0, nullptr);
    if (thread != nullptr) {
        CloseHandle(thread);
    }
}

void DetachConnectEx() {
    AcquireSRWLockExclusive(&g_connectExLock);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (int i = 0; i < kConnectExSlots; ++i) {
        if (g_connectExTarget[i] != nullptr) {
            DetourDetach(reinterpret_cast<PVOID*>(&g_connectExReal[i]), kConnectExHooks[i]);
            g_connectExTarget[i] = nullptr;
        }
    }
    DetourTransactionCommit();
    ReleaseSRWLockExclusive(&g_connectExLock);
}

}  // namespace proxynator
