#include "service_client.h"

#include <windows.h>

#include "hook_state.h"
#include "log.h"

namespace proxynator {

namespace {

constexpr DWORD kIoTimeoutMs = 15000;
constexpr DWORD kPipeBusyWaitMs = 2000;
constexpr int kConnectAttempts = 5;

SRWLOCK g_lock = SRWLOCK_INIT;
HANDLE g_pipe = INVALID_HANDLE_VALUE;
HANDLE g_event = nullptr;
bool g_reportedFailure = false;

void Disconnect() {
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

// Reads or writes exactly length bytes, giving up after kIoTimeoutMs per operation.
bool Transfer(bool write, uint8_t* data, DWORD length) {
    DWORD done = 0;
    while (done < length) {
        OVERLAPPED overlapped = {};
        overlapped.hEvent = g_event;
        ResetEvent(g_event);
        BOOL ok = write ? WriteFile(g_pipe, data + done, length - done, nullptr, &overlapped)
                        : ReadFile(g_pipe, data + done, length - done, nullptr, &overlapped);
        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            return false;
        }
        if (WaitForSingleObject(g_event, kIoTimeoutMs) != WAIT_OBJECT_0) {
            CancelIoEx(g_pipe, &overlapped);
            DWORD ignored = 0;
            GetOverlappedResult(g_pipe, &overlapped, &ignored, TRUE);
            return false;
        }
        DWORD transferred = 0;
        if (!GetOverlappedResult(g_pipe, &overlapped, &transferred, FALSE) || transferred == 0) {
            return false;
        }
        done += transferred;
    }
    return true;
}

bool Exchange(const Writer& request, MessageType type, uint8_t* response, size_t* responseLength) {
    if (!request.Ok()) {
        return false;
    }
    if (!Transfer(true, const_cast<uint8_t*>(request.Frame()), static_cast<DWORD>(request.FrameLength()))) {
        return false;
    }
    uint8_t header[4];
    if (!Transfer(false, header, 4)) {
        return false;
    }
    uint32_t length = header[0] | (header[1] << 8) | (header[2] << 16) | (static_cast<uint32_t>(header[3]) << 24);
    if (length < 2 || length > kMaxBody) {
        return false;
    }
    if (!Transfer(false, response, length)) {
        return false;
    }
    *responseLength = length;
    return response[0] == kProtocolVersion && response[1] == static_cast<uint8_t>(type);
}

bool Connect() {
    if (g_event == nullptr) {
        g_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (g_event == nullptr) {
            return false;
        }
    }
    for (int attempt = 0; attempt < kConnectAttempts; ++attempt) {
        // SECURITY_IDENTIFICATION: whoever serves the pipe may identify, but never impersonate, this process.
        g_pipe = CreateFileW(g_payload.pipePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (g_pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        if (GetLastError() != ERROR_PIPE_BUSY) {
            return false;
        }
        WaitNamedPipeW(g_payload.pipePath, kPipeBusyWaitMs);
    }
    if (g_pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    Writer hello(MessageType::Hello);
    hello.U8(sizeof(void*) * 8);
    uint8_t response[kMaxBody];
    size_t length = 0;
    if (!Exchange(hello, MessageType::Hello, response, &length)) {
        Disconnect();
        return false;
    }
    return true;
}

// Sends the request (connecting or reconnecting once if needed) and returns the response body.
bool Request(const Writer& request, MessageType type, uint8_t* response, size_t* length) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (g_pipe == INVALID_HANDLE_VALUE && !Connect()) {
            break;
        }
        if (Exchange(request, type, response, length)) {
            g_reportedFailure = false;
            return true;
        }
        Disconnect();
    }
    if (!g_reportedFailure) {
        g_reportedFailure = true;
        Log(L"proxynatord is not reachable at %s (error %lu); new connections are refused", g_payload.pipePath, GetLastError());
    }
    return false;
}

class LockScope {
public:
    LockScope() { AcquireSRWLockExclusive(&g_lock); }
    ~LockScope() { ReleaseSRWLockExclusive(&g_lock); }
    LockScope(const LockScope&) = delete;
    LockScope& operator=(const LockScope&) = delete;
};

}  // namespace

bool QueryConnect(const ConnectQuery& query, ConnectAnswer* answer) {
    Writer request(MessageType::Connect);
    request.U8(static_cast<uint8_t>(query.transport));
    request.Address(query.local);
    request.Address(query.remote);
    request.String(query.hostname);

    uint8_t response[kMaxBody];
    size_t length = 0;
    {
        LastErrorScope preserve;
        LockScope lock;
        if (!Request(request, MessageType::Connect, response, &length)) {
            return false;
        }
    }

    Reader reader(response, length);
    uint8_t verdict = 0;
    if (!reader.Header(MessageType::Connect) || !reader.U8(&verdict) || verdict > static_cast<uint8_t>(Verdict::Block)) {
        return false;
    }
    answer->verdict = static_cast<Verdict>(verdict);
    if (answer->verdict == Verdict::Relay) {
        // The relay is always local; anything else would send this process's traffic somewhere unexpected.
        if (!reader.Address(&answer->relay) || !IsLoopback(answer->relay)) {
            return false;
        }
    }
    return reader.AtEnd();
}

bool QueryResolve(const char* hostname, bool* faked, uint8_t fakeAddress[4]) {
    Writer request(MessageType::Resolve);
    request.String(hostname);

    uint8_t response[kMaxBody];
    size_t length = 0;
    {
        LastErrorScope preserve;
        LockScope lock;
        if (!Request(request, MessageType::Resolve, response, &length)) {
            return false;
        }
    }

    Reader reader(response, length);
    uint8_t result = 0;
    if (!reader.Header(MessageType::Resolve) || !reader.U8(&result) || result > 1) {
        return false;
    }
    *faked = result == 1;
    if (*faked && !reader.Bytes(fakeAddress, 4)) {
        return false;
    }
    return reader.AtEnd();
}

}  // namespace proxynator
