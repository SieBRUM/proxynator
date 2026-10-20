// Declarations shared by the hook modules.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstddef>

#include "payload.h"

namespace proxynator {

// One detoured function: *real holds the original (a trampoline once attached), hook replaces it.
struct HookEntry {
    PVOID* real;
    PVOID hook;
    const wchar_t* name;
};

// Within an open Detours transaction.
bool AttachEntries(const HookEntry* entries, size_t count);
void DetachEntries(const HookEntry* entries, size_t count);

// Each module's detours. The process hooks need CreateProcessInternalW, looked up at runtime.
const HookEntry* SocketHooks(size_t* count);
const HookEntry* ResolverHooks(size_t* count);
const HookEntry* ProcessHooks(size_t* count);

// ConnectEx is not exported; it is detoured when found (a helper thread looks it up at start, and every
// WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) result is checked).
void StartConnectExDiscovery();
void DetachConnectEx();

// The resolver logic (fake addresses in remote DNS mode, hostname hints) for callers inside the hook.
int ResolveForConnect(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* results);

// Loads the hook DLL of the target's bitness into a process created suspended and hands it the payload.
DWORD InjectIntoSuspendedProcess(HANDLE process, DWORD processId, const HookPayload& payload);

}  // namespace proxynator
