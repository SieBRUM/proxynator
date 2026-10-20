// Process-wide state of the hook and the per-thread reentrancy guard.
#pragma once

#include <windows.h>

#include "payload.h"

namespace proxynator {

// Set once in DllMain when the process carries the payload; read-only afterwards.
extern HookPayload g_payload;
extern HMODULE g_module;

// Whether the hooks are installed in this process (false in the CLI and in rundll32 helpers).
bool HooksActive();
void SetHooksActive(bool active);

// The full path of the hook DLL for a 64-bit or 32-bit target, next to this DLL. ANSI because Detours takes ANSI
// DLL names; falls back to the short (8.3) path when the path does not fit the ANSI code page.
bool HookDllPathA(bool target64, char* buffer, size_t size);
bool HookDllPathW(bool target64, wchar_t* buffer, size_t size);

// Hooks call into Winsock and the resolver themselves, and Winsock functions call each other internally (Detours
// patches the function bodies, so internal calls are hooked as well). Only the outermost hook on a thread acts.
class ReentrancyGuard {
public:
    ReentrancyGuard();
    ~ReentrancyGuard();
    ReentrancyGuard(const ReentrancyGuard&) = delete;
    ReentrancyGuard& operator=(const ReentrancyGuard&) = delete;

    // True when another hook on this thread is already active: call the real function and do nothing else.
    bool Nested() const { return nested_; }

private:
    bool nested_;
};

// Preserves the thread's last error (and so WSAGetLastError) across bookkeeping calls.
class LastErrorScope {
public:
    LastErrorScope() : error_(GetLastError()) {}
    ~LastErrorScope() { SetLastError(error_); }
    LastErrorScope(const LastErrorScope&) = delete;
    LastErrorScope& operator=(const LastErrorScope&) = delete;

private:
    DWORD error_;
};

}  // namespace proxynator
