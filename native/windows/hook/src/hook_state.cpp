#include "hook_state.h"

#include <cwchar>

namespace proxynator {

HookPayload g_payload = {};
HMODULE g_module = nullptr;

namespace {

volatile LONG g_active = 0;
thread_local int t_depth = 0;

bool ModuleDirectory(wchar_t* buffer, size_t size) {
    DWORD length = GetModuleFileNameW(g_module, buffer, static_cast<DWORD>(size));
    if (length == 0 || length >= size) {
        return false;
    }
    wchar_t* slash = wcsrchr(buffer, L'\\');
    if (slash == nullptr) {
        return false;
    }
    slash[1] = L'\0';
    return true;
}

}  // namespace

bool HooksActive() { return InterlockedCompareExchange(&g_active, 0, 0) != 0; }

void SetHooksActive(bool active) { InterlockedExchange(&g_active, active ? 1 : 0); }

bool HookDllPathW(bool target64, wchar_t* buffer, size_t size) {
    if (!ModuleDirectory(buffer, size)) {
        return false;
    }
    const wchar_t* name = target64 ? L"proxynator-hook64.dll" : L"proxynator-hook32.dll";
    return wcscat_s(buffer, size, name) == 0;
}

bool HookDllPathA(bool target64, char* buffer, size_t size) {
    wchar_t wide[MAX_PATH * 2];
    if (!HookDllPathW(target64, wide, MAX_PATH * 2)) {
        return false;
    }
    BOOL lossy = FALSE;
    int written = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wide, -1, buffer, static_cast<int>(size), nullptr, &lossy);
    if (written > 0 && !lossy) {
        return true;
    }
    wchar_t shortPath[MAX_PATH];
    DWORD length = GetShortPathNameW(wide, shortPath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    lossy = FALSE;
    written = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, shortPath, -1, buffer, static_cast<int>(size), nullptr, &lossy);
    return written > 0 && !lossy;
}

ReentrancyGuard::ReentrancyGuard() : nested_(t_depth > 0) { ++t_depth; }

ReentrancyGuard::~ReentrancyGuard() { --t_depth; }

}  // namespace proxynator
