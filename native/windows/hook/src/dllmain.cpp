// Entry point. Hooks are installed only in processes that carry the Proxynator payload (started or attached by
// proxynator, or created by a hooked process). Elsewhere the DLL only provides its exports: the CLI calls them, and
// Detours runs ordinal 1 in a rundll32 helper to inject into processes of the other bitness.
#include <winsock2.h>
#include <windows.h>

#include <detours.h>

#include "hook_state.h"
#include "hooks.h"
#include "log.h"

namespace proxynator {

bool AttachEntries(const HookEntry* entries, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (*entries[i].real == nullptr) {
            Log(L"Cannot hook %s: function not found", entries[i].name);
            return false;
        }
        LONG error = DetourAttach(entries[i].real, entries[i].hook);
        if (error != NO_ERROR) {
            Log(L"Cannot hook %s: Detours error %ld", entries[i].name, error);
            return false;
        }
    }
    return true;
}

void DetachEntries(const HookEntry* entries, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        DetourDetach(entries[i].real, entries[i].hook);
    }
}

namespace {

using EntriesFunction = const HookEntry* (*)(size_t*);
const EntriesFunction kModules[] = {SocketHooks, ResolverHooks, ProcessHooks};

bool InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (EntriesFunction module : kModules) {
        size_t count = 0;
        const HookEntry* entries = module(&count);
        if (!AttachEntries(entries, count)) {
            DetourTransactionAbort();
            return false;
        }
    }
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        Log(L"Installing the hooks failed: Detours error %ld", error);
        return false;
    }
    return true;
}

void RemoveHooks() {
    DetachConnectEx();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    for (EntriesFunction module : kModules) {
        size_t count = 0;
        const HookEntry* entries = module(&count);
        DetachEntries(entries, count);
    }
    DetourTransactionCommit();
}

}  // namespace

}  // namespace proxynator

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    using namespace proxynator;
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (reason == DLL_PROCESS_ATTACH) {
        g_module = instance;
        DisableThreadLibraryCalls(instance);
        DetourRestoreAfterWith();

        DWORD size = 0;
        const auto* payload = static_cast<const HookPayload*>(DetourFindPayloadEx(kPayloadGuid, &size));
        if (payload == nullptr || size < sizeof(HookPayload) || payload->version != kPayloadVersion) {
            return TRUE;
        }
        g_payload = *payload;
        g_payload.pipePath[kMaxPipePath - 1] = L'\0';

        InitializeLog();
        if (!InstallHooks()) {
            // Fail closed: a process that cannot be hooked must not run unhooked (it would bypass the rules).
            Log(L"Hooks could not be installed; refusing to load");
            return FALSE;
        }
        SetHooksActive(true);
        Log(L"Hooks installed (%d-bit); proxynatord at %s", static_cast<int>(sizeof(void*) * 8), g_payload.pipePath);
        StartConnectExDiscovery();
    } else if (reason == DLL_PROCESS_DETACH && reserved == nullptr && HooksActive()) {
        // FreeLibrary (not process exit): restore the original functions.
        RemoveHooks();
        SetHooksActive(false);
    }
    return TRUE;
}
