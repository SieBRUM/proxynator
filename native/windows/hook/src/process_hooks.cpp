// Child propagation: every process a hooked process creates is created suspended, gets the hook DLL of its bitness
// and the payload, and only then runs. CreateProcessInternalW (kernelbase) is the function all CreateProcess*
// variants (A/W, AsUser, ShellExecute's process launches, ...) end up in.
#include <windows.h>

#include <initializer_list>

#include "hook_state.h"
#include "hooks.h"
#include "log.h"

namespace proxynator {

namespace {

using CreateProcessInternalW_t = BOOL(WINAPI*)(HANDLE token, LPCWSTR applicationName, LPWSTR commandLine,
                                               LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
                                               BOOL inheritHandles, DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory,
                                               LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation, PHANDLE newToken);

CreateProcessInternalW_t Real_CreateProcessInternalW = nullptr;

BOOL WINAPI Hook_CreateProcessInternalW(HANDLE token, LPCWSTR applicationName, LPWSTR commandLine, LPSECURITY_ATTRIBUTES processAttributes,
                                        LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environment,
                                        LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo, LPPROCESS_INFORMATION processInformation,
                                        PHANDLE newToken) {
    ReentrancyGuard guard;
    if (guard.Nested() || processInformation == nullptr) {
        return Real_CreateProcessInternalW(token, applicationName, commandLine, processAttributes, threadAttributes, inheritHandles,
                                           creationFlags, environment, currentDirectory, startupInfo, processInformation, newToken);
    }
    if (!Real_CreateProcessInternalW(token, applicationName, commandLine, processAttributes, threadAttributes, inheritHandles,
                                     creationFlags | CREATE_SUSPENDED, environment, currentDirectory, startupInfo, processInformation,
                                     newToken)) {
        return FALSE;
    }
    DWORD createError = GetLastError();

    DWORD error = InjectIntoSuspendedProcess(processInformation->hProcess, processInformation->dwProcessId, g_payload);
    if (error != ERROR_SUCCESS) {
        // Fail closed: an unhooked child would bypass the rules.
        Log(L"Cannot hook child process %lu (%s): error %lu; it was terminated", processInformation->dwProcessId,
            applicationName != nullptr ? applicationName : (commandLine != nullptr ? commandLine : L"?"), error);
        TerminateProcess(processInformation->hProcess, error);
        CloseHandle(processInformation->hThread);
        CloseHandle(processInformation->hProcess);
        ZeroMemory(processInformation, sizeof(*processInformation));
        SetLastError(error);
        return FALSE;
    }

    if ((creationFlags & CREATE_SUSPENDED) == 0) {
        ResumeThread(processInformation->hThread);
    }
    SetLastError(createError);
    return TRUE;
}

HookEntry g_entries[] = {
    {reinterpret_cast<PVOID*>(&Real_CreateProcessInternalW), reinterpret_cast<PVOID>(&Hook_CreateProcessInternalW), L"CreateProcessInternalW"},
};

}  // namespace

const HookEntry* ProcessHooks(size_t* count) {
    if (Real_CreateProcessInternalW == nullptr) {
        for (const wchar_t* module : {L"kernelbase.dll", L"kernel32.dll"}) {
            HMODULE handle = GetModuleHandleW(module);
            if (handle != nullptr) {
                Real_CreateProcessInternalW =
                    reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(handle, "CreateProcessInternalW"));
                if (Real_CreateProcessInternalW != nullptr) {
                    break;
                }
            }
        }
    }
    *count = sizeof(g_entries) / sizeof(g_entries[0]);
    return g_entries;
}

}  // namespace proxynator
