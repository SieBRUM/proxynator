// Injection: the exports used by the CLI (start a process with the hook, attach to a running one) and the helper
// that hooks children of hooked processes.
#include <windows.h>
#include <tlhelp32.h>

#include <detours.h>

#include <cwchar>

#include "hook_state.h"
#include "hooks.h"
#include "log.h"

namespace proxynator {

namespace {

constexpr DWORD kAttachTimeoutMs = 30000;

bool Is64BitProcess(HANDLE process) {
#ifndef _WIN64
    BOOL selfWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &selfWow64) || !selfWow64) {
        return false;  // 32-bit Windows
    }
#endif
    BOOL wow64 = FALSE;
    return IsWow64Process(process, &wow64) && !wow64;
}

constexpr bool kSelf64 = sizeof(void*) == 8;

bool MakePayload(LPCWSTR pipePath, HookPayload* payload) {
    if (pipePath == nullptr || wcslen(pipePath) == 0 || wcslen(pipePath) >= kMaxPipePath) {
        return false;
    }
    ZeroMemory(payload, sizeof(*payload));
    payload->version = kPayloadVersion;
    wcscpy_s(payload->pipePath, pipePath);
    return true;
}

DWORD ErrorOr(DWORD fallback) {
    DWORD error = GetLastError();
    return error != ERROR_SUCCESS ? error : fallback;
}

bool IsModuleLoaded(DWORD processId, const wchar_t* path) {
    const wchar_t* name = wcsrchr(path, L'\\');
    name = name != nullptr ? name + 1 : path;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool found = false;
    for (BOOL more = Module32FirstW(snapshot, &entry); more && !found; more = Module32NextW(snapshot, &entry)) {
        found = _wcsicmp(entry.szModule, name) == 0;
    }
    CloseHandle(snapshot);
    return found;
}

// Loads the DLL into a running process of the same bitness with a remote LoadLibraryW thread. The payload is
// copied first, so DllMain finds it.
DWORD AttachToProcess(HANDLE process, DWORD processId, const HookPayload& payload) {
    if (Is64BitProcess(process) != kSelf64) {
        return ERROR_BAD_EXE_FORMAT;
    }
    wchar_t dll[MAX_PATH * 2];
    if (!HookDllPathW(kSelf64, dll, MAX_PATH * 2)) {
        return ERROR_PATH_NOT_FOUND;
    }
    if (!DetourCopyPayloadToProcess(process, kPayloadGuid, &payload, sizeof(payload))) {
        return ErrorOr(ERROR_GEN_FAILURE);
    }

    SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == nullptr) {
        return ErrorOr(ERROR_NOT_ENOUGH_MEMORY);
    }
    if (!WriteProcessMemory(process, remote, dll, bytes, nullptr)) {
        DWORD error = ErrorOr(ERROR_GEN_FAILURE);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return error;
    }

    // kernel32 is mapped at the same address in every process of the same bitness.
    auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remote, 0, nullptr);
    if (thread == nullptr) {
        DWORD error = ErrorOr(ERROR_GEN_FAILURE);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return error;
    }
    DWORD wait = WaitForSingleObject(thread, kAttachTimeoutMs);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);
    if (wait != WAIT_OBJECT_0) {
        return WAIT_TIMEOUT;  // the string stays allocated: the thread may still read it
    }
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);

    // The exit code is the low 32 bits of the module handle, which can be 0 for a loaded 64-bit module.
    return exitCode != 0 || IsModuleLoaded(processId, dll) ? ERROR_SUCCESS : ERROR_DLL_INIT_FAILED;
}

}  // namespace

DWORD InjectIntoSuspendedProcess(HANDLE process, DWORD processId, const HookPayload& payload) {
    bool target64 = Is64BitProcess(process);
    char dll[MAX_PATH * 2];
    if (!HookDllPathA(target64, dll, sizeof(dll))) {
        return ERROR_PATH_NOT_FOUND;
    }
    if (GetFileAttributesA(dll) == INVALID_FILE_ATTRIBUTES) {
        return ERROR_MOD_NOT_FOUND;
    }

    LPCSTR dlls[] = {dll};
    // Same bitness: add the DLL to the process's import table directly. Otherwise Detours runs a rundll32 of the
    // target's bitness with that DLL (ordinal 1) to do it.
    BOOL updated = target64 == kSelf64 ? DetourUpdateProcessWithDll(process, dlls, 1)
                                       : DetourProcessViaHelperDllsW(processId, 1, dlls, CreateProcessW);
    if (!updated) {
        return ErrorOr(ERROR_GEN_FAILURE);
    }
    if (!DetourCopyPayloadToProcess(process, kPayloadGuid, &payload, sizeof(payload))) {
        return ErrorOr(ERROR_GEN_FAILURE);
    }
    return ERROR_SUCCESS;
}

}  // namespace proxynator

using namespace proxynator;

// Starts a process suspended with the hook DLL, then resumes it. The child inherits this process's console and
// standard handles. Returns ERROR_SUCCESS or a Win32 error; the caller closes the handles in processInformation.
extern "C" DWORD WINAPI ProxynatorCreateProcess(LPCWSTR applicationName, LPWSTR commandLine, LPCWSTR currentDirectory, LPCWSTR hookPipe,
                                               LPPROCESS_INFORMATION processInformation) {
    HookPayload payload;
    if (processInformation == nullptr || !MakePayload(hookPipe, &payload)) {
        return ERROR_INVALID_PARAMETER;
    }
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreateProcessW(applicationName, commandLine, nullptr, nullptr, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr,
                        currentDirectory, &startup, processInformation)) {
        return ErrorOr(ERROR_GEN_FAILURE);
    }
    DWORD error = InjectIntoSuspendedProcess(processInformation->hProcess, processInformation->dwProcessId, payload);
    if (error != ERROR_SUCCESS) {
        TerminateProcess(processInformation->hProcess, error);
        CloseHandle(processInformation->hThread);
        CloseHandle(processInformation->hProcess);
        ZeroMemory(processInformation, sizeof(*processInformation));
        return error;
    }
    ResumeThread(processInformation->hThread);
    return ERROR_SUCCESS;
}

// Loads the hook DLL into a running process of this DLL's bitness. Returns ERROR_SUCCESS, ERROR_BAD_EXE_FORMAT
// when the process has the other bitness (use the other DLL through ProxynatorAttachRundll), or a Win32 error.
extern "C" DWORD WINAPI ProxynatorAttach(DWORD processId, LPCWSTR hookPipe) {
    HookPayload payload;
    if (!MakePayload(hookPipe, &payload)) {
        return ERROR_INVALID_PARAMETER;
    }
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, processId);
    if (process == nullptr) {
        return ErrorOr(ERROR_ACCESS_DENIED);
    }
    DWORD result = AttachToProcess(process, processId, payload);
    CloseHandle(process);
    return result;
}

// rundll32 entry point: rundll32 "<dll>",ProxynatorAttachRundll <pid> <pipe path>. The exit code is the result.
extern "C" void CALLBACK ProxynatorAttachRundllW(HWND, HINSTANCE, LPWSTR commandLine, int) {
    wchar_t* rest = nullptr;
    unsigned long processId = commandLine != nullptr ? wcstoul(commandLine, &rest, 10) : 0;
    while (rest != nullptr && *rest == L' ') {
        ++rest;
    }
    DWORD result = processId == 0 || rest == nullptr || *rest == L'\0' ? ERROR_INVALID_PARAMETER : ProxynatorAttach(processId, rest);
    ExitProcess(result);
}
