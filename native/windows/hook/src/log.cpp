#include "log.h"

#include <windows.h>

#include <cstdarg>
#include <cstdio>

namespace proxynator {

namespace {

HANDLE g_logFile = INVALID_HANDLE_VALUE;

}  // namespace

void InitializeLog() {
    wchar_t path[MAX_PATH];
    DWORD length = GetEnvironmentVariableW(L"PROXYNATOR_HOOK_LOG", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return;
    }
    g_logFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

void Log(const wchar_t* format, ...) {
    DWORD error = GetLastError();
    wchar_t message[1024];
    int prefix = swprintf_s(message, L"[proxynator-hook %lu] ", GetCurrentProcessId());
    if (prefix < 0) {
        prefix = 0;
    }
    va_list args;
    va_start(args, format);
    int length = _vsnwprintf_s(message + prefix, sizeof(message) / sizeof(message[0]) - prefix - 2, _TRUNCATE, format, args);
    va_end(args);
    size_t end = prefix + (length < 0 ? wcslen(message + prefix) : static_cast<size_t>(length));
    message[end++] = L'\n';
    message[end] = L'\0';
    OutputDebugStringW(message);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        char utf8[3 * 1024];
        int bytes = WideCharToMultiByte(CP_UTF8, 0, message, static_cast<int>(end), utf8, sizeof(utf8), nullptr, nullptr);
        if (bytes > 0) {
            DWORD written = 0;
            WriteFile(g_logFile, utf8, static_cast<DWORD>(bytes), &written, nullptr);
        }
    }
    SetLastError(error);
}

}  // namespace proxynator
