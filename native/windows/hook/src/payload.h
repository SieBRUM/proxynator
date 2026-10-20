// The Detours payload that marks a process as hooked and tells the hook where the service listens. It is copied into
// every target process (proxynator run / attach, and every child a hooked process creates) before the DLL runs.
#pragma once

#include <windows.h>

namespace proxynator {

// {6E1C9B3A-5D2F-4C8E-9A71-3B0D4F6A8C21}
inline constexpr GUID kPayloadGuid = {0x6e1c9b3a, 0x5d2f, 0x4c8e, {0x9a, 0x71, 0x3b, 0x0d, 0x4f, 0x6a, 0x8c, 0x21}};
inline constexpr DWORD kPayloadVersion = 1;
inline constexpr size_t kMaxPipePath = 256;

struct HookPayload {
    DWORD version;
    WCHAR pipePath[kMaxPipePath];  // e.g. \\.\pipe\proxynator.v1.hook, null-terminated
};

}  // namespace proxynator
