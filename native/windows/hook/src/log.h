// Diagnostics of the hook: OutputDebugString always (visible in DebugView / a debugger), and a file when the
// PROXYNATOR_HOOK_LOG environment variable names one (inherited by child processes).
#pragma once

namespace proxynator {

void InitializeLog();
void Log(const wchar_t* format, ...);

}  // namespace proxynator
