# ADR 0006: Desktop GUI with Avalonia

- Status: accepted
- Date: 2026-10-21

## Context

Phase 6 adds a GUI for Windows and Linux (Ubuntu, Kali). It must not weaken the security model: anyone who can talk
to the service can redirect traffic, so the GUI must not need, or ask for, more rights than the CLI. It has to cover
what users do all day: watch connections, change rules and proxies, start programs in the user-mode capture modes,
and find out why something does not work. The CLI's `run`/`attach` logic lived in the CLI project.

## Decision

- **Avalonia 12 + Fluent theme, MVVM with the CommunityToolkit**, one codebase for Windows and Linux (X11). Compiled
  bindings only and a reflection-free view locator, so it stays trim-friendly. Light and dark follow the system.
- **A thin, unprivileged client** (`proxynator-gui`) on the existing `proxynator.v1` gRPC API: no new RPCs were needed.
  The manifest requests `asInvoker`. Access is decided by the pipe ACL / socket group, exactly as for the CLI.
- **`Proxynator.Client`** (new library) holds what the CLI and the GUI share: `ProgramLauncher` (start with the hook,
  open a hooked terminal, attach), terminal discovery on Linux, argument splitting, display formatting and the
  "service unreachable" hints. The CLI commands became thin wrappers around it.
- **Configuration editing works on a working copy** (`ConfigWorkspace`) shared by the Rules, Proxies, Settings and
  JSON pages. It is validated on every change with Core's `ConfigValidator` (problems shown in words, mapped from
  JSON paths), and only sent with `ApplyConfig`, so the service validates again and swaps atomically (golden rule:
  invalid config is never half applied). The editors build the configuration with `with` on the loaded one, so
  settings without a form survive. While nothing is edited, outside changes (CLI, another GUI) are picked up on the
  2-second refresh; while something is edited they are not, and Apply wins.
- **Live connections** use `WatchConnections` (subscribe first, then list, tolerating duplicates) and refresh byte
  counters with `ListConnections` on every tick; the watch reconnects when the service restarts. Closed connections
  stay in the list (up to 1000).
- **Hooked terminal**: Windows starts PowerShell (pwsh if installed) with the hook in a new console; children inherit
  the hook. Linux starts the desktop's terminal emulator (`x-terminal-emulator` first, then common ones) *without*
  the library and runs `env LD_PRELOAD=… PROXYNATOR_HOOK_ENDPOINT=… $SHELL` in it, because some terminals hand the
  command to a server process that would not inherit the environment.
- **Tests**: view models against the in-process service of the service tests; the real window on Avalonia's headless
  platform with Skia rendering, which also writes a screenshot of every page (uploaded by CI); integration tests for
  `ProgramLauncher` in preload (incl. the terminal, with a stand-in terminal emulator) and injection modes.
- **Packaging**: the GUI is published next to the service and CLI (Windows zip, `.deb`), with a `.desktop` entry and
  icon on Linux. X11 libraries are `Recommends`, not `Depends`, so servers can skip them.
- Avalonia's build telemetry is opted out in CI (`AVALONIA_TELEMETRY_OPTOUT=1`).

## Consequences

- Everything the GUI can do, the CLI can do too, and the service needs no GUI-specific code.
- The GUI depends on a native renderer (SkiaSharp, HarfBuzzSharp): larger downloads, and an X server (or XWayland)
  on Linux.
- A config edited in the GUI and applied replaces the service's configuration wholesale, like `config load`; edits
  made elsewhere in the meantime are overwritten. Acceptable for a single-operator tool; a versioned compare-and-swap
  `ApplyConfig` can be added to v1 later if needed.
