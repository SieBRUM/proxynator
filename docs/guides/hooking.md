# Hooking single programs

Sometimes you don't want to capture the whole machine, just the tools you start. In the `injection` (Windows) and
`preload` (Linux) modes nothing is captured machine-wide. The programs you start through Proxynator load a small hook
that asks the service before every outbound connection, and goes to the relay when the rules say so. Everything those
programs start is hooked too (on Windows also 32-bit programs started by 64-bit ones and vice versa). Think
proxychains, but it also works on Windows programs that ignore proxy settings.

## Setup

1. **Settings** → **Capture mode** `injection` (Windows) or `preload` (Linux), **Apply and save**, then restart the
   service (**Diagnostics** shows the mode it runs in). JSON: `"settings": { "capture": { "mode": "injection" } }`.
2. Add a proxy and rules as usual. A rule with no criteria at all means "everything I start through Proxynator",
   because nothing else is captured. See [`samples/injection-run.json`](../../samples/injection-run.json).

## Starting programs

**In the GUI** (**Launch** page):

- **Launch** a program: **Program** (a path, or a command on the `PATH` such as `nxc` or `curl`), **Arguments**
  (quote arguments with spaces), **Working directory**.
- **Open hooked terminal** opens PowerShell (Windows) or your shell in the desktop's terminal (Linux). Every program
  you start from it is hooked, the easiest way to work with many tools.
- **Attach** (Windows only) loads the hook into a running process: pick it from the list. Its new connections, and
  those of programs it starts, follow the rules; open connections are not affected.

**In a terminal:**

```
proxynator run -- nxc smb dc01.corp.local -u alice -p 'Passw0rd!'
proxynator run --detach -- "C:\Program Files\App\app.exe"
proxynator attach 4321
```

The `--` keeps the program's options from being read as Proxynator's. `run` waits for the program and returns its exit
code; neither `run` nor `attach` needs elevation.

## Differences from the machine-wide modes

- **Fails closed when the service is gone:** hooked programs get "connection refused" instead of going direct; a
  child process the hook can't load into isn't started.
- **Remote DNS is per program:** only hooked programs get placeholder addresses; the rest of the machine resolves
  normally.
- **Names come from the program's own lookups,** so the proxy gets them even for protocols that can't be sniffed (SMB,
  LDAP, Kerberos). A name read from TLS or HTTP still wins.
- **UDP is not relayed:** each rule blocks it (default) or sends it direct. QUIC is blocked.

## What escapes a hook

Programs that bypass the system's socket library: raw system calls, their own network stack, Go and statically linked
binaries on Linux, setuid programs and `sudo` (they drop `LD_PRELOAD`), and Windows processes that only load
Microsoft-signed DLLs (some browser sandboxes). Use the kernel modes (`windivert`, `ebpf`) for those. `attach` doesn't
exist on Linux: a library can't be preloaded into a running process.

Set `PROXYNATOR_HOOK_LOG` to a file path before starting a program to get a log from every hooked process; on Windows
the hook also writes to the debugger output (Sysinternals DebugView).
