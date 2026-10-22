# CLI

`proxynator` talks to the running service, like the GUI; it doesn't need elevation (see
[Installation](installation.md) for who may use it).

```
proxynator status                       # service, capture mode and state, relay, DNS, active rules
proxynator doctor                       # privileges, driver/eBPF/native parts, capture, relay, DNS, proxy reachability
proxynator config validate <file>       # check a file without applying it (works without the service)
proxynator config load <file>           # validate and apply atomically, and save it; --no-save to not save it
proxynator config show                  # print the active configuration
proxynator rules list                   # rules in evaluation order with their resolved routes
proxynator connections [--follow]       # relayed connections: process, destination, rule, route, bytes
proxynator run [--detach] -- <program> [args...]   # hooking modes: start a program with the hook
proxynator attach <pid>                 # injection mode (Windows): hook a running program
```

- `--endpoint <pipe name | socket path>` (or `PROXYNATOR_ENDPOINT`) talks to a service on a non-default endpoint.
- Exit codes: `0` success, `1` failure (invalid configuration, failed checks), `2` service not reachable.
  `proxynator run` returns the program's own exit code.

## `proxynatord`

```
proxynatord [--config <file>] [--endpoint <pipe | socket>] [--verbose] [--no-capture]
```

| Option | |
|---|---|
| `--config`, `-c` | Configuration file (default: `%ProgramData%\Proxynator\config.json` / `/etc/proxynator/config.json`). A missing file means no rules; an invalid one stops the service with exit code 3. |
| `--endpoint` | Control endpoint (default `proxynator.v1` / `/run/proxynator/proxynator.sock`). |
| `--verbose`, `-v` | Debug logging: every redirected connection and its decision. |
| `--no-capture` | Run the control API and relay without capturing anything (and without privileges): for trying out configurations and development. |

It runs in the foreground in a terminal, as a Windows service or as a systemd unit. Exit codes: `1` error, `2` not
elevated / not root, `3` invalid configuration.

## `proxynator-gui`

```
proxynator-gui [--endpoint <pipe | socket>]
```
