# OS-Level Auto-Instrumentation (v0.7.0 target — highest novelty)

eBPF (Linux) / Endpoint Security Framework (macOS) / ETW (Windows)
programs that observe agent processes at the syscall layer and emit
Veritas Acta receipts for interesting events (tool invocations,
network calls, file mutations). Zero code changes in the observed
agent.

## Goal

The ultimate frictionless integration: install the observer, point it
at a process, and every significant action that process takes gets a
cryptographic receipt. No SDK, no framework adapter, no code change
required.

## Design

### Linux (eBPF)

- eBPF program attached to syscalls:
  - `openat()`, `unlink()` — file mutations
  - `connect()`, `sendto()` — network activity
  - `execve()` — subprocess spawning
- User-space daemon consumes kernel ring buffer events
- Daemon maintains a per-pid receipt chain
- Daemon signs receipts using a project attester key

### macOS (Endpoint Security Framework)

- ESF client subscribes to:
  - `ES_EVENT_TYPE_AUTH_EXEC` — process execution
  - `ES_EVENT_TYPE_NOTIFY_OPEN` / `NOTIFY_WRITE` — file access
  - `ES_EVENT_TYPE_NOTIFY_CREATE` — new files
- ES client requires Team ID + System Extension entitlements
- Runs as a privileged daemon

### Windows (ETW)

- ETW provider subscription to:
  - Microsoft-Windows-Kernel-File
  - Microsoft-Windows-Kernel-Process
  - Microsoft-Windows-Kernel-Network
- Agent process pattern matching via image load events

### Composition with sb-runtime

sb-runtime = kernel-level enforcement (deny)
eBPF observer = kernel-level observation (report)

Together: agents can't do forbidden things (sb-runtime), and everything
they DO do is receipted (observer).

## Receipt format

```json
{
  "payload": {
    "type": "veritasacta:os-observer:event",
    "event_kind": "file_write" | "network_connect" | "exec",
    "pid": 12345,
    "process_name": "python",
    "cmdline_hash": "sha256:...",
    "target": {
      "kind": "file",
      "path_hash": "sha256:...",
      "size_bytes": 1024
    },
    "timestamp_nanos": ...
  },
  "signature": { ... }
}
```

Sensitive fields (full paths, cmdlines) are hashed, not stored raw.
Reveals happen via selective disclosure (AIP-0002) when needed.

## Privacy implications

- Observes at the syscall layer: can see EVERYTHING
- Must be deployed with informed user consent
- Private / sensitive paths configurable via allow / deny filters
- No phone-home: receipts stay local unless explicitly exported

## Performance

- eBPF adds ~1-5µs per observed syscall (acceptable for moderate
  volumes)
- ESF has ~10-50µs overhead
- High-volume scenarios (>10K syscalls/sec) require event filtering
  upstream of receipt generation

## Deployment tiers

- **Developer mode**: observer runs as the user, observes only the
  user's processes, no special privileges (Linux only with ebpf
  unprivileged mode)
- **Production mode**: observer runs as root / admin, can observe any
  process, requires explicit install + trust

## License

Apache-2.0 once shipped. eBPF programs will likely need dual-license
(GPL kernel compatibility).
