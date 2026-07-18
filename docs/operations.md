# Operations: running and operating chromium-bridge

> This doc covers how to operate chromium-bridge at runtime: the binary
> modes, read-only diagnostics, logging/audit, the runtime directory, and
> native host reconnect. Full subcommand usage and "server not reachable"
> troubleshooting are in [cli.md](./cli.md) (not repeated here); component
> boundaries are in [architecture.md](./architecture.md).

## The two wire modes

`chromium-bridge` is a single binary with subcommand dispatch (see
[ADR-0001](./adr/0001-use-rust-single-binary.md)). Two modes carry protocol
on stdout:

- **MCP server** (no arguments): the default mode, spawned by the MCP
  client. The first instance binds the bridge socket, becomes the broker,
  and holds session state; later instances attach to it as relays, so
  several MCP clients share the browsers concurrently
  ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)).
  stdout carries MCP JSON-RPC.
- **native host** (`--native-host --label <browser>`): a thin bridge,
  spawned by each browser via the wrapper. Forwards between Native Messaging
  frames on stdin/stdout and NDJSON on the bridge socket, and terminates the
  control-plane frames (enrollment, kill, client admin) itself. stdout
  carries NM frames.

In both modes, **stdout carries only protocol bytes**; every diagnostic goes
to stderr. A single stray write would corrupt the frame stream (see
[trust-boundaries.md](./security/trust-boundaries.md)).

The management subcommands (`doctor`, `--fix`, `uninstall`, `pair`,
`pair-client`, `kill`, `audit`, ...) are documented in [cli.md](./cli.md);
the desktop app drives the same engines
([desktop-app.md](./desktop-app.md)).

## Read-only diagnostics: doctor / status

`chromium-bridge doctor` (alias `status`) is a read-only self-check: it does
not bind the socket, does not write the lock file, and does not spawn child
processes. It reports the version/platform, the lock file's endpoint and
pid, a passive reachability probe of the bridge socket, the kill-switch
state, and each known browser's registration state. Plain doctor does no
repairs; repairing a registration is the explicit, opt-in
`chromium-bridge doctor --fix` (with `uninstall` as its reverse), and the
report and the repair share one browser-path resolver, so they always agree
on where a manifest belongs (see
[cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration)).

## Logging and audit: BB_LOG / BB_LOG_FORMAT

Diagnostics all go to **stderr**; two environment variables control the
output (full table in
[cli.md](./cli.md#logging-and-audit-bb_log--bb_log_format)):

- `BB_LOG`: `error` / `warn` / `info` (default) / `debug`, the log threshold.
- `BB_LOG_FORMAT`: `text` (default) / `json`, the audit line format.

**Structured audit events**: every security decision emits one audit line;
tool calls carry per-call fields (`req`, `tool`, `outcome`, the stable
`code` from [`ERROR_SPECS`](../src/packages/core/src/error.rs) on error, and
`dur_ms`). Audit lines carry both a per-call request id and a
cross-connection connection id (the `conn` field), so events can be
correlated to a specific connection across reconnects.

Audit lines record no sensitive content (full page text, cookie/storage
values, complete eval return values, form fill values); masking happens on
the extension side (see [threat-model.md](./security/threat-model.md)).

Since [ADR-0030](./adr/0030-global-kill-switch-and-audit.md) the same events
are also appended to a durable, size-capped `audit.log` (0600, in the
runtime directory next to the lock file) and read back with
`chromium-bridge audit`; see
[cli.md](./cli.md#logging-and-audit-bb_log--bb_log_format).

## Kill switch: state, and recovering an unreadable record

`chromium-bridge kill` halts all bridge activity until an explicit,
user-present release; the behavior and the release paths are documented in
[cli.md](./cli.md#kill-switch-kill--unkill) and
[ADR-0030](./adr/0030-global-kill-switch-and-audit.md). The latch lives in
`revocation.json` in the runtime directory, the same record that carries the
revocation epoch (ADR-0025).

Every enforcement point reads that record fail-closed, so if it becomes
unreadable (corrupt JSON, unknown fields, bad permissions), the bridge stops
serving everything: tool calls are refused with `BRIDGE_KILLED`, browser
connections are severed, fresh instances refuse to start, and both `kill`
and `unkill` refuse to write (releasing from a state you cannot read would
fail open, and rebuilding the file silently would mask tampering). `doctor`
reports the unreadable state and exits non-zero.

Recovery is deliberately manual:

1. Run `chromium-bridge doctor` to confirm the state and find the runtime
   directory.
2. Look at `revocation.json` before touching it. If you cannot explain the
   corruption (a crash mid-write, a disk incident), treat it as a possible
   tampering indicator and see
   [incident-response.md](./security/incident-response.md) before proceeding.
3. Delete `revocation.json` **and** `clients.json` from the runtime
   directory. Deleting only one is itself detected as tampering (ADR-0025);
   dropping both is a factory reset of harness trust, back to the
   loudly-logged unenrolled bootstrap.
4. Re-pair each trusted client (`chromium-bridge pair-client`), and
   re-engage the kill switch if you had it on. The extension's enrollment
   pin is not affected (the host key never lived in these files).

## The runtime directory and the lock file

The bridge rendezvous lives in a 0700 per-user runtime directory (macOS:
`$XDG_RUNTIME_DIR/chromium-bridge`, else
`~/Library/Application Support/chromium-bridge`; Linux:
`$XDG_RUNTIME_DIR/chromium-bridge`, with XDG-cache fallback; Windows:
`%LOCALAPPDATA%\chromium-bridge`). It holds the lock file (`run.lock`, 0600:
the broker's pid, endpoint, and per-run secret), the bridge socket itself on
Unix, the trusted-client allowlist (`clients.json`), the revocation/kill
record (`revocation.json`), and the audit trail (`audit.log`).

Peers read the lock file, connect to the endpoint, and must pass the kernel
checks and the HMAC challenge-response before the mandatory attach frame
(see [architecture.md section 3.3](./architecture.md#33-internal-bridge-protocol-broker---native-hosts-and-relays)
and [trust-boundaries.md](./security/trust-boundaries.md)).

**Stale lock file**: a broker that exited abnormally may leave the lock file
behind. The next server instance probes it; a dead endpoint is detected and
the lock replaced at startup. There is no forced takeover of a live owner:
a second instance that finds a live broker attaches to it instead
([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)).
`doctor` only reads the lock file; it never cleans it up.

## native host reconnect

The MV3 Service Worker is force-restarted every 5 minutes (Chromium
#40733525), which closes the Port; the native host then gets EOF on stdin
and exits. Reconnection is driven by the extension (see
[architecture.md section 5.2](./architecture.md#52-native-host-reconnect)):

```
Browser closes the extension Port -> native host stdin EOF -> host exits
extension onDisconnect -> scheduleReconnect(2s)
after 2s connectNative() -> browser respawns the host -> reads lock file
  -> connects to the socket -> kernel checks + HMAC + attach(label)
broker re-attaches that label's connection
```

Request/response state (pending calls, their pairing ids, the connection
generation) lives in the MCP server process, not the SW, so an SW restart
does not lose in-flight session bookkeeping; the extension's ref markers are
stamped onto DOM attributes, so the content script rebuilds its refMap after
a restart, and the active tab is re-resolved per call. Pending requests are
bound to a **connection generation**, and generation-guarded reconnect
guarantees an old connection cannot affect a new one (see
[compatibility.md](./compatibility.md)).

## Related

- Subcommand usage and troubleshooting: [cli.md](./cli.md).
- Versions and the handshake: [compatibility.md](./compatibility.md).
- Handling security incidents: [security/incident-response.md](./security/incident-response.md).
