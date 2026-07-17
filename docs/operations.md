# Operations: running and operating chromium-bridge

> This doc covers how to operate chromium-bridge at runtime: the two binary
> modes, read-only diagnostics, logging/audit, the lock file, and native host
> reconnect. Full subcommand usage and "server not reachable" troubleshooting
> are in [cli.md](./cli.md) (not repeated here); component boundaries are in
> [architecture.md](./architecture.md).

## The two binary modes

`chromium-bridge` is a single binary with subcommand dispatch (see [ADR-0001](./adr/0001-use-rust-single-binary.md)):

- **MCP server** (no arguments): the default mode, spawned by the MCP client. Listens on
  localhost TCP, holds session state, dispatches tools. stdout carries MCP JSON-RPC.
- **native host** (`--native-host`): a thin bridge, spawned by Chrome via the wrapper.
  Forwards between Native Messaging frames on stdin/stdout and TCP NDJSON. stdout carries
  NM frames.

In both modes, **stdout carries only protocol bytes**; every diagnostic goes to stderr. A
single stray write would corrupt the frame stream
(see [trust-boundaries.md](./security/trust-boundaries.md)).

## Read-only diagnostics: doctor / status

`chromium-bridge doctor` (alias `status`) is a **read-only** self-check: it does not listen
on a port, does not write the lock file, and does not spawn child processes. It only probes
and prints the environment and connectivity conclusions (version/platform, lock file
port/pid, MCP server reachability, and per browser the state of the native-messaging
registration). Plain doctor does **no repairs**: it does not kill processes, delete the
lock file, or restart the server. Repairing a registration is the explicit, opt-in
`chromium-bridge doctor --fix` (with `uninstall` as its reverse); the report and the
repair share one browser-path resolver, so they always agree on where a manifest belongs
(see [cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration)).
The meaning of each item and how to interpret "server not reachable" are in
[cli.md](./cli.md#doctor--status-read-only-self-check).

## Logging and audit: BB_LOG / BB_LOG_FORMAT

Diagnostics all go to **stderr**; two environment variables control the output (full table
in [cli.md](./cli.md#logging-and-audit-bb_log--bb_log_format)):

- `BB_LOG`: `error` / `warn` / `info` (default) / `debug`, the log threshold.
- `BB_LOG_FORMAT`: `text` (default) / `json`, the audit line format.

**Structured audit events**: the MCP server emits one audit line for every `tools/call`
it processes, with per-call fields: `req` (monotonic request id), `tool`, `outcome`
(`ok`/`error`), `code` (on error, the stable code from
[`ERROR_SPECS`](../src/packages/core/src/error.rs)), and `dur_ms`. With `BB_LOG_FORMAT=json` each
line is one JSON object, convenient for machine collection. The leveled logging design is
in [ADR-0014](./adr/0014-leveled-logging.md).

Audit lines record **no sensitive content** (full page text, cookie/storage values,
complete eval return values, form fill values); masking happens on the extension side
(see [threat-model.md](./security/threat-model.md)).

> Audit lines carry both a **per-call request id** and a cross-connection
> **connection id** (the `conn` field, provided by `Session::current_generation()`), so
> events can be correlated to a specific connection across reconnects.

Since ADR-0030 the same events are also appended to a durable, size-capped
`audit.log` (0600, in the runtime directory next to the lock file) and read back with
`chromium-bridge audit`; see [cli.md](./cli.md#logging-and-audit-bb_log--bb_log_format).

## Kill switch: state, and recovering an unreadable record

`chromium-bridge kill` halts all bridge activity until an explicit, user-present
release; the behavior and the release paths are documented in
[cli.md](./cli.md#kill-switch-kill--unkill) and
[ADR-0030](./adr/0030-global-kill-switch-and-audit.md). The latch lives in
`revocation.json` in the runtime directory, the same record that carries the
revocation epoch (ADR-0025).

Every enforcement point reads that record fail-closed, so if it becomes
unreadable (corrupt JSON, unknown fields, bad permissions), the bridge stops
serving everything: tool calls are refused with `BRIDGE_KILLED`, browser
connections are severed, fresh instances refuse to start, and both `kill` and
`unkill` refuse to write (releasing from a state you cannot read would fail
open, and rebuilding the file silently would mask tampering). `doctor` reports
the unreadable state and exits non-zero.

Recovery is deliberately manual:

1. Run `chromium-bridge doctor` to confirm the state and find the runtime
   directory.
2. Look at `revocation.json` before touching it. If you cannot explain the
   corruption (a crash mid-write, a disk incident), treat it as a possible
   tampering indicator and see
   [incident-response.md](./security/incident-response.md) before proceeding.
3. Delete `revocation.json` **and** `clients.json` from the runtime directory.
   Deleting only one is itself detected as tampering (ADR-0025); dropping both
   is a factory reset of harness trust, back to the loudly-logged unenrolled
   bootstrap.
4. Re-pair each trusted client (`chromium-bridge pair-client`), and re-engage
   the kill switch if you had it on. The extension's enrollment pin is not
   affected (the host key never lived in these files).

## Lock file

The bridge socket publishes its port and authenticates peers through a **lock file in the
user directory**: the MCP server writes `{ port, pid, per-run secret }` at startup, with
file permissions `0600` on Unix; the native host reads the lock file when connecting,
connects over TCP, and sends `hello` with the secret. The design is in
[ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md) and
[trust-boundaries.md](./security/trust-boundaries.md).

**Stale lock file**: a previous server that exited abnormally may leave the lock file
behind (its port/pid no longer valid); a new server detects and replaces it at startup
(on Windows it takes over the old server with `TerminateProcess`, see
[architecture.md section 9](./architecture.md#9-known-limitations)). `doctor` only reads the lock
file; it never cleans it up.

## native host reconnect

The MV3 Service Worker is force-restarted every 5 minutes (Chromium #40733525), which
closes the Port; the native host then gets EOF on stdin and exits. Reconnection is driven
by the extension (see
[architecture.md section 5.2](./architecture.md#52-native-host-reconnect-flow)):

```
Chrome closes the extension Port -> native host stdin EOF -> host exits
extension onDisconnect -> scheduleReconnect(2s)
after 2s connectNative() -> Chrome respawns the host -> reads lock file -> connects TCP -> sends hello
MCP server validate_hello -> session.attach_connection (replaces the old connection)
```

Session state (current tab, ref map) lives in the MCP server process, not the SW, so an SW
restart does not lose the session; ref markers are stamped onto DOM attributes, so the
content script can rebuild the refMap after a restart. Pending requests are bound to a
**connection generation**, and generation-guarded reconnect guarantees an old connection
cannot affect a new one (see [compatibility.md](./compatibility.md)).

## Related

- Subcommand usage and troubleshooting: [cli.md](./cli.md).
- Versions and the handshake: [compatibility.md](./compatibility.md).
- Handling security incidents: [security/incident-response.md](./security/incident-response.md).
