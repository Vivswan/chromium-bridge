# Operations: running and operating browser-bridge

> This doc covers how to operate browser-bridge at runtime: the two binary
> modes, read-only diagnostics, logging/audit, the lock file, and native host
> reconnect. Full subcommand usage and "server not reachable" troubleshooting
> are in [cli.md](./cli.md) (not repeated here); component boundaries are in
> [architecture.md](./architecture.md).

## The two binary modes

`browser-bridge` is a single binary with subcommand dispatch (see [ADR-0001](./adr/0001-use-rust-single-binary.md)):

- **MCP server** (no arguments): the default mode, spawned by the MCP client. Listens on
  localhost TCP, holds session state, dispatches tools. stdout carries MCP JSON-RPC.
- **native host** (`--native-host`): a thin bridge, spawned by Chrome via the wrapper.
  Forwards between Native Messaging frames on stdin/stdout and TCP NDJSON. stdout carries
  NM frames.

In both modes, **stdout carries only protocol bytes**; every diagnostic goes to stderr. A
single stray write would corrupt the frame stream
(see [trust-boundaries.md](./security/trust-boundaries.md)).

## Read-only diagnostics: doctor / status

`browser-bridge doctor` (alias `status`) is a **read-only** self-check: it does not listen
on a port, does not write the lock file, and does not spawn child processes. It only probes
and prints the environment and connectivity conclusions (version/platform, lock file
port/pid, MCP server reachability, whether the native host manifest is in place). It does
**no repairs**: it does not kill processes, delete the lock file, or restart the server.
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
[`errors.json`](../contracts/errors.json)), and `dur_ms`. With `BB_LOG_FORMAT=json` each
line is one JSON object, convenient for machine collection. The leveled logging design is
in [ADR-0014](./adr/0014-leveled-logging.md).

Audit lines record **no sensitive content** (full page text, cookie/storage values,
complete eval return values, form fill values); masking happens on the extension side
(see [threat-model.md](./security/threat-model.md)).

> Audit lines carry both a **per-call request id** and a cross-connection
> **connection id** (the `conn` field, provided by `Session::current_generation()`), so
> events can be correlated to a specific connection across reconnects.

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
