# CLI and troubleshooting: chromium-bridge

> This doc covers the subcommands of the `chromium-bridge` binary and the common
> troubleshooting paths. Components and process boundaries are in
> [architecture.md](./architecture.md); install artifact paths are in
> [architecture.md section 4.3](./architecture.md#43-install-artifacts).

## Subcommand overview

`chromium-bridge` is a single binary with subcommand dispatch (see [ADR-0001](./adr/0001-use-rust-single-binary.md)):

| Invocation | Mode | Description |
|------|------|------|
| `chromium-bridge` (no arguments) | MCP server | Default mode: listens on TCP, holds session state, dispatches tools. Spawned by the MCP client. |
| `chromium-bridge --native-host` | native host | Thin bridge: stdin/stdout NM frames <-> TCP NDJSON. Spawned by Chrome (via the wrapper). |
| `chromium-bridge doctor` (alias `status`) | read-only diagnostics | Prints an environment and connectivity self-check; does not start a server and does not change any state. |
| `chromium-bridge --help` | help | Usage information. |

## doctor / status (read-only self-check)

`doctor` (with `status` as an equivalent alias) is a **read-only** subcommand:
it does not listen on a port, does not write the lock file, and does not spawn
any child process. It only probes the current environment and prints its
conclusions, to answer the question "why can't I connect".

It reports:

- **Version / platform**: the binary version (Cargo is the source, see [ADR-0013](./adr/0013-ci-and-toolchain.md)) and the running platform (macOS/Windows).
- **Lock file**: whether the bridge lock file exists in the user directory, and the **port / pid**
  recorded in it (for the lock file mechanism see [ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md)).
- **MCP server reachability**: a single localhost probe against the `127.0.0.1:<port>` from the
  lock file, reporting whether the server is listening (`reachable` / `not reachable`).
- **native host manifest**: whether Chrome's native messaging host manifest
  (`com.vivswan.chromium_bridge.host.json`) is in place (paths in [architecture.md section 4.3](./architecture.md#43-install-artifacts)).

### How to interpret "server not reachable"

"server not reachable" means `doctor` read the port from the lock file, but the localhost
probe against that port failed. Common causes and what to do:

1. **The MCP server is not running**: the MCP server is spawned by the MCP client (such as
   Claude Code) inside its session. If the client is not running, or that server is not
   configured or not started, nothing is listening on the port. -> Confirm the client has
   loaded the chromium-bridge MCP server configuration and is in a running session.
2. **Stale lock file**: the previous server exited abnormally and left the lock file behind
   (its port/pid are no longer valid). A new server detects and replaces a stale lock file at
   startup (see [architecture.md section 9](./architecture.md#9-known-limitations)); if no live server
   exists right now, `doctor` reporting not reachable is expected. -> Restart the client
   session.
3. **Port taken or blocked by a firewall**: localhost loopback usually does not involve a
   firewall, but local security software may intercept it. -> Check whether another process
   is occupying the port.

> `doctor` only probes; it does not repair. It will **not** kill processes, delete the lock
> file, or restart the server. When you see not reachable, the correct action is to go back
> to the MCP client side and re-establish the session, not to intervene in processes by hand.

If the **manifest is missing**, the extension-side native host cannot be spawned by Chrome
(Chrome cannot find the host declaration).
-> Re-run the install script (`install.sh` / `install.ps1`) to write the manifest.

## Logging and audit (BB_LOG / BB_LOG_FORMAT)

Diagnostics in both modes go to **stderr** (stdout carries protocol frames). Two
environment variables control the output:

| Variable | Values | Effect |
|------|------|------|
| `BB_LOG` | `error` \| `warn` \| `info` (default) \| `debug` | Log threshold. `info` and above print audit lines; set `warn`/`error` to silence auditing. |
| `BB_LOG_FORMAT` | `text` (default) \| `json` | Format of audit lines. `json` emits one JSON object per line, convenient for machine collection. |

**Audit events**: the MCP server emits one audit line for every `tools/call` it processes,
with per-call fields: `req` (monotonic request id), `tool` (tool name), `outcome`
(`ok`/`error`), `code` (on error, the stable error code from
[errors.json](../contracts/errors.json), otherwise `-`), and `dur_ms` (duration).

```text
# BB_LOG_FORMAT default (text)
[AUDIT] ts=1721000000000 req=7 tool=page_click outcome=ok code=- dur_ms=12
# BB_LOG_FORMAT=json
{"kind":"audit","ts":1721000000000,"req":"7","tool":"page_eval","outcome":"error","code":"EXECUTION_FAILED","dur_ms":8}
```

Error codes and the error taxonomy are in [architecture.md section 11.1](./architecture.md#111-error-taxonomy-errorsjson).

## Related

- Connection lifecycle and disconnect/reconnect semantics: [architecture.md section 5.2](./architecture.md#52-native-host-reconnect-flow).
- Error taxonomy (`NOT_CONNECTED` / disconnect class): [architecture.md section 11.1](./architecture.md#111-error-taxonomy-errorsjson).
