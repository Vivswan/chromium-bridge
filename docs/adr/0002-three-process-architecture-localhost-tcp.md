# ADR-0002: Three-process architecture with localhost TCP bridging

- **Status**: Accepted; superseded in part by ADR-0019 (localhost TCP -> 0600 Unix domain socket); the three-process architecture still holds
- **Date**: 2026-07-07

## Context

browser-bridge involves two independent "hosts":

- The **MCP client** (such as Claude Code or Codex) spawns a process as the MCP server (stdio JSON-RPC)
- **Chrome** spawns a process as the native messaging host (stdio NM frames)

These two hosts **each spawn their own process**; they are not parent and child and cannot share stdin/stdout. Some form of IPC is therefore required so the MCP server process and the native host process can exchange messages.

In addition, Chrome force-restarts the MV3 Service Worker every 5 minutes (Chromium #40733525). On restart all in-memory state is lost and the extension's native Port closes. That means no "session state" (the currently focused tab, the ref map from the latest snapshot) can live in the SW or in the native host.

## Decision

**Adopt a three-process architecture, with localhost TCP plus a lock file as the IPC:**

1. **MCP server process** (spawned by the MCP client, long-lived): holds all session state, listens on `127.0.0.1:0` (random port), writes the port plus a per-run secret to a 0600 lock file
2. **Native host process** (spawned by Chrome, living as long as the Port): extremely thin, only translates stdin NM frames <-> TCP NDJSON
3. **Chrome extension** (SW + content): performs the actual page operations

When the native host connects to the MCP server, it first sends one line, `{"hello": "<secret>"}`, for authentication; the connection is accepted only if it matches the secret in the lock file.

## Alternatives considered

### Option A: merge the MCP server and native host into one process
- **Not feasible**: the two hosts (MCP client, Chrome) each spawn their own process; the processes are not parent and child and stdin/stdout is not shared. It would take something like socket activation, which Chrome's native messaging does not support.

### Option B: Unix domain socket (instead of TCP)
- **Pros**: file permissions can be restricted to 0600, only the current user can connect, smaller attack surface
- **Cons**:
  - Not supported on Windows (the current target is macOS only, so this does not apply)
  - Path management is slightly fiddly (handling `/tmp` vs the user directory)
- **Why it was not chosen**: the user picked localhost TCP at decision time (easier debugging, can telnet in). TCP with a per-run secret and a 0600 lock file is secure enough on a single-user machine

### Option C: file IPC (the MCP server and host do not talk directly; both read and write the same file)
- **Cons**: poor concurrency/latency; unsuitable for interactive control (each tool call needs a round trip)
- **Rejected**: the user explicitly marked it "not recommended" among the options

### Option D: the native host holds the session state (instead of the MCP server)
- **Problem**: the native host lives as long as the Chrome Port; an SW restart loses it. The native host is also "passive" (spawned by Chrome) and unsuited to being the coordinator
- **Rejected**: state must live in the most stable process, the MCP server

## Consequences

### Positive
- **Stable session state**: the MCP server process does not lose state when the SW or Chrome restarts
- **Extremely thin host**: the native host only translates protocols; all logic lives in the MCP server, which is easy to test and maintain
- **Debuggable**: localhost TCP can be connected to manually with telnet/nc
- **Authentication**: per-run secret plus 0600 lock file prevents accidental connections from other users/processes on the same machine

### Negative
- **One more IPC layer**: in theory one extra serialize/deserialize round (in practice local TCP is < 1ms, negligible)
- **Lock file management**: the MCP server must clean up the lock file on exit; a stale lock file makes the host connection fail (handled: the host deletes the lock file when it cannot connect)
- **Random port**: the port differs on every MCP server start; the lock file is the only discovery mechanism
- **In theory other users on the same machine can connect**: the secret's protection depends on the lock file being 0600; unsafe on multi-user machines (the project's design assumption is single-user)

### Neutral
- localhost TCP is supported on macOS/Linux/Windows, so it is cross-platform (although v0.1 is tested on macOS only)

## Authentication details

- **Lock file**: `~/Library/Application Support/browser-bridge/run.lock` (macOS), mode 0600
- **Contents**: `{port, secret, pid}`; the secret is 128 bits of entropy (/dev/urandom)
- **Write**: atomic rename (tmp file -> final file), so the host never reads a half-written file
- **Verification flow**: after connecting, the host's first line is `{"hello": secret}`; the MCP server compares it against the secret in the lock file and rejects on mismatch
- **Stale handling**: when the host fails to connect it deletes the lock file, so the next MCP server start begins clean

## Implementation

- `src/ipc.rs`: `listen()` (bind + create LockFile), `connect()` (read lock + connect + send hello), `validate_hello()`
- `src/session.rs`: `attach_connection()` (verify hello + start a reader thread that dispatches BridgeResp), `call()` (register pending sender -> send BridgeReq -> wait for the response, 120s timeout)
- `src/native_host.rs`: two threads, stdin->TCP and TCP->stdout
- The MCP server deletes the lock file on exit (`stdin EOF`)

## Verified

End-to-end tests PASS:
1. mock host connects -> hello authentication passes -> tool-call round trip succeeds
2. `--native-host` mode: real NM frames flow both ways plus a full round trip
