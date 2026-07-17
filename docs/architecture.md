# Architecture: chromium-bridge

> This document describes the component structure, data flows, protocols,
> security model, and key constraints of chromium-bridge.
> For the "why" behind design decisions, see [adr/](./adr/).

## 1. Architecture overview

```
+----------------------------------------------------------------------------+
|                    chromium-bridge (single Rust binary)                    |
|                                                                            |
|  +---------------------------+   localhost TCP     +---------------------+ |
|  | MCP server (default mode) | <---NDJSON JSON---> | --native-host       | |
|  | - holds session state     |  127.0.0.1:<random> | (thin bridge)       | |
|  | - listens on TCP,         |                     | - stdin NM frames   | |
|  |   writes the lock file    |                     |   -> TCP            | |
|  | - tool dispatch           |                     | - TCP -> stdout     | |
|  |                           |                     |   NM frames         | |
|  +-------------+-------------+                     +----------+----------+ |
+----------------|------------------------------------------------|----------+
                 ^ stdio (NDJSON)                                  ^ stdin/stdout
                 | JSON-RPC 2.0                                    | NM frames (4B LE length + JSON)
                 |                                                 |
+----------------+------------+                     +--------------+---------+
| MCP client (Claude Code,    |                     | Chrome (spawns the     |
| etc.); the client manages   |                     | host itself)           |
| the connection              |                     +--------------+---------+
+-----------------------------+                                    | chrome.runtime.connectNative
                                                                   v
                                                    +------------------------+
                                                    | Chromium Bridge         |
                                                    | extension (MV3)        |
                                                    | background.js (SW):    |
                                                    |  - native port +       |
                                                    |    reconnect           |
                                                    |  - dispatches requests |
                                                    |    to content          |
                                                    |  - allowlist           |
                                                    |    management          |
                                                    | content.js:            |
                                                    |  - snapshot/click/fill |
                                                    |  - Toast/masking       |
                                                    +--------------+---------+
                                                                   | chrome.tabs.sendMessage
                                                                   v
                                                    +------------------------+
                                                    | the user's real page   |
                                                    | (logged in)            |
                                                    +------------------------+
```

## 2. The three processes

The system spans three independent processes, and understanding their
boundaries is the key to understanding the whole architecture.

| Process | Who starts it | Responsibility | Lifetime |
|------|---------|------|---------|
| **MCP server** | The MCP client (spawned via its server config) | Holds session state, listens on TCP, dispatches tool logic | Follows the client session |
| **native host** | Chrome (via the host manifest) | Thin bridge between stdin/stdout NM frames and TCP NDJSON | Follows the Chrome extension's Port |
| **Chrome extension (SW + content)** | Chrome | Actual page operations, allowlist, Toast | The SW restarts every 5 minutes; the extension follows the browser |

**Why three processes instead of one**: Chrome spawns the native host itself
(via the manifest) and the MCP client spawns the MCP server itself. The two
are **not** in a parent-child relationship, cannot share stdin/stdout, and so
need an IPC channel between them. See
[ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md).

**Why the native host is so thin**: all logic lives in the MCP server. That
way neither an SW restart nor a host restart loses session state (the state
is in the MCP server). The native host is just a protocol translator.

## 3. Protocol layers

The system involves three protocols, each with its own transport and framing.

### 3.1 Native Messaging (extension <-> native host)

Chrome's official protocol, defined at
[developer.chrome.com/native-messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

- **Frame format**: `4-byte little-endian u32 length` + `UTF-8 JSON`
- **Length**: counts only the JSON bytes, **excluding** the 4-byte prefix
- **Outbound (host -> Chrome) hard limit**: **1 MB** (exceeding it makes Chrome drop the Port immediately)
- **Inbound (Chrome -> host)**: 64 MB
- **Shutdown signal**: **stdin EOF** (not SIGTERM); the host should exit gracefully on EOF
- **stderr**: not shown to the user, but usable for logging (recorded in Chrome's internal logs)
- **argv[1]**: Chrome passes the caller origin (e.g. `chrome-extension://<id>/`), usable to tell multiple extensions apart

**Key traps** (all handled in the implementation):
- All stdout writes must be **single-threaded** with a **flush** per frame (concurrent writes interleave in the pipe buffer and corrupt frames)
- A panic prints to stdout by default and pollutes the stream -> a **stderr panic hook** is mandatory
- With `BufWriter`, an explicit flush after every frame is required
- `panic = "abort"` (Cargo profile) + the stderr hook, as a double safety net

### 3.2 MCP JSON-RPC (MCP server <-> MCP client)

Based on JSON-RPC 2.0 over NDJSON, defined at
[modelcontextprotocol.io](https://modelcontextprotocol.io/specification/2025-06-18).

- **Transport**: stdin/stdout, NDJSON (one message per line, LF-terminated)
- **No embedded newlines** (serde serialization escapes `\n` automatically)
- **Protocol version**: pinned to `2025-06-18`. See [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md)
- **Three-step handshake**: `initialize` (request/response) -> `notifications/initialized` (notification, no response) -> running
- **Tool errors**: use `isError: true` inside the result, **not** a JSON-RPC error (so the model sees the error text and can react)
- **Must handle**: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`
- **Error codes**: unknown method `-32601`, parse error `-32700`

**Minimum viable message set** (implemented in v0.1): `initialize` /
`notifications/initialized` / `ping` / `tools/list` / `tools/call`. Other
methods return `-32601`.

### 3.3 Internal bridge protocol (MCP server <-> native host)

Custom, over localhost TCP, NDJSON transport.

```typescript
// Request: MCP server -> native host -> extension
interface BridgeReq {
  id: number;        // monotonically increasing, used to pair responses
  op: string;        // operation name, e.g. "tab_list", "page_click"
  tabId?: number;    // target tab (optional; default = currently active tab)
  args: any;         // operation arguments
}

// Response: extension -> native host -> MCP server
interface BridgeResp {
  id: number;        // matches BridgeReq.id
  ok: boolean;
  data?: any;        // returned data on success
  error?: string;    // error message on failure
}
```

**Authentication**: when the connection is established, the native host first
sends one line, `{"hello": "<secret>"}`, and the MCP server validates it
against the secret in the lock file. See [ipc.rs](../src/ipc.rs).

## 4. Components in detail

### 4.1 Rust backend (`src/`)

| File | Responsibility |
|------|------|
| `main.rs` | Mode dispatch: no arguments = MCP server, `--native-host` = native host, `doctor`/`status` = read-only self-check (see [cli.md](./cli.md)), `--help` = help |
| `protocol.rs` | Message types plus read/write functions for the three protocols; stderr panic hook; SIGPIPE ignore |
| `ipc.rs` | localhost TCP listener + lock file in the user directory + hello authentication + secret from the system randomness source |
| `native_host.rs` | `--native-host` mode: two threads (stdin -> TCP, TCP -> stdout), graceful exit on EOF |
| `mcp_server.rs` | Default mode: TCP accept thread + stdin JSON-RPC main loop + message dispatch |
| `tools/` | Schema definitions for the 15 tools (`catalogue.rs`) + the `HANDLERS` registry (`{name, build_payload}` pure functions, `mod.rs`) + argument shaping (`handlers.rs`) -> dispatch to session.call |
| `session.rs` | Connection management + request/response pairing by id (one mpsc channel per id) + a per-connection generation id (fixes the writer-clobber race; pending calls drain as `Disconnected` on disconnect) + 120s timeout |
| `error.rs` | Typed error `CallError` at the tool-call boundary (thiserror); its Display is the text the model sees. See [ADR-0014](./adr/0014-leveled-logging.md) |
| `log.rs` | Leveled stderr logger controlled by `BB_LOG` (error/warn/info/debug, default info) + the `log_*!` macros. See [ADR-0014](./adr/0014-leveled-logging.md) |

### 4.2 Chrome extension (`extension/`)

The extension source is written in **TypeScript** (strict) under
`extension/src/*.ts` and bundled by **esbuild** into IIFEs in
`extension/dist/`, with static assets (manifest/HTML/CSS/icons) copied in.
**The load-unpacked target is `extension/dist/`** (not `extension/`). After
changing code, run `bun run build` (or `just ext-build`) first. See
[ADR-0012](./adr/0012-typescript-esbuild-extension-build.md).

| Source (`src/`) | Artifact (`dist/`) | Responsibility |
|------|------|------|
| `manifest.json` (static, copied into dist) | `manifest.json` | MV3; permissions=[tabs,scripting,storage,nativeMessaging]; **no static host_permissions** (everything goes through optional, on-demand requests) |
| `background.ts` | `background.js` | SW **entry point** (about 20 lines): registers the onMessage router + connectNative on startup. The real logic lives in `src/background/*` (see below) |
| `content.ts` | `content.js` | content script **entry point** (about 30 lines): re-injection guard + onMessage listener -> `handle`. The real logic lives in `src/content/*` (see below) |
| `options.ts` + `options.html` | `options.js` + `options.html` | Standalone Options settings page (see [ADR-0011](./adr/0011-options-page-for-settings.md)) |
| `popup.ts` + `popup.html` | `popup.js` + `popup.html` | Authorization UI: shows connection status, the allowlist (revocable), and Allow/Deny for pending authorization requests |
| `toast.css` (static, copied into dist) | `toast.css` | Styles for the high-risk confirmation Toast |

**Modular structure**: the two giant files have been split into cohesive
modules; esbuild bundles the imports back into single IIFEs, so runtime
behavior is unchanged (verified by dom_test 77 / smoke / e2e).

- `src/shared/` (shared by both sides, pure logic, unit-tested): `types` (bridge/message/settings types), `settings` (DEFAULTS + getSetting), `masking` (catalog of masking patterns), `allowlist` (glob matching / domain normalization), `ops` (tool catalog; unit tests check it matches `tools.rs`)
- `src/background/`: `port` (native port lifecycle), `dispatch` (BridgeReq routing + tool-disable gate), `tabs` (target tab resolution/injection + the tab_* tools), `precise` (page_snapshot_precise / CDP), `cookies` (cookie_get), `allowlist-store` (stored allowlist + authorization flow), `messages` (runtime.onMessage routing)
- `src/content/`: `refs` (encapsulated ref state), `snapshot` (a11y tree), `actions` (click/fill/text/screenshot/scroll), `wait`, `eval`, `storage`, `toast`, `handle` (op dispatch)

The dependencies form an acyclic DAG: `shared/*` -> `background/allowlist-store`
-> `tabs` -> `precise`/`cookies` -> `dispatch` -> `port` -> `messages`; on the
content side, `shared/*`/`util` -> `refs`/`snapshot` -> `toast` ->
`actions`/`eval` -> `handle`. Unit tests (`src/shared/*.test.ts`, bun) cover
the pure modules, including one cross-language guard (the op list must match
`tools.rs`).

### 4.3 Install artifacts

macOS:

```
~/.chromium-bridge/
|-- chromium-bridge          # release binary (608KB)
|-- run-host-chrome.sh      # wrapper: exec chromium-bridge --native-host --label chrome
|-- run-host-<browser>.sh   # one wrapper per installed browser (brave/edge/...)
`-- run-host.sh             # label-less wrapper, only for manual --nm-dir registration
                            # (wrappers work around the NM manifest's lack of an args field)

~/Library/Application Support/Google/Chrome/NativeMessagingHosts/
`-- com.vivswan.chromium_bridge.host.json   # host manifest; path points at that browser's own wrapper
```

Windows:

```text
%LOCALAPPDATA%\chromium-bridge\
|-- chromium-bridge.exe
`-- com.vivswan.chromium_bridge.host.json

HKCU\Software\Google\Chrome\NativeMessagingHosts\com.vivswan.chromium_bridge.host
`-- (Default) = absolute path of the manifest above
```

Linux:

```text
${XDG_DATA_HOME:-~/.local/share}/chromium-bridge/
|-- chromium-bridge
|-- run-host-chrome.sh
|-- run-host-<browser>.sh
`-- run-host.sh

${XDG_CONFIG_HOME:-~/.config}/google-chrome/NativeMessagingHosts/
`-- com.vivswan.chromium_bridge.host.json

${XDG_CONFIG_HOME:-~/.config}/chromium/NativeMessagingHosts/
`-- com.vivswan.chromium_bridge.host.json   # when Chromium or --browser both is selected
```

On Windows the manifest points directly at the EXE. When Chrome starts the
native host it appends the caller's extension origin, and the binary uses
that to enter native-host mode; on macOS/Linux the wrapper passes
`--native-host` explicitly. On Linux the lock file lives at
`$XDG_RUNTIME_DIR/chromium-bridge/run.lock` when a runtime dir exists,
falling back to the XDG cache otherwise; see
[ADR-0016](./adr/0016-linux-wsl-support.md).

The extension itself is loaded **load-unpacked** from **`extension/dist/`**
(the esbuild output: bundled from `src/*.ts` plus copied static assets);
`install.sh`/`install.ps1` build it first. dist/ is not checked in, so after
cloning run `bun run build` (or `just ext-build`) first. See
[ADR-0012](./adr/0012-typescript-esbuild-extension-build.md).

## 5. Key data flows

### 5.1 One complete tool-call round trip (`page_click(ref="e3")`)

```
1. MCP client -> MCP server (stdin NDJSON):
   {"jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"page_click","arguments":{"ref":"e3"}}}

2. mcp_server.handle() -> tools.dispatch()
   -> session.call("page_click", None, {"ref":"e3"})
   -> assigns BridgeReq.id=1, writes to TCP

3. native host reads TCP NDJSON -> converts to an NM frame -> writes stdout

4. background.js Port.onMessage receives {op:"page_click",args:{ref:"e3"}}
   -> resolveTargetTab(currently active tab)
   -> ensureAllowed(tab.url)  // allowlist check; opens the popup if not authorized
   -> injectIfNeeded(tab.id)  // dynamically injects content.js
   -> chrome.tabs.sendMessage(tab.id, {op, args})

5. content.js handle()
   -> resolveTarget({ref:"e3"}) // refMap lookup -> element
   -> isHighRiskClick(el)? // if submit/link -> confirmWithToast()
     -> injects the Toast DOM; user clicks Allow -> continue; Deny/timeout -> throw
   -> el.scrollIntoView() + el.click()

6. The result returns along the same path:
   content -> chrome.runtime.sendMessage response
   -> background Port.postMessage({id:1,ok:true,data:{clicked:"e3"}})
   -> native host reads the NM frame -> converts to NDJSON -> writes TCP

7. session receives the BridgeResp -> finds the pending sender by id=1 -> wakes it
   -> mcp_server returns the tools/call result -> MCP client
```

### 5.2 Native host reconnect flow

```
Chrome closes the extension Port -> native host gets stdin EOF -> host exits
The extension background.js onDisconnect fires -> scheduleReconnect(2s)
After 2s, connectNative() -> Chrome re-spawns the host -> host reads the lock file -> connects to TCP -> sends hello
MCP server accepts -> validate_hello -> session.attach_connection (replaces the old connection)
```

## 6. Security model

See the individual ADRs for detail; this is the overview.

| Boundary | Mechanism | ADR |
|------|------|-----|
| Domain allowlist | chrome.storage.local + popup authorization + permissions.request | [0004](./adr/0004-allowlist-with-optional-host-permissions.md) |
| High-risk action confirmation | content script injects a Toast; 30s timeout rejects; 60s grace window | [0006](./adr/0006-toast-confirmation-for-high-risk.md) |
| page_eval | Enlarged Toast confirming each call + a short same-origin window + return values masked by default | [0008](./adr/0008-page-eval-confirmation-channel.md) |
| host authentication | allowed_origins hardcodes the extension ID | [0002](./adr/0002-three-process-architecture-localhost-tcp.md) |
| bridge socket | per-run secret + lock file in the user directory (Unix mode 0600) | [0002](./adr/0002-three-process-architecture-localhost-tcp.md) |
| Masking | page_text masks passwords + long digit runs; page_fill masks password values when echoed | (none) |
| Protocol safety | NM 1MB outbound limit; single-threaded writes + flush; stderr panic hook | (none) |
| Settings management | Standalone Options page centralizes security switches/timeouts/tool enablement/allowlist/allowAllSites | [0011](./adr/0011-options-page-for-settings.md) |

## 7. Key constraints (pitfalls hit and handled during implementation)

### 7.1 MV3 Service Worker 5-minute restart (Chromium #40733525)
**Constraint**: Chrome force-restarts the SW every 5 minutes, losing all
in-memory state; the Port closes and the native host exits on stdin EOF.
**Mitigation**:
- The allowlist is stored in `chrome.storage.local` (not in memory)
- The SW automatically calls `connectNative()` to reconnect on startup
- Session state (current tab, ref map) lives in the MCP server process, not in the SW
- ref markers are written to the DOM element's `data-zcb-ref` attribute, so after an SW restart the content script can rebuild the refMap from the DOM

### 7.2 chrome.debugger forces an infobar
**Constraint**: any `chrome.debugger.attach` forces a "Started debugging this
browser" infobar at the top of every tab, and it cannot be dismissed (short of
the `--silent-debugger-extension-api` launch flag, which brings back a special
launch).
**Mitigation**: the default snapshot uses a content script approximation and
never touches the debugger; when the authoritative a11y tree is needed, call
`page_snapshot_precise` explicitly, which attaches temporarily and detaches
immediately. See
[ADR-0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) and
[ADR-0009](./adr/0009-page-snapshot-precise-debugger.md).

### 7.3 The Native Messaging manifest has no args field
**Constraint**: the manifest's `path` must be an executable and cannot carry
arguments.
**Mitigation**: use a wrapper (shebang script):
`exec chromium-bridge --native-host --label <browser>`. One
`run-host-<browser>.sh` per browser; the label identifies that browser, and
the server keeps a multi-browser connection registry keyed by label (see
[ADR-0022](./adr/0022-multi-browser-label-routing.md)).

### 7.4 chrome.permissions.request requires a user gesture
**Constraint**: `permissions.request` (requesting host permissions) must be
called in a user-gesture context such as a popup/action click; it cannot be
called from the service worker in the background.
**Mitigation**: the allowlist authorization flow goes through the popup. When
the user clicks Allow in the popup, the host permission is requested and the
allowlist entry is recorded at the same time.

### 7.5 Static content_scripts matches conflict with optional permissions
**Constraint**: in MV3, the `matches` declaration of content_scripts also
needs host permissions to inject. With an initial `host_permissions: []`, the
content script never injects at all.
**Mitigation**: **no manifest content_scripts**; everything uses
`chrome.scripting.executeScript` dynamic injection. Permissions follow
`optional_host_permissions`: whichever domain is granted is the domain that
gets injected.

### 7.6 Rust panics pollute stdout
**Constraint**: panic messages print to stdout by default, corrupting NM
frames and MCP NDJSON and dropping the connection.
**Mitigation**:
- The Cargo release profile sets `panic = "abort"`
- `install_stderr_panic_hook()` redirects panic messages to stderr
- Both together, as a double safety net

### 7.7 page_eval uses the Function constructor, not eval()
**Constraint**: `page_eval` must run arbitrary JS in the page's global scope,
but content.js itself runs inside a strict-mode closure. A direct `eval(code)`
cannot see the page's globals, and eval has its own scope under strict mode.
**Mitigation**: use
`new Function('"use strict"; return (async () => { <code> })()')()`. The
Function constructor executes in the global scope and supports
`return`/`await` (the code is wrapped in an async IIFE).
**Known limitation**: a reliable execution timeout is hard to set (JS is
single-threaded and cannot be interrupted externally); the session layer's
120s timeout is the backstop, and an infinite loop will hang the page. Before
leaving the page, the return value goes through `serializeResult` for safe
handling (circular references/DOM/Error/BigInt/exotic types) and then through
`maskSensitive` for masking. See
[ADR-0008](./adr/0008-page-eval-confirmation-channel.md).

### 7.8 chrome.debugger: infobar / restrictions / SW-only
**Constraints** (page_snapshot_precise):
- `chrome.debugger.attach` forces a "Started debugging this browser" infobar at the top of **every tab**; it persists while attached and cannot be dismissed; it disappears after `detach`.
- The `chrome.debugger` API can only be called from the **extension context (SW/popup)**; a content script runs in the page context and cannot reach it.
- Cannot attach to `chrome://`, `chrome-extension://`, the Chrome Web Store, `view-source:`, or `about:` pages.
- Only one debugger per tab at a time (if DevTools is open, attach fails with "Another debugger is already attached").

**Mitigation**:
- Execution happens entirely in background.js (the SW); only "show the notification Toast" is delegated to the content script (the Toast must render in the page)
- Within one handler: attach -> `getFullAXTree` -> `resolveNode` + `callFunctionOn` to stamp refs -> `detach`; the infobar flashes for only about 1 second
- Before attaching, the content script shows an **informational Toast** (blue, proceeds by default, cancellable) to inform the user
- **`detach` must be on the finally path**: detach on any error, or the infobar stays forever
- A URL-scheme check up front filters out non-debuggable pages
- refs use a `p` prefix (precise) to stay clear of the content script's `e` prefix and avoid collisions; content.js's `resolveTarget` looks elements up by DOM attribute value, so the prefix does not matter

**Key chain**: `Accessibility.getFullAXTree` (each AXNode carries a
`backendDOMNodeId`) -> `DOM.resolveNode({backendNodeId})` -> `RemoteObjectId`
-> `Runtime.callFunctionOn` to stamp `data-zcb-ref`. See
[ADR-0009](./adr/0009-page-snapshot-precise-debugger.md).

### 7.9 chrome.cookies is host-bound / localStorage is same-origin / httpOnly is readable
**Constraints** (cookie_get / storage_get):
- The `chrome.cookies` API is **bound by host_permissions**: `getAll({})` returns only cookies for authorized domains, **not** all browser cookies. The blast radius matches the existing tools, reusing the allowlist.
- `chrome.cookies` is only available in the **SW/extension context** -> cookie_get lives in background.js.
- The page's `localStorage`/`sessionStorage` is readable only from a **content script (page context, same origin)**; `chrome.storage` belongs to the extension, not the page, and the two are different things. -> storage_get lives in content.js.
- `chrome.cookies` **can read httpOnly cookies** (its core value over `document.cookie`; session tokens usually live there).
- The `cookies` permission adds **no extra install warning** (debugger already triggers the maximal host warning).
- Unauthorized domains: getAll returns an **empty array, not an error**, so "not authorized" and "genuinely no data" cannot be told apart; the only option is a friendly hint.

**Mitigation**:
- cookie_get in background, storage_get in content (each determined by its data source)
- **Read-only**: no set/remove. cookie_set could forge httpOnly+Secure cookies (session fixation), which not even XSS can do
- Masking: cookie values use the compact maskCookieValue; storage values use maskString. **storage_get always masks** (not governed by the evalMask switch, because silent reads leak tokens with risk equivalent to eval)
- Values are masked but structural fields such as name/domain/httpOnly are kept (diagnostic value)

See [ADR-0010](./adr/0010-cookie-storage-readonly.md).

## 8. Technology choices

| Dimension | Choice | Rationale |
|------|------|------|
| Backend language | Rust | Single-binary distribution is reliable; the host manifest takes an absolute path with no PATH dependency; good performance and memory. See [ADR-0001](./adr/0001-use-rust-single-binary.md) |
| Binary split | Single binary + subcommands | One codebase, one compile, upgrades replace one file. See [ADR-0001](./adr/0001-use-rust-single-binary.md) |
| IPC | localhost TCP + lock file | Simple across processes; easy to debug; per-run secret authentication. See [ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md) |
| Rust dependencies | serde/serde_json + libc + thiserror | The protocol is still handwritten and tokio is still unused; beyond serde, `libc` (signals/low-level interaction) and `thiserror` (typed errors on the tool path) were added. This revises ADR-0001's old "serde is the only dependency" wording; the minimal-dependency principle stands. See [ADR-0014](./adr/0014-leveled-logging.md) |
| Extension toolchain | TypeScript + esbuild -> dist/ | strict types + a single dependency bundling to IIFE; load-unpacked target is `extension/dist/`. See [ADR-0012](./adr/0012-typescript-esbuild-extension-build.md) |
| Engineering gates | justfile + GitHub Actions | A single task entry point + CI (fmt/clippy -D warnings, Biome, typos/machete + tests); Cargo is the version's single source. See [ADR-0013](./adr/0013-ci-and-toolchain.md), revised by the 2026-07 bun/Biome/just migration |
| Extension platform | MV3 | Mandated by Chrome; Service Worker model |
| snapshot implementation | content script approximate a11y tree | No infobar; roughly 90% coverage, with the debugger fallback as backstop. See [ADR-0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) |
| MCP version | 2025-06-18 | The current stable version; the one MCP clients commonly implement. See [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md) |

## 9. Known limitations

1. **snapshot accuracy is roughly 90%**: the content script recomputes a11y names and misses shadow DOM and complex ARIA; phase two adds the debugger fallback
2. **Cross-origin iframes**: the content script is bound by the same-origin policy and cannot read cross-origin iframe content
3. **Single-user machine**: the bridge socket has secret authentication, but the design assumes a single-user machine
4. **Chrome platform scope**: supports Google Chrome on macOS/Windows/Linux and Chromium on Linux; Edge should work in theory but is untested
5. **Forced takeover on Windows**: Windows uses `TerminateProcess` to take over an old server, so the old process cannot clean up after itself; the new server explicitly deletes and replaces the stale lock file

## 10. Roadmap

See [requirements.md section 7, Phase plan](./requirements.md#7-phase-plan).
Extension points reserved in the architecture:
- **Adding a new tool**: add a schema definition in `tools/catalogue.rs` + one `HANDLERS` entry in `tools/mod.rs` (a `build_payload` pure function), and add the corresponding op handling in the extension's background/content
- **page_eval**: needs a new high-risk confirmation channel (a stronger confirmation than the Toast)
- **debugger fallback**: add a `page_snapshot_precise` tool; the SW attaches/detaches temporarily
- **Skill layer**: no architecture change; purely additive skill files that teach the AI to combine existing tools

### 10.1 Engineering standardization overhaul

A round of engineering standardization reshaped the build, test, and
observability baseline without changing the tools' runtime behavior. The
decisions:
- **[ADR-0012](./adr/0012-typescript-esbuild-extension-build.md)**: the extension moved to TypeScript, bundled by esbuild into `extension/dist/` (the new load-unpacked target).
- **[ADR-0013](./adr/0013-ci-and-toolchain.md)**: task-runner entry point + GitHub Actions CI + rustfmt/clippy and TS lint/format gates + Cargo-sourced version sync (tooling now just + Biome, 2026-07).
- **[ADR-0014](./adr/0014-leveled-logging.md)**: `BB_LOG` leveled stderr logging + thiserror typed errors (new `libc` and `thiserror` dependencies).

## 11. Protocol boundary: error taxonomy and handshake

The cross-process contracts are centralized in
[`contracts/`](../contracts/README.md) (the single source of truth), and
runtime behavior is validated against them. This section ties together the
three contracts related to the protocol boundary.

### 11.1 Error taxonomy (errors.json)

At the tool-call boundary, Rust's typed error `CallError` (see section 4.1,
`error.rs`) maps to the stable `code`s in
[`contracts/errors.json`](../contracts/errors.json); `cargo test` validates
the mapping against that file, and the extension side normalizes its own
failures to the same set of `code`s. The `code` is for programmatic decisions
(it carries `category` and `retryable`); what the model/user sees is the
`message`. This way the "three connection-layer failures"
(`NOT_CONNECTED` / `EXTENSION_NOT_READY` / `CONNECTION_LOST`) have one shared
meaning across the three processes instead of each telling its own story.

### 11.2 Capability / version handshake (capabilities.json + protocol-version.json)

On top of the internal bridge protocol of section 3.3, connection setup
**intends** one more step beyond the `hello` secret authentication of section
3.3: capability + version negotiation.

- The native host / extension reports the internal protocol version it
  supports per [`protocol-version.json`](../contracts/protocol-version.json)
  (currently `1`) and its available capability set (see
  [`capabilities.json`](../contracts/capabilities.json); capabilities are
  conceptually derived from the `permission`/`scope` notions in `tools.json`).
- Incompatible version -> **fail fast** with `PROTOCOL_MISMATCH` (see
  errors.json) and a clear message, rather than accepting the connection and
  blowing up late on some `tools/call` with "unknown op".
- A tool whose required capability was not advertised -> reject that tool
  call up front instead of dispatching an op the extension cannot handle.

Note the three distinct "versions": the MCP JSON-RPC version `2025-06-18`
(section 3.2 / [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md)),
the internal bridge protocol version (an integer, protocol-version.json), and
the extension release version (Cargo-sourced). They are all different.

> To troubleshoot these two links at runtime (whether the connection is
> reachable; whether the lock file/port/manifest are in place), use the
> read-only `chromium-bridge doctor`; see [cli.md](./cli.md).
