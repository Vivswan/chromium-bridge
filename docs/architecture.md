# Architecture: chromium-bridge

> This document describes the component structure, data flows, protocols,
> security model, and key constraints of chromium-bridge.
> For the "why" behind design decisions, see [adr/](./adr/).

## 1. Architecture overview

```
MCP client A --stdio--> +--------------------------------------------------+
MCP client B --stdio--> | chromium-bridge (MCP server instances)           |
                        |                                                  |
                        |  first instance = BROKER                         |
                        |   - owns the bridge socket + lock file           |
                        |   - admits each harness against the              |
                        |     trusted-client allowlist (attested)          |
                        |   - holds session state, dispatches tools        |
                        |  later instances = relays, attach as clients     |
                        +------------------------+-------------------------+
                                                 | bridge socket: NDJSON over a
                                                 | 0600 Unix-domain socket in a
                                                 | 0700 runtime dir (loopback
                                                 | TCP on Windows); peer-UID +
                                                 | attestation + HMAC handshake
                                                 v
                        +--------------------------------------------------+
                        | chromium-bridge --native-host  (one per browser, |
                        | spawned by that browser, label e.g. "chrome")    |
                        +------------------------+-------------------------+
                                                 | stdin/stdout, Chrome native
                                                 | messaging (4B LE len + JSON)
                                                 v
                        +--------------------------------------------------+
                        | Chromium Bridge extension (MV3, WXT)             |
                        |  service worker: dispatch, allowlist, masking,   |
                        |    kill-switch mirror, enrollment pin            |
                        |  content script + CDP backend: one shared DOM    |
                        |    implementation (snapshot/click/fill/...)      |
                        |  confirm.html: extension-owned confirmation      |
                        |    window, off the page-reachable DOM            |
                        +------------------------+-------------------------+
                                                 |
                                                 v
                                       the user's real page (logged in)

  Management surfaces (co-equal, over the same core, never a trust root):
    - Chromium Bridge desktop app (Tauri, macOS): registration, pairing,
      clients, kill switch, audit    [ADR-0029]
    - the CLI: doctor --fix / uninstall / pair / pair-client / kill / audit
```

## 2. The processes

| Process | Who starts it | Responsibility | Lifetime |
|------|---------|------|---------|
| MCP server (broker) | The first MCP client to spawn one | Owns the socket and the lock, admits harnesses, holds session state, dispatches tools | Until the last attached harness detaches |
| MCP server (relay) | Each further MCP client | Attests itself to the broker and forwards its harness's calls | Follows its client session |
| native host | Each browser (via the host manifest) | Thin bridge between stdin/stdout NM frames and socket NDJSON; answers control frames (enrollment, kill, client admin) itself | Follows the browser extension's Port |
| extension (SW + content) | The browser | Page operations, allowlist, confirmations, masking | The SW restarts about every 5 minutes; the extension follows the browser |
| desktop app | The user | Management UI over the core's engines (registration, pairing, revocation, kill, audit) | User-run |

Why separate server and host processes: the browser spawns the native host
itself (via the manifest) and the MCP client spawns the MCP server itself.
The two are not parent and child, cannot share stdin/stdout, and so need an
IPC channel between them. See
[ADR-0002](./adr/0002-three-process-architecture-localhost-tcp.md) (original
design) and [ADR-0019](./adr/0019-authenticated-ipc.md) /
[ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md) (the
authenticated socket and the broker that own that channel today).

Why the native host is so thin: all logic lives in the MCP server, so
neither an SW restart nor a host restart loses session state. The host is a
protocol translator with one addition: it terminates the control plane
(enrollment ceremony frames, kill-switch frames, client-admin frames,
audit-event forwarding) so those work even when the bridge is down or killed.

Why a broker instead of one server per client: several MCP clients may be
configured at once, and the old newest-wins takeover (SIGTERM the previous
server) made them fight over the browsers. The first instance now owns the
socket; later attested instances attach as relays and share one session,
ref-counted so the broker exits when the last harness detaches. See
[ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md).

## 3. Protocol layers

### 3.1 Native Messaging (extension <-> native host)

Chrome's official protocol, defined at
[developer.chrome.com/native-messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

- Frame format: `4-byte little-endian u32 length` + `UTF-8 JSON`
- Length counts only the JSON bytes, excluding the 4-byte prefix
- Outbound (host -> Chrome) hard limit: 1 MB (exceeding it makes Chrome drop the Port immediately)
- Inbound (Chrome -> host): 64 MB
- Shutdown signal: stdin EOF (not SIGTERM); the host exits gracefully on EOF
- stderr: not shown to the user, but usable for logging (recorded in Chrome's internal logs)
- argv: Chrome appends the caller origin (e.g. `chrome-extension://<id>/`)

Key traps (all handled in the implementation):
- All stdout writes must be single-threaded with a flush per frame
  (concurrent writes interleave in the pipe buffer and corrupt frames)
- A panic prints to stdout by default and pollutes the stream, so a stderr
  panic hook is mandatory
- `panic = "abort"` (Cargo profile) + the stderr hook, as a double safety net

### 3.2 MCP JSON-RPC (MCP server <-> MCP client)

Based on JSON-RPC 2.0 over NDJSON, defined at
[modelcontextprotocol.io](https://modelcontextprotocol.io/specification/2025-06-18).

- Transport: stdin/stdout, NDJSON (one message per line, LF-terminated)
- Protocol version pinned to `2025-06-18`; see [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md)
- Three-step handshake: `initialize` -> `notifications/initialized` -> running
- Tool errors use `isError: true` inside the result, not a JSON-RPC error,
  so the model sees the error text and can react
- Handled methods: `initialize`, `notifications/initialized`, `ping`,
  `tools/list`, `tools/call`; unknown methods return `-32601`
- Before any tool call is served, the harness that spawned the server must
  pass admission against the trusted-client allowlist (section 6 and
  [trust-boundaries.md](./security/trust-boundaries.md))

### 3.3 Internal bridge protocol (broker <-> native hosts and relays)

Custom, NDJSON over the bridge socket: a 0600 Unix-domain socket inside the
0700 per-user runtime directory on macOS/Linux, a loopback TCP socket on
Windows (see [SECURITY.md](../SECURITY.md#platform-support)).

Connection setup, in order, each step fail-closed:

1. **Kernel checks** (Unix): the accepting end verifies the peer's UID equals
   its own and takes a kernel-attested identity of the peer's running
   executable, which must match its own image (mutual; see
   [ADR-0020](./adr/0020-kernel-attested-peer-identity.md)).
2. **HMAC handshake**: the server sends a fresh nonce; the peer answers with
   `HMAC-SHA256(secret, nonce)` over the per-run secret from the lock file.
   The secret never crosses the wire; the nonce defeats replay.
3. **Attach frame**: one mandatory role-declaring frame. A browser's native
   host attaches with its label (`chrome`, `brave`, ...); a relay attaches
   with its attested harness identity, which the broker checks against the
   trusted-client allowlist ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)).

After attach, tool traffic is the `BridgeReq`/`BridgeResp` envelope pair
(`src/packages/core/src/protocol.rs`; the Rust types are the wire contract,
see section 11):

```typescript
interface BridgeReq {
  id: number;        // monotonically increasing, pairs responses
  op: string;        // operation name, e.g. "tab_list", "page_click"
  tabId?: number;    // target tab (optional; default = active tab)
  browser?: string;  // target browser label (required when several attached)
  args: unknown;     // operation arguments
}

interface BridgeResp {
  id: number;
  ok: boolean;
  data?: unknown;
  error?: string;
}
```

Control frames (enrollment, revocation, kill switch, audit events) ride the
native-messaging leg between the extension and its host and are terminated
at the host; the same frame kinds arriving from the socket leg are dropped
as injections (see [trust-boundaries.md](./security/trust-boundaries.md)).

## 4. Components in detail

### 4.1 The Rust core (`src/packages/core`) and the binary (`src/apps/host`)

The binary is a thin argv dispatch (`src/apps/host/src/main.rs`) over the
`chromium-bridge-core` library:

| Module | Responsibility |
|------|------|
| `protocol.rs` | Message types and read/write for the three protocols; the wire-envelope contract; stderr panic hook; SIGPIPE ignore |
| `ipc/` | The bridge socket: platform socket + lockfile + peer credentials + attestation + HMAC handshake, split per concern with platform impls |
| `broker.rs` | Broker ownership, relay attach/detach ref-counting, DoS caps, the kill-switch watcher |
| `session.rs` | Connection registry keyed by browser label; request/response pairing by id; per-connection generation guard; 120s timeout |
| `mcp_server.rs` | Default mode: harness admission, JSON-RPC loop, dispatch into the shared session |
| `native_host.rs` | `--native-host` mode: NM frames <-> socket NDJSON, control-plane frame handling, graceful exit on EOF |
| `tools/` | The tool catalogue (26 tools; the cross-process contract source), capabilities, and the `HANDLERS` registry |
| `allowlist.rs` | The trusted-client allowlist: `pair-client` / `revoke-client` / `list-clients`, atomic 0600 writes, fail-closed parsing |
| `revocation.rs` | The revocation epoch and the kill latch (`revocation.json`), one-way enrollment latch, tamper detection |
| `kill.rs` | Kill-switch engage/release; release demands a `PresenceAttestation` |
| `presence/` | User-presence proofs: Secure Enclave Touch ID on an enrolled Mac; interactive fail-closed floors elsewhere ([ADR-0031](./adr/0031-touch-id-confirmations-and-presence-grants.md)) |
| `enclave/` | The enrollment ceremony: Secure Enclave key, presence-gated signing, pin/verify/revoke ([ADR-0021](./adr/0021-enrollment-ceremony.md)) |
| `audit.rs` | The durable audit trail: bounded 0600 `audit.log`, strict-parsed JSON records, `audit` subcommand reader |
| `registration.rs` + `browsers.rs` | The registration engine and browser-path resolver behind `doctor --fix`, `uninstall`, and the app's Connect/Repair buttons |
| `doctor.rs` | Read-only health report (`doctor` / `status` / `doctor --list`) |
| `error.rs` | Typed `CallError` at the tool-call boundary and the stable `ERROR_SPECS` taxonomy |
| `log.rs` | Leveled stderr logger (`BB_LOG`) and the `log_*!` macros |
| `identity.rs` | The native-messaging host id and the pinned extension key: the single definition site |

### 4.2 The extension (`src/apps/extension`)

Built on WXT (which generates the manifest, including the pinned key) with
React UI, TypeScript strict, Vitest + `fakeBrowser` tests
([ADR-0027](./adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md)).
The load-unpacked target is the build output
`build/extension/chrome-mv3`, not the source directory.

| Where | Responsibility |
|------|------|
| `src/entrypoints/background.ts` | Service-worker entry: native port + reconnect, message router |
| `src/entrypoints/content.ts` | Content-script entry: injection guard, op dispatch into the shared DOM layer |
| `src/entrypoints/confirm/` | The confirmation window: an extension-owned `chrome-extension://` document the page cannot read, overlay, or click |
| `src/entrypoints/options/`, `popup/` | Settings (Zod-validated, versioned, migrated) and the authorization/status popup |
| `src/lib/background/` | Dispatch, allowlist store, tabs/CDP backends, cookies, egress masking, kill mirror, enrollment |
| `src/lib/dom/` | The one shared DOM implementation (snapshot/refs/actions); the CDP backend ships its stringified source so the two page backends cannot diverge |
| `src/lib/shared/` | Settings schema, message protocol types, allowlist matching |
| `src/locales/*.yml` | The i18n bundles (en, zh_CN, zh_TW); CI enforces key parity |

Trust-state isolation: the enrollment pin, kill mirror, allowlist, and audit
ring live in storage confined to extension contexts
(`setAccessLevel(TRUSTED_CONTEXTS)`), and the message router refuses
security-relevant messages from anything but the extension's own pages.

### 4.3 On-disk artifacts

Registration (written by the app's Connect/Repair buttons or `doctor --fix`,
both through `registration.rs`):

```
macOS   ~/.chromium-bridge/run-host-<browser>.sh      # wrapper: exec <host> --native-host --label <browser>
        ~/Library/Application Support/<Vendor>/NativeMessagingHosts/
          com.vivswan.chromium_bridge.host.json       # manifest -> that browser's wrapper

Linux   ${XDG_DATA_HOME:-~/.local/share}/chromium-bridge/run-host-<browser>.sh
        ${XDG_CONFIG_HOME:-~/.config}/<vendor>/NativeMessagingHosts/
          com.vivswan.chromium_bridge.host.json

Windows %LOCALAPPDATA%\chromium-bridge\com.vivswan.chromium_bridge.host.json
        HKCU\Software\<Vendor>\NativeMessagingHosts\com.vivswan.chromium_bridge.host
          (Default) = absolute path of the manifest; manifest points at the exe
```

The manifest's `path` points at the registering binary in place (through the
wrapper on Unix, because the manifest format has no `args` field); nothing is
built, downloaded, or copied. On Windows, Chrome appends the extension origin
to the command line, which selects native-host mode.

Runtime state, in the 0700 per-user runtime directory (macOS:
`$XDG_RUNTIME_DIR/chromium-bridge` or
`~/Library/Application Support/chromium-bridge`; Linux:
`$XDG_RUNTIME_DIR/chromium-bridge` with XDG-cache fallback; Windows:
`%LOCALAPPDATA%\chromium-bridge`):

| File | Contents |
|------|----------|
| `run.lock` (0600) | The broker's pid and the per-run HMAC secret; the socket rendezvous |
| the bridge socket (0600) | Unix only; no listening port exists |
| `clients.json` (0600) | The trusted-client allowlist ([ADR-0024](./adr/0024-multi-client-attested-pairing-and-broker.md)) |
| `revocation.json` (0600) | The revocation epoch, the enrollment latch, and the kill latch ([ADR-0025](./adr/0025-any-side-revocation-epoch.md), [ADR-0030](./adr/0030-global-kill-switch-and-audit.md)) |
| `audit.log` (0600) | The durable audit trail, size-capped |

The Secure Enclave enrollment key lives in the keychain under
`com.vivswan.chromium-bridge.enclave.signing.v1`, never on disk.

## 5. Key data flows

### 5.1 One complete tool-call round trip (`page_click(ref="e3")`)

```
1. MCP client -> MCP server (stdin NDJSON):
   {"jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"page_click","arguments":{"ref":"e3"}}}

2. dispatch checks: harness admitted, epoch fresh, kill switch clear
   -> session.call assigns BridgeReq.id=1, writes to the socket
   (a relay's call reaches the same dispatcher through the broker)

3. native host reads socket NDJSON -> NM frame -> stdout

4. extension SW receives {op:"page_click",args:{ref:"e3"}}
   -> resolve target tab
   -> ensureAllowed(tab.url)   // allowlist; prompts if not authorized
   -> inject content script if needed
   -> content: resolveTarget({ref:"e3"}) -> element
   -> high-risk? (submit/link) -> confirmation window (confirm.html);
      deny/timeout/close all reject
   -> click

5. The result returns along the same path, masked at the SW egress,
   and session pairs it back to the pending call by id.
```

### 5.2 Native host reconnect

```
Browser closes the Port -> host gets stdin EOF -> host exits
Extension onDisconnect -> scheduleReconnect(2s)
connectNative() -> browser re-spawns the host -> host reads the lock file
  -> connects to the socket -> kernel checks + HMAC + attach(label)
Broker accepts -> session re-attaches that label (generation-guarded:
  pending calls of the old connection drain as Disconnected)
```

### 5.3 A second MCP client attaches

```
Client B spawns its own chromium-bridge process
  -> it finds a live broker via the lock file
  -> attests itself over the socket (kernel checks + HMAC + attach frame
     carrying its harness's attested identity)
  -> broker checks the identity against clients.json; unmatched fails closed
  -> B's tool calls multiplex through the shared session
Broker exits when the last attached harness detaches.
```

## 6. Security model

The full treatment is in [docs/security/](./security/); this is the map.

| Boundary | Mechanism | ADR |
|------|------|-----|
| Harness admission (stdio) | Kernel-attested parent identity checked against the trusted-client allowlist; fail-closed once enrolled | [0024](./adr/0024-multi-client-attested-pairing-and-broker.md) |
| Bridge socket | 0600 Unix-domain socket in a 0700 dir; peer-UID check; mutual executable attestation; HMAC challenge-response; role-declaring attach | [0019](./adr/0019-authenticated-ipc.md), [0020](./adr/0020-kernel-attested-peer-identity.md), [0024](./adr/0024-multi-client-attested-pairing-and-broker.md) |
| Any-side revocation | Monotonic epoch in `revocation.json`, re-read at every enforcement point; both credential halves deleted on unpair | [0025](./adr/0025-any-side-revocation-epoch.md) |
| Enrollment (host <-> extension) | Secure Enclave key, presence-gated signing, extension-side pin, fingerprint comparison | [0021](./adr/0021-enrollment-ceremony.md) |
| Site allowlist | Per-origin approval + `chrome.permissions.request`; page cannot self-approve | [0004](./adr/0004-allowlist-with-optional-host-permissions.md) |
| High-risk confirmation | Extension-owned window off the page-reachable DOM; deny on timeout/close | [0027](./adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) |
| Crown-jewel confirmation | `page_eval` / `page_upload` approval is a Secure Enclave Touch ID signature on an enrolled Mac | [0031](./adr/0031-touch-id-confirmations-and-presence-grants.md) |
| Kill switch + audit | Fail-closed latch enforced at four layers; presence-gated release; log-after-decide trail | [0030](./adr/0030-global-kill-switch-and-audit.md) |
| Masking | Cookie/storage/eval/page-text egress masked in the SW, once for both page backends | [0010](./adr/0010-cookie-storage-readonly.md) |
| Protocol safety | NM 1 MB outbound limit; single-writer + flush; stderr panic hook; fuzzed parsers | (section 3.1) |

## 7. Key constraints (pitfalls hit and handled)

### 7.1 MV3 Service Worker 5-minute restart (Chromium #40733525)
Chrome force-restarts the SW about every 5 minutes, losing in-memory state;
the Port closes and the native host exits on stdin EOF. Mitigation: durable
state lives in `chrome.storage` (confined to trusted contexts) or in the MCP
server process; the SW reconnects on startup; ref markers are stamped onto
DOM attributes so the content script rebuilds its map after a restart;
pending calls are generation-guarded.

### 7.2 chrome.debugger forces an infobar
Any `chrome.debugger.attach` shows a "Started debugging this browser" banner
on every tab while attached. Mitigation: the default snapshot uses a content
script and never touches the debugger; `page_snapshot_precise` attaches,
reads the a11y tree, and detaches in one handler (detach on the finally
path), so the banner flashes for about a second. See
[ADR-0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) and
[ADR-0009](./adr/0009-page-snapshot-precise-debugger.md).

### 7.3 The Native Messaging manifest has no args field
The manifest's `path` must be a bare executable. Mitigation: a wrapper script
per browser (`run-host-<browser>.sh`) bakes in
`--native-host --label <browser>`; the label keys the broker's connection
registry (see [ADR-0022](./adr/0022-multi-browser-label-routing.md)).

### 7.4 chrome.permissions.request requires a user gesture
Host permissions can only be requested from a user-gesture context.
Mitigation: the allowlist authorization flow goes through the popup; Allow
requests the permission and records the entry together.

### 7.5 Static content_scripts conflict with optional permissions
With empty initial host permissions, manifest-declared content scripts never
inject. Mitigation: no manifest `content_scripts`; everything injects at
runtime via `chrome.scripting.executeScript`, following the granted optional
permissions.

### 7.6 Rust panics pollute stdout
Panic messages default to stdout, which corrupts NM frames and MCP NDJSON.
Mitigation: `panic = "abort"` in the release profile plus a stderr panic
hook, as a double safety net.

### 7.7 page_eval uses the Function constructor, not eval()
`page_eval` must run code in the page's global scope, but the content script
runs in a strict-mode closure where `eval` sees the wrong scope. Mitigation:
`new Function('"use strict"; return (async () => { <code> })()')()`, which
executes in the global scope and supports `return`/`await`. A reliable
execution timeout is impossible in single-threaded JS; the session layer's
120s timeout is the backstop. Results pass through safe serialization
(cycles/DOM/exotic types) and masking before leaving the extension. See
[ADR-0008](./adr/0008-page-eval-confirmation-channel.md).

### 7.8 chrome.debugger restrictions (page_snapshot_precise, CDP mode)
The `chrome.debugger` API is SW-only, cannot attach to `chrome://` or Web
Store pages, and allows one debugger per tab (DevTools counts). Mitigation:
CDP work happens in the SW; a URL-scheme check filters non-debuggable pages;
precise-snapshot refs use a `p` prefix to stay clear of content-script refs;
detach is on the finally path. See
[ADR-0009](./adr/0009-page-snapshot-precise-debugger.md) and
[ADR-0017](./adr/0017-cdp-mode-all-ops.md).

### 7.9 Cookies are host-bound; storage is same-origin; httpOnly is readable
`chrome.cookies` is bound by host permissions and lives in the SW (it can
read `httpOnly`, its core value); page `localStorage`/`sessionStorage` is
readable only from a content script on the same origin. Hence `cookie_get`
in the SW, `storage_get` in content, both read-only and always masked. See
[ADR-0010](./adr/0010-cookie-storage-readonly.md).

## 8. Technology choices

| Dimension | Choice | Rationale |
|------|------|------|
| Backend language | Rust, single binary + subcommands | Single-file distribution; the host manifest takes an absolute path; one codebase for server, host, and CLI. See [ADR-0001](./adr/0001-use-rust-single-binary.md) |
| IPC | Unix-domain socket + lock file (TCP fallback on Windows) | No listening port; kernel peer credentials enable attestation. See [ADR-0019](./adr/0019-authenticated-ipc.md) |
| Crypto and parsing | RustCrypto `hmac`/`sha2`, `subtle`, `serde` | Many-eyes libraries over homegrown code, even in the security core; bespoke code only where no library exists (see SECURITY.md and AGENTS.md) |
| Extension platform | MV3 on WXT, React UI, Vitest | Generated manifest with the pinned key; unified `browser.*`; testable SW. See [ADR-0027](./adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) |
| Desktop app | Tauri v2 (macOS) | Bundles the entitled host next to a webview UI; the UI carries no security weight. See [ADR-0026](./adr/0026-tauri-signing-and-entitlement-chain.md), [ADR-0029](./adr/0029-desktop-app-management-surface.md) |
| Contracts | The Rust core generates the TS side | One source of truth; CI fails on drift. See [ADR-0028](./adr/0028-contracts-dissolved-into-rust-core.md) and section 11 |
| Engineering gates | justfile + GitHub Actions, bun workspace, Biome, cargo-nextest, typos/machete, cargo-vet | One `just ci` compiles and gates the whole graph. See [ADR-0013](./adr/0013-ci-and-toolchain.md), revised by ADR-0023 |
| MCP version | 2025-06-18 | The current stable version MCP clients implement. See [ADR-0007](./adr/0007-mcp-protocol-version-2025-06-18.md) |

## 9. Known limitations

1. **Snapshot accuracy**: the content-script a11y tree is an approximation
   (shadow DOM, complex ARIA); `page_snapshot_precise` is the authoritative
   fallback.
2. **Cross-origin iframes**: the content script cannot read them.
3. **Windows bridge downgrade**: no Unix socket, no peer-UID check, no
   attestation; the HMAC secret is the only gate, and harness admission is
   unenforced. See [SECURITY.md](../SECURITY.md#platform-support).
4. **Same-user attacker running our own binary**: kernel attestation
   distinguishes binaries, not intentions; see the
   [threat model](./security/threat-model.md) residuals.
5. **Revocation latency to the extension**: the socket leg is immediate; the
   extension's reflection of a host-key revoke is bounded to the next
   service-worker wake ([ADR-0025](./adr/0025-any-side-revocation-epoch.md)).

## 10. Extension points

- **Adding a tool**: one catalogue entry + handler in the core, `just gen`,
  an op home in the extension, a risk-matrix row, and tests; the drift
  guards fail until every surface is covered. The step-by-step list is in
  [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-tool).
- **Adding a browser**: one row in the resolver (`browsers.rs`); doctor,
  --fix, uninstall, and the app pick it up from there.
- **Skill layer**: no architecture change; additive skill files that teach an
  agent to combine existing tools.

## 11. Protocol boundary contracts: error taxonomy and handshake

The cross-process contracts live in the Rust core, the single source of
truth ([ADR-0028](./adr/0028-contracts-dissolved-into-rust-core.md)); the
TypeScript side is generated from it, and runtime behavior is validated
against it. The canonical modules and their derived artifacts:

- **Tool catalogue** (`src/packages/core/src/tools/catalogue.rs`): each tool's
  name, English model-facing description, JSON-Schema `inputSchema`, and
  policy metadata (risk / scope / permission / confirmation). `just gen`
  runs the core's `emit_contract` example and `scripts/gen-ops.ts` to
  produce `src/packages/shared/src/ops.gen.ts`: op names, policy metadata, and
  a Zod arg validator per tool. The `BridgeCommand` request union is
  inferred from those validators, so the compile-time types and the runtime
  checks are the same artifact. CI regenerates and fails on any diff, so
  the checked-in TS cannot drift from the Rust source. UI labels are
  deliberately NOT part of the contract; they are extension UI copy
  (`tools.<op>` keys in `src/apps/extension/src/locales/*.yml`).
- **Error taxonomy** (`ERROR_SPECS` in `src/packages/core/src/error.rs`): the
  stable cross-process `code`s with `category`, `retryable`, and the
  user/model-facing `message`. `CallError::code()` maps the Rust tool-call
  errors into the table (`cargo test` enforces membership), and
  `src/packages/shared/src/errors.gen.ts` gives the extension the same codes.
- **Capabilities** (`src/packages/core/src/tools/capabilities.rs`): the
  negotiable groupings over the catalogue, emitted into
  `src/packages/shared/src/protocol.gen.ts`. `cargo test` enforces that every
  bridge-routed tool is covered by exactly one capability and each
  capability's permissions equal the union of its tools' permissions.
- **Protocol version** (`BRIDGE_PROTOCOL_VERSION` in
  `src/packages/core/src/protocol.rs`): the internal bridge protocol integer,
  also emitted into `protocol.gen.ts`.
- **Identity** (`src/packages/core/src/identity.rs`): the native-messaging host
  id and the pinned extension manifest key, emitted into
  `src/packages/shared/src/identity.gen.ts` (the extension imports
  `NATIVE_HOST_ID` for `connectNative`, `EXTENSION_MANIFEST_KEY` for the
  built manifest, and `PINNED_EXTENSION_ID`, derived from the key, for its
  startup self-check). `scripts/check-extension-id.ts` (`just
  check-extension-id`, part of `just ci`) verifies the generated TS, the
  built manifest, and the single-definition-site rule against the same
  values; the registration engine consumes the constants directly, so no
  installer copy exists to drift.
- **Wire envelopes and control frames** (`BridgeReq` / `BridgeResp`,
  `EnclaveControl`, and `AdminControl` - the latter embedding
  `allowlist::ClientEntry` - in `src/packages/core/src/protocol.rs`): the
  Rust types ARE the contract. The extension enforces hand-written Zod
  validators (`src/packages/shared/src/envelope.ts` for the envelopes,
  `enclave.ts` for the control frames), and the double-derivation gate
  (`scripts/check-envelope-parity.ts`, `just check-envelope`) holds the
  two structurally equivalent in CI: schemars derives a schema from the
  Rust types (behind the gen-only `envelope-schema` feature, never in a
  shipped binary), `z.toJSONSchema` derives one from the Zod side, and
  both are normalized through the documented rules in
  `src/packages/shared/src/json-schema-normalize.ts` before an exact diff.
  Control frames are diffed per `type` tag against a coverage plan in the
  script: every host->extension frame is held to its Zod validator (or
  pinned as a bare classification tag), extension->host frames are named
  as enforced by the Rust serde parser itself, and an added or renamed
  variant fails until the plan says how it is covered. The parsers
  deliberately differ in a few places (Option null-arms, JS-safe integer
  bounds, the id's forward-compat string arm, the control frames'
  strict-host/loose-extension split); each such asymmetry is erased only
  when it exactly matches the approved form recorded there, so any drift
  beyond the recorded decisions fails CI. No generated schema is checked
  in anywhere.

### 11.1 Error taxonomy (ERROR_SPECS)

At the tool-call boundary, Rust's typed error `CallError` maps to the stable
`code`s in `ERROR_SPECS` (`src/packages/core/src/error.rs`); `cargo test`
validates the mapping, and the extension normalizes its own failures to the
same set (generated into `errors.gen.ts`). The `code` is for programmatic
decisions (it carries `category` and `retryable`); what the model and the
user see is the `message`. This way the connection-layer failures
(`NOT_CONNECTED` / `EXTENSION_NOT_READY` / `CONNECTION_LOST`), the
admission and revocation refusals, and `BRIDGE_KILLED` have one shared
meaning across every process instead of each telling its own story.

### 11.2 Capability / version handshake

Beyond the authentication of section 3.3, connection setup carries a
capability and version dimension: the extension side advertises its
supported `BRIDGE_PROTOCOL_VERSION` and available capability set (see
`src/packages/core/src/tools/capabilities.rs`). An incompatible version
fails fast with `PROTOCOL_MISMATCH` rather than blowing up later on an
unknown op, and a tool whose capability is not advertised is rejected up
front. The wiring status of this negotiation is tracked honestly in
[compatibility.md](./compatibility.md).

Note the three distinct "versions": the MCP JSON-RPC version `2025-06-18`
(section 3.2), the internal bridge protocol version (an integer), and the
release version (Cargo-sourced). They are all different.

> To troubleshoot these links at runtime (whether the connection is
> reachable; whether the lock file, socket, and manifests are in place), use
> the read-only `chromium-bridge doctor`; see [cli.md](./cli.md).
