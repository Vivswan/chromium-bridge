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
[modelcontextprotocol.io](https://modelcontextprotocol.io/specification/2026-07-28).

- Transport: stdin/stdout, NDJSON (one message per line, LF-terminated)
- Protocol version `2026-07-28`, the stateless revision; see
  [ADR-0034](./adr/0034-mcp-2026-07-28-stateless.md)
- The layer is built on the official Rust SDK
  ([rmcp](https://github.com/modelcontextprotocol/rust-sdk); ADR-0034
  records the trust-surface decision), with a small shared tokio runtime
  confined to the MCP serve path. Our invariants wrap the SDK:
  harness attestation and admission pass before serving begins, the kill
  switch and audit trail run on every tool call, diagnostics stay on stderr
  (stdout is protocol), and the broker/relay legs are unchanged
- No handshake and no session state: a modern request carries the version
  and the client capabilities in `params._meta`
  (`io.modelcontextprotocol/protocolVersion` and
  `.../clientCapabilities`; rmcp requires both, an empty capabilities
  object suffices) and is gated per request: an unsupported version
  string gets JSON-RPC error `-32022` (`UnsupportedProtocolVersionError`)
  with `data.supported` (the full rmcp set) and `data.requested`;
  incomplete or malformed metadata gets `-32602` naming the field(s). A
  connection's FIRST request must be a legacy `initialize` or a
  well-formed stateless request - anything else drops the connection
  without a reply, fail closed (a bare `ping` is answered without opening
  the connection). See ADR-0034 for the measured actuals
- `server/discover` replaces the handshake. Its result declares
  `supportedVersions` (rmcp's full supported set, newest pinned to
  `2026-07-28` by a unit test) and `capabilities: {"tools": {}}`;
  cacheable results (`server/discover`, `tools/list`) carry
  `ttlMs: 3600000` / `cacheScope: "private"` for peers >= 2026-07-28 (the
  catalogue is static per binary, so one hour bounds staleness across
  upgrades; "private" is the conservative scope - a local single-user
  server has no shared caches to feed). There is no bare-probe form: a
  `server/discover` without its `_meta` is refused (or, as an opener,
  dropped) - ADR-0034 cut the planned leniency to match the SDK
- Results carry `resultType`; the serverInfo `_meta` rides only the
  `server/discover` result; tool errors still use `isError: true` inside
  the result, not a JSON-RPC error, so the model sees the error text and can
  react
- Handled methods: `server/discover`, `tools/list`, `tools/call`, plus
  `ping` for legacy peers (answered `{}` pre-open and in initialize-opened
  sessions; refused after a stateless opener); unknown
  methods return `-32601` (`initialize` is served in every era as the
  legacy negotiation - rmcp echoes a supported requested revision and
  answers an unknown one with the newest)
- **Temporary legacy era**: on a connection opened with `initialize`, a
  request with no `_meta` version key is served the previous
  revision's behavior (`initialize` /
  `notifications/initialized` / `ping` and legacy-shaped tool results,
  ADR-0007) through rmcp's built-in earlier-revision support while Claude
  Code's 2026-07-28 support rolls out. Once the
  harness interop smoke shows our harnesses opening with `server/discover`,
  legacy support is disabled and a missing version key fails closed.
  See [ADR-0034](./adr/0034-mcp-2026-07-28-stateless.md)
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
| `policy.json` (0600) | The host-owned policy: the signed baseline and the unsigned restriction overlay ([ADR-0032](./adr/0032-host-owned-policy-settings.md), section 11.3) |
| `policy-history.json` (0600) | Superseded policy revisions, a bounded ring; data for rollback, never authority |
| `pending-import.json` (0600) | The one-shot legacy-settings import: pending bag or consumed tombstone (section 11.3) |
| `lang.json` (0600) | The shared `uiLanguage` preference and its echo-suppression sequence |
| `audit.log` (0600) | The durable audit trail, size-capped |

The Secure Enclave enrollment key lives in the keychain under
`com.vivswan.chromium-bridge.enclave.signing.v1`, never on disk.

## 5. Key data flows

### 5.1 One complete tool-call round trip (`page_click(ref="e3")`)

```
1. MCP client -> MCP server (stdin NDJSON):
   {"jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"page_click","arguments":{"ref":"e3"},
     "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
      "io.modelcontextprotocol/clientCapabilities":{}}}}

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
| Engineering gates | moon + proto + GitHub Actions, bun workspace, Biome, cargo-nextest, typos/machete, cargo-deny/audit + dependency review | One `moon run ci` runs the local cross-platform gate; CI layers additional jobs on top (the repo's jobs live in `.github/workflows/checks.yml`, called inside the managed ci.yml's all-green gate). See [ADR-0013](./adr/0013-ci-and-toolchain.md), revised by ADR-0023 and the moon adoption; supply chain per [ADR-0035](./adr/0035-automated-supply-chain-review.md) |
| MCP version | 2026-07-28 (stateless) | The current spec revision, served on the official rmcp SDK: per-request version gate, `server/discover`; rmcp's built-in legacy-era support serves older harnesses during the rollout. See [ADR-0034](./adr/0034-mcp-2026-07-28-stateless.md) |

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

- **Adding a tool**: one catalogue entry + handler in the core, `moon run gen`,
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
  policy metadata (risk / scope / permission / confirmation). `moon run gen`
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
  errors into a subset of the table (`cargo test` enforces membership), and
  `src/packages/shared/src/errors.gen.ts` gives TS consumers the same code
  constants (currently unconsumed; see section 11.1).
- **Capabilities** (`src/packages/core/src/tools/capabilities.rs`): the
  negotiable groupings over the catalogue, emitted into
  `src/packages/shared/src/protocol.gen.ts`. `cargo test` enforces that every
  bridge-routed tool is covered by exactly one capability and each
  capability's permissions equal the union of its tools' permissions.
- **Protocol versions** (`src/packages/core/src/protocol.rs`): the internal
  bridge protocol integer (`BRIDGE_PROTOCOL_VERSION`) and the MCP JSON-RPC
  revision the server speaks (`MCP_PROTOCOL_VERSION`, gated per request,
  declared by `server/discover`, and asserted by the protocol e2e suites),
  both emitted into `protocol.gen.ts`.
- **Audit forwarding whitelist** (`EXTENSION_AUDIT_KINDS` in
  `src/packages/core/src/audit.rs`): the extension-owned audit kinds the
  host accepts over the `audit_event` control frame (`extension_kind`
  derives from the same list), emitted into
  `src/packages/shared/src/audit.gen.ts`. The extension's forwarding set
  and the forwarded prefix of its audit-ring vocabulary build on the
  generated constant, so the two sides of the forwarding boundary cannot
  drift apart.
- **Identity** (`src/packages/core/src/identity.rs`): the native-messaging host
  id and the pinned extension manifest key, emitted into
  `src/packages/shared/src/identity.gen.ts` (the extension imports
  `NATIVE_HOST_ID` for `connectNative`, `EXTENSION_MANIFEST_KEY` for the
  built manifest, and `PINNED_EXTENSION_ID`, derived from the key, for its
  startup self-check). `scripts/check-extension-id.ts` (`moon run
  check-extension-id`, part of `moon run ci`) verifies the generated TS, the
  built manifest, and the single-definition-site rule against the same
  values; the registration engine consumes the constants directly, so no
  installer copy exists to drift.
- **Enclave signing contract** (`src/packages/core/src/enclave/`:
  `challenge.rs` for the domain strings and field bounds, `pubkey.rs`/`der.rs`
  for the key and signature byte lengths, `mod.rs` for the `enclave_error`
  reason codes): emitted by the core's `emit_enclave_contract` example into
  `src/packages/shared/src/enclave.gen.ts` (constants plus the
  `EnclaveReasonCode` union the extension's enrollment state machine
  classifies exhaustively) and `enclave-fixture.gen.ts` (golden vectors:
  Rust-built message bytes with deterministic software-P256 proofs, replayed
  through the extension's WebCrypto verifier by
  `tests/background/enclave-golden.test.ts`, so the signed-message encoding
  itself is pinned across languages). The fixture's signing key is public
  test data and deny-listed as an enrollment identity on both sides
  (`ensure_not_fixture_key` in the core, `ENCLAVE_FIXTURE_KEY_ID` in the
  extension's pairing verifier and stored-pin validators).
- **Policy document and directions** (`src/packages/core/src/policy/`,
  ADR-0032): the host-owned `PolicyDoc` - the fifteen policy fields (the
  four capability grants, the confirmation policy, `disabledTools`, the
  confirmation timeouts), their deny defaults, the per-field
  permissive-direction table, and the `relaxes`/`restricts` comparisons -
  plus the signed store and the `set_signed`/`restrict` write seams.
  `moon run gen` emits `src/packages/shared/src/policy.gen.ts`: the signing
  domain constant, the field list with its directions, the defaults, and
  strict Zod validators for the document, the values, and the restriction
  overlay. The extension recomputes every direction comparison from the
  emitted table itself; it never trusts a host's claim about which way a
  change points. On an enrolled Mac, grants are signed by the enrollment
  key over
  `UTF8("chromium-bridge-policy-v1") || 0x00 || doc_bytes` - a third,
  NUL-separated signing domain, injective against the enclave challenge and
  presence domains, so no artifact of one ceremony replays as another (on a
  genuinely unenrolled Mac the desktop app's interactive floor stores the
  baseline unsigned; what that is worth at the extension is section 11.3's
  unpinned lane, never a pinned one).
  There is no canonicalization step anywhere: the host signs and stores the
  exact document bytes, and the extension verifies the exact bytes it
  received against its pinned key before strict-parsing those same bytes.
  Section 11.3 covers the frames that carry all of this.
- **Wire envelopes and control frames** (`BridgeReq` / `BridgeResp`,
  `EnclaveControl`, `AdminControl` - the latter embedding
  `allowlist::ClientEntry` - and `PolicyControl` in
  `src/packages/core/src/protocol.rs`): the
  Rust types ARE the contract, and the extension's validators are built
  from it in two layers. The base layer is generated: `moon run gen` runs the
  core's `emit_envelope_schema` example (schemars behind the gen-only
  `envelope-schema` feature, never in a shipped binary) and
  `scripts/gen-envelope.ts` (whose Zod emitter is in-repo - the schema
  subset the rules below admit needs no external converter) to produce
  `src/packages/shared/src/envelope-wire.gen.ts`: one faithful strict Zod
  schema per envelope and per host->extension control frame - unknown
  fields rejected, required fields required, no invented defaults, and
  generation aborts rather than emit anything weaker (rules G1-G5 in the
  script). CI regenerates and fails on a stale diff (`moon run check-gen`).
  The enforced validators (`envelope.ts` for the envelopes, `enclave.ts`
  for the control frames) wrap those bases with the deliberate parser
  asymmetries (Option null-arms, JS-safe integer bounds, the id's
  forward-compat string arm, the control frames' strict-host /
  loose-extension split), each named in a comment at the override site.
  The asymmetry gate (`scripts/check-envelope-parity.ts`, `moon run
  check-envelope`) pins that hand-written layer: schemars derives a schema
  from the Rust types, `z.toJSONSchema` derives one from the wrapped
  validators, both are normalized through the documented rules in
  `src/packages/shared/src/json-schema-normalize.ts` - each asymmetry is
  erased only when it exactly matches the approved form recorded there -
  and any remaining diff fails CI. With the base generated, a surviving
  diff means the wrapper drifted outside the approved list; the check is
  not tautological because the wrapper is hand-written. Control frames
  are covered per `type` tag by a plan in the script: every
  host->extension frame is held to its wrapped validator (or pinned as a
  bare classification tag), extension->host frames are named as enforced
  by the Rust serde parser itself, the `{ zod }` plans are cross-checked
  against the generated frame list, and an added or renamed variant fails
  until the plan says how it is covered. The extension->host frames also
  get generated WRITER schemas (types the constructor sites `satisfies`,
  so a drifted field or typo'd tag is a compile error; no runtime
  validation rides on the outbound path), cross-checked against the
  "rust-parsed" plans the same way. Each asymmetry and the
  fail-closed behavior of the generated bases (unknown fields, missing
  required fields, type confusion, nested extras) are also exercised
  behaviorally in `src/packages/shared/tests/envelope-wire.gen.test.ts`.
  One named limit: the schema-derived parity gate cannot see
  refinement-level runtime semantics (a `z.preprocess`/`z.coerce` slipped
  into a validator is invisible to it - the behavioral test file exists to
  catch exactly that class).
- **Desktop command DTOs** (`src/apps/desktop/src/`): the payload structs
  the app's Tauri commands return, exported to the webview as
  `src/apps/desktop/ui/src/lib/commands.gen.ts` by ts-rs (`#[derive(TS)]`
  behind the gen-only `ts-export` feature). ts-rs writes bindings by
  executing generated code, so the export runs as a cargo test; `moon run gen`
  runs it (the `gen-app-types` recipe), and CI's macOS desktop job
  regenerates and fails on a stale diff. Unlike the boundaries above, this
  seam is same-author IPC inside one signed app, so it gets static types
  only - no runtime validators - and `ui/src/lib/tauri.ts` wraps the
  generated types in the typed `api` facade. ts-rs never enters a shipped
  binary's dependency graph, and schemars may reach the host binary only
  through rmcp - never through our own gen-only feature
  (`moon run check-gen-isolation` pins both; ADR-0034).

### 11.1 Error taxonomy (ERROR_SPECS)

At the tool-call boundary, Rust's typed error `CallError` maps to the stable
`code`s in `ERROR_SPECS` (`src/packages/core/src/error.rs`); `cargo test`
validates the mapping. Today the Rust server is the only assigner, and it
covers a subset of the table: the extension reports its failures as
free-form strings, which the host surfaces as `EXECUTION_FAILED`.
`TOOL_DISABLED` is assigned by the host-side policy gate (ADR-0032
decision 4, section 11.3): dispatch refuses a tool whose capability grant
is off or that the effective policy disables, before any bridge traffic.
Of the
unassigned codes, `PROTOCOL_MISMATCH` awaits the version/capability
handshake wiring (see [compatibility.md](./compatibility.md)); the others
(`SITE_NOT_ALLOWED`, `USER_DENIED`, `TAB_NOT_FOUND`, ...) would need
structured error reporting from the extension in place of those free-form
strings. The TS constants generated
into `errors.gen.ts` exist for future consumers. The `code` is for
programmatic decisions (it carries `category` and `retryable`); what the
model and the user see is the `message`. Defining every code in one table
gives the connection-layer failures
(`NOT_CONNECTED` / `EXTENSION_NOT_READY` / `CONNECTION_LOST`), the
admission and revocation refusals, and `BRIDGE_KILLED` one shared
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

Note the three distinct "versions": the MCP JSON-RPC version `2026-07-28`
(section 3.2), the internal bridge protocol version (an integer), and the
release version (Cargo-sourced). They are all different.

### 11.3 Host-owned policy and language sync (ADR-0032)

Since [ADR-0032](./adr/0032-host-owned-policy-settings.md) the host owns the
security policy: the four capability grants, the confirmation policy,
`disabledTools`, and the confirmation timeouts. The host persists at most
one signed baseline plus an unsigned restriction overlay in
`runtime_dir()/policy.json`, and the state travels over six additive
host-handled control frames (`PolicyControl` in `protocol.rs`), classified
and terminated exactly like the enclave and admin frames: answered by the
host, never forwarded to the MCP server, and dropped when the server leg
tries to inject one.

- `policy_get {}` (extension -> host): on-demand refresh. Like every
  extension-originated frame in this family, it is sent only on a
  connection where the host has already pushed a frame on the same lane
  (`policy_current` for the policy frames, `lang_current` for the language
  ones - the
  never-speak-first rule: an old host would classify an unknown frame as
  forwardable and the MCP server's strict parse would tear the browser leg
  down, so against an old host the new frames simply never flow).
- `policy_current { ok, baseline?, sig?, overlay?, reason?, error? }`
  (host -> extension): the policy state, pushed unsolicited at every
  connect and on every observed store change, and the reply to
  `policy_get`. The frame is ok-split, and the host builds it only through
  a typed intermediate so the mixtures the extension must never see cannot
  be constructed: `ok: true` carries the exact signed baseline bytes
  (base64, so the signed artifact survives the JSON hop byte-for-byte),
  the optional signature, and the optional overlay; `ok: false` carries
  `error` plus an optional structured `reason`
  (`absent` / `damaged` / `unreadable`) and never a baseline, so the
  extension fails closed rather than trusting bytes nobody vouched for.
  `absent` (no baseline yet, the pre-cutover state) is the only reason that
  can trigger the one-shot legacy import below; `damaged` and `unreadable`
  are fail-closed states.
- `legacy_settings { bag }` (extension -> host): the snapshotted legacy
  settings bag, sent at most once ever, and only to a pinned host that has
  proven key possession on the same connection through a fresh-nonce
  challenge (ADR-0032 decision 8 as amended). The host records it as a
  pending import, never applies it.
- `lang_get {}` / `lang_set { value }` (extension -> host) and
  `lang_current { value, seq }` (host -> extension): the shared
  `uiLanguage` preference (`runtime_dir()/lang.json`), deliberately outside
  the signed policy document - not signed, not ratcheted, unable to affect
  any security decision - with echo suppression by sequence number.

The enforcement contract is asymmetric by design (ADR-0032 decision 3):
policy that grants capability must carry proof no same-user process can
forge - on an enrolled Mac, a Secure Enclave signature by the enrollment
key, whose user-presence ACL makes the Touch ID tap and the signature one
act - while policy that only removes capability travels free as the
unsigned overlay. A genuinely unenrolled Mac has exactly one grant
surface, the desktop app's interactive floor, which stores the baseline
unsigned: a pinned extension refuses it, and an unpinned one accepts it
only through the approval window below.
The extension verifies the signature against its own pinned key (never a
frame-supplied identity), strict-parses the verified bytes, direction-checks
the overlay locally, and keeps a value ratchet in trusted storage: a pinned
extension never applies a relaxation without a fresh signature whose signed
`touched` set names the relaxed field. Post-cutover a per-connection
dispatch barrier refuses bridge ops until the connection's first policy
push has verified and applied, so an op cannot race ahead of a tightening.
On the wire-validation side the six frames ride the same two-layer
machinery as every other control frame (section 11 above): generated strict
bases in `envelope-wire.gen.ts`, wrapped by hand-written enforced
validators next to the enclave ones - the `policy_current` ok-split
refinement is one of the individually pinned asymmetries the
`moon run check-envelope` gate holds to its approved list.

The pending legacy import (`runtime_dir()/pending-import.json`) has a
deliberately narrow lifecycle: record-once (only an absent store accepts a
bag; the first bag wins and later receipts are dropped, so a
later-compromised extension cannot replace the user's real legacy bag),
read-only inspection (`chromium-bridge policy pending-import`, `doctor`,
and the app's first-run screen), then consumption into a durable tombstone
when the first baseline lands. Recording a bag bumps the policy epoch, so
a running desktop app learns of a mid-session arrival rather than only
discovering it at first run. The tombstone write happens in the
same critical section as - and durably before - the revision 1 baseline
write, so a baseline can never land with the import window still
open, and the tombstone survives key disposal, closing the
forged-bag-replant path from the host side. What the tombstone cannot
defend against is a hostile same-user native process deleting the file;
that residual is recorded in the
[threat model](./security/threat-model.md#host-owned-policy-adr-0032-residual-ledger).

The host also enforces its own policy at dispatch (`policy/gating.rs`):
a tool whose capability grant is off or that is in `disabledTools` is
refused with the stable `TOOL_DISABLED` code before any bridge traffic,
with an absent store allowing (pre-cutover) and an unreadable one denying
all. That check is defense in depth for the honest-host path; the
extension's gate stays authoritative at its boundary precisely because the
host may not be ours.

> To troubleshoot these links at runtime (whether the connection is
> reachable; whether the lock file, socket, and manifests are in place), use
> the read-only `chromium-bridge doctor`; see [cli.md](./cli.md).
