# Trust boundaries

The system spans three processes and four protocol hops. Each hop is a trust
boundary — data crossing it is validated and/or authenticated. Pairs with the
[threat model](threat-model.md).

```
MCP client ──①──▶ Rust MCP server ──②──▶ native host ──③──▶ extension ──④──▶ web page
   (trusted)         (trusted)           (trusted)         (trusted)        (UNTRUSTED)
```

## ① MCP client ↔ Rust MCP server  (stdio, JSON-RPC 2.0)

- **Direction of trust**: the client is trusted (user-configured). This boundary
  is about *protocol correctness*, not authz.
- **Enforcement**: strict JSON-RPC parsing; unknown methods → `-32601`; parse
  errors surfaced, not fatal; **stdout carries only protocol** (diagnostics go
  to stderr, or a stray write corrupts the stream).

## ② Rust MCP server ↔ native host  (bridge socket, NDJSON)

- **Direction of trust**: this is the one boundary defended against *local*
  peers — any process that could try to reach the bridge.
- **Enforcement** (see [ADR-0019](../adr/0019-authenticated-ipc.md) and
  [ADR-0020](../adr/0020-kernel-attested-peer-identity.md)):
  - **No listening port** (Unix): the bridge is a **0600 Unix-domain socket**
    inside a 0700 per-user directory, so there is no localhost port for another
    process to connect to, and the filesystem mode keeps other users out.
    Windows, lacking std Unix sockets, keeps a loopback TCP socket.
  - **Peer-UID check** (Unix): on `accept`, the server reads the connecting
    peer's UID from the kernel (`getpeereid` / `SO_PEERCRED`) and drops any
    connection not from its own UID, before authentication.
  - **Kernel-attested executable identity** (Linux/macOS): still before
    authentication, each end takes a kernel-attested identity for the peer and
    requires it to match its own running image. On Linux it resolves the peer PID
    (`SO_PEERCRED`) and hashes `/proc/<pid>/exe` (bound to the running inode,
    subject to a narrow pid-reuse race on resolution). On macOS it identifies the
    peer by its kernel **audit token** (`LOCAL_PEERTOKEN`), validates the running
    code with `SecCodeCheckValidity`, and compares its `cdhash` -- bound to the
    running image, closing both the path re-open TOCTOU and the pid-reuse race.
    (Only if the kernel reports the audit-token option unsupported --
    `ENOPROTOOPT`, older systems -- does it fall back to a pid-identified
    `SecCode`, where the narrow pid-reuse race remains; any other error fails
    closed.) A different same-user program is rejected here. Attestation is **mutual**: the
    server attests the host after `accept`, the host attests the server after
    `connect`.
  - **HMAC challenge-response**: the server sends a fresh random nonce; the host
    replies with `HMAC-SHA256(secret, nonce)`, verified in constant time. The
    per-run secret (0600 lock file) never travels on the wire, and the
    per-connection nonce defeats replay.
  - Each connection is size-checked NDJSON; the newest authenticated connection
    replaces the previous writer.
  - **Windows downgrade**: Windows has no std Unix-domain socket, so the bridge
    is a loopback TCP socket, and neither the peer-UID check nor the attestation
    is compiled in (both are Unix only). Any local process can open the loopback
    port; the only barrier is the HMAC secret. The lock file holding that secret
    gets no explicit mode on Windows and relies on the default per-user
    permissions of `LOCALAPPDATA`. So on Windows the guarantee is weaker: it
    rests on the secret staying confidential, not on kernel-attested peer
    identity.
  - **Residual risk**: neither a hash nor a code signature can distinguish the
    legitimate browser-spawned host from the same binary re-run by a same-user
    attacker: the bytes, and the cdhash, are identical. Closing that requires
    browser/extension-side pairing (trust-on-first-use in the extension
    settings). On macOS, trust is pinned to one exact cdhash; Team-ID /
    designated-requirement pinning (to also accept a separate trusted build) is a
    deferred follow-up, not a gap in the same-binary bridge. See ADR-0020.

## ③ Chrome ↔ native host  (Native Messaging framing)

- **Direction of trust**: Chrome spawns the host per the host manifest, whose
  `allowed_origins` **pins the extension ID** — only our extension can talk to
  it.
- **Enforcement**: 4-byte LE length prefix + JSON; 64 MB inbound clamp, 1 MB
  outbound cap; single-writer + flush-per-frame on stdout; `panic = "abort"` +
  stderr panic hook so a panic can't corrupt the frame stream. Shutdown on stdin
  EOF.
- **Residual (host-to-extension is unauthenticated)**: `allowed_origins` pins
  which extension may open the host, but nothing pins which host the extension
  will accept. The manifest lives in a user-writable directory, so a same-user
  attacker can repoint its `path` at a malicious host binary. The browser
  launches that binary and it speaks native messaging straight to the extension,
  bypassing the authenticated socket at boundary ②. Closing this needs
  trust-on-first-use host-identity pairing in the extension. See the
  [threat model](threat-model.md).

## ④ Extension ↔ web page  (Chrome API / content script / DOM)

- **Direction of trust**: **the page is untrusted.** This is the security-
  critical boundary.
- **Enforcement**:
  - **Allowlist**: page-level ops only run on origins the user approved; a new
    origin prompts the user and requests the host permission. The page cannot
    self-approve.
  - **Confirmation**: submit/link clicks, `page_eval`, and tab close inject an
    in-page toast the page cannot forge or auto-dismiss (30s auto-deny). Only
    these high-risk ops confirm; low-risk ops (navigate, `page_text`,
    `tab_list`, masked cookie or storage reads) run with no per-action prompt.
  - **Masking**: page text, cookies, storage, and eval output are masked before
    crossing back toward the model.
  - **Isolation**: content scripts run in the isolated world; `page_eval` uses a
    `Function` constructor (not the content script's scope) and its result is
    serialized safely (cycles/DOM/exotic types) before masking.
  - **Read-only credentials**: no cookie/storage writes.

## Invariants that must not regress

- stdout on either binary mode = protocol bytes only.
- On Unix, the bridge never serves a connection that failed the peer-UID check,
  the executable-identity attestation, or the HMAC handshake. On Windows only
  the HMAC handshake gates a connection: there is no peer-UID check and no
  attestation, so the guarantee reduces to knowledge of the per-run secret.
- The host manifest's `allowed_origins` always pins exactly our extension ID.
  (This pins extension-to-host only; the host-to-extension hop is not yet
  authenticated. See boundary ③.)
- No page-level tool runs on a non-allowlisted origin (absent `allowAllSites`).
- No tool writes cookies or web storage.

Changing any of these is a **security-relevant change** (see
[SECURITY.md](../../SECURITY.md)).
