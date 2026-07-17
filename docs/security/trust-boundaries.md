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
- **Enforcement** (see [ADR-0019](../adr/0019-authenticated-ipc.md)):
  - **No listening port** (Unix): the bridge is a **0600 Unix-domain socket**
    inside a 0700 per-user directory, so there is no localhost port for another
    process to connect to, and the filesystem mode keeps other users out.
    Windows, lacking std Unix sockets, keeps a loopback TCP socket.
  - **Peer-UID check**: on `accept`, the server reads the connecting peer's UID
    from the kernel (`getpeereid` / `SO_PEERCRED`) and drops any connection not
    from its own UID, before authentication.
  - **HMAC challenge-response**: the server sends a fresh random nonce; the host
    replies with `HMAC-SHA256(secret, nonce)`, verified in constant time. The
    per-run secret (0600 lock file) never travels on the wire, and the
    per-connection nonce defeats replay.
  - Each connection is size-checked NDJSON; the newest authenticated connection
    replaces the previous writer.

## ③ Chrome ↔ native host  (Native Messaging framing)

- **Direction of trust**: Chrome spawns the host per the host manifest, whose
  `allowed_origins` **pins the extension ID** — only our extension can talk to
  it.
- **Enforcement**: 4-byte LE length prefix + JSON; 64 MB inbound clamp, 1 MB
  outbound cap; single-writer + flush-per-frame on stdout; `panic = "abort"` +
  stderr panic hook so a panic can't corrupt the frame stream. Shutdown on stdin
  EOF.

## ④ Extension ↔ web page  (Chrome API / content script / DOM)

- **Direction of trust**: **the page is untrusted.** This is the security-
  critical boundary.
- **Enforcement**:
  - **Allowlist**: page-level ops only run on origins the user approved; a new
    origin prompts the user and requests the host permission. The page cannot
    self-approve.
  - **Confirmation**: submit/link clicks, `page_eval`, and tab close inject an
    in-page toast the page cannot forge or auto-dismiss (30s auto-deny).
  - **Masking**: page text, cookies, storage, and eval output are masked before
    crossing back toward the model.
  - **Isolation**: content scripts run in the isolated world; `page_eval` uses a
    `Function` constructor (not the content script's scope) and its result is
    serialized safely (cycles/DOM/exotic types) before masking.
  - **Read-only credentials**: no cookie/storage writes.

## Invariants that must not regress

- stdout on either binary mode = protocol bytes only.
- The bridge never serves a connection that failed the peer-UID check or the
  HMAC handshake.
- The host manifest's `allowed_origins` always pins exactly our extension ID.
- No page-level tool runs on a non-allowlisted origin (absent `allowAllSites`).
- No tool writes cookies or web storage.

Changing any of these is a **security-relevant change** (see
[SECURITY.md](../../SECURITY.md)).
