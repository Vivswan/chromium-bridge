//! Wire protocols for chromium-bridge.
//!
//! Three protocols live here:
//! 1. Chrome Native Messaging framing (4-byte LE length prefix + UTF-8 JSON)
//!    — used between the native-host subprocess and the Chrome extension.
//! 2. MCP JSON-RPC 2.0 messages (NDJSON over stdio) — used between the MCP
//!    server and the MCP client.
//! 3. The internal "bridge" envelope — request/response exchanged between the
//!    MCP server and the native-host subprocess over the bridge socket
//!    (newline-delimited JSON).

use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ----------------------------------------------------------------------------
// 1. Chrome Native Messaging framing
// ----------------------------------------------------------------------------

/// Hard cap on a single native-messaging message sent *to* Chrome. Chrome
/// closes the port if a message exceeds 1 MB. (Inbound from Chrome the limit
/// is 64 MB, which we don't need to enforce.)
pub const NM_MAX_OUTGOING: usize = 1024 * 1024;

/// Read one native-messaging frame from `r`: a 4-byte LE length prefix
/// followed by that many bytes of UTF-8 JSON. Returns `Ok(None)` on EOF
/// (Chrome's canonical shutdown signal).
pub fn nm_read_frame<R: Read>(r: &mut R) -> io::Result<Option<Value>> {
    let mut header = [0u8; 4];
    match r.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(header) as usize;
    // Defensive bound: a corrupted prefix yielding a huge value would OOM us.
    // Inbound limit is 64 MB per the spec; clamp well above any legitimate use.
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native-messaging frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let value = serde_json::from_slice(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("nm json decode: {e}")))?;
    Ok(Some(value))
}

/// Write one native-messaging frame to `w`: 4-byte LE length prefix + JSON.
/// Aborts (panic→abort via Cargo profile) if the payload exceeds 1 MB; caller
/// should check size before serializing large data. Flushes after writing.
pub fn nm_write_frame<W: Write>(w: &mut W, value: &Value) -> io::Result<()> {
    let json = serde_json::to_vec(value)?;
    if json.len() > NM_MAX_OUTGOING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "native-messaging outgoing frame {} bytes exceeds 1 MB cap",
                json.len()
            ),
        ));
    }
    let len = (json.len() as u32).to_le_bytes();
    w.write_all(&len)?;
    w.write_all(&json)?;
    w.flush()?;
    Ok(())
}

// ----------------------------------------------------------------------------
// 2. MCP JSON-RPC 2.0 (over stdio, NDJSON)
// ----------------------------------------------------------------------------

/// A parsed inbound JSON-RPC message. Distinguishes request (has `id`),
/// notification (no `id`), and their shapes.
///
/// Deliberately NOT `deny_unknown_fields`, unlike every other wire type here:
/// this is the one frame whose peer is a third-party MCP client we do not
/// ship, and JSON-RPC/MCP implementations add top-level members as the spec
/// evolves. Rejecting those would break the bridge's primary function against
/// conforming clients; nothing security-relevant is decided from this frame's
/// shape (authorization happens at the attested stdio/socket boundaries).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpc {
    pub jsonrpc: Option<String>,
    /// `id` is present for requests/responses, absent for notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    // For responses only:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpc {
    #[allow(dead_code)]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Build a successful response echoing the request id.
    pub fn ok(id: Value, result: Value) -> Self {
        JsonRpc {
            jsonrpc: Some("2.0".into()),
            id: Some(id),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response echoing the request id.
    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        JsonRpc {
            jsonrpc: Some("2.0".into()),
            id: Some(id),
            method: None,
            params: None,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Build a notification (no id, no response expected).
    #[allow(dead_code)]
    pub fn notification(method: impl Into<String>, params: Value) -> Self {
        JsonRpc {
            jsonrpc: Some("2.0".into()),
            id: None,
            method: Some(method.into()),
            params: Some(params),
            result: None,
            error: None,
        }
    }
}

/// Hard cap on a single inbound MCP NDJSON line, the same 64 MB order of
/// magnitude [`nm_read_frame`] and [`bridge_read`] clamp to (counting the whole
/// line, trailing newline included). The MCP client is trusted, but the most
/// likely real attack on this system is prompt-injection hijacking that client
/// (a web page telling the model to misbehave), so the client stdio leg must
/// not be able to exhaust memory with one newline-less line either.
pub const MCP_MAX_LINE: usize = 64 * 1024 * 1024;

/// Read one NDJSON line from `r` and parse it as JSON-RPC. Returns `Ok(None)`
/// on EOF (client gone → shut down). The line is bounded to [`MCP_MAX_LINE`];
/// an overrun fails closed with `InvalidData` rather than buffering unbounded.
pub fn mcp_read<R: io::BufRead>(r: &mut R) -> io::Result<Option<JsonRpc>> {
    mcp_read_capped(r, MCP_MAX_LINE)
}

fn mcp_read_capped<R: io::BufRead>(r: &mut R, max_line: usize) -> io::Result<Option<JsonRpc>> {
    // Loop (not recurse) over skipped blank lines: a client flooding blank
    // lines must not grow the stack, which under panic=abort would abort the
    // process.
    loop {
        let mut line = Vec::new();
        // Take bounds how many bytes read_until will pull in. The +1 sentinel
        // byte lets a full-but-legal line (exactly at the cap) be told apart
        // from one that ran past it: only an overrun leaves line.len() above
        // max_line.
        let n = (&mut *r)
            .take(max_line as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(None);
        }
        if line.len() > max_line {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mcp frame exceeds the line-length cap",
            ));
        }
        // Trim a trailing newline; tolerate CRLF.
        while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let msg: JsonRpc = serde_json::from_slice(&line).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("mcp json decode: {e}"))
        })?;
        return Ok(Some(msg));
    }
}

/// Write one JSON-RPC message as a single NDJSON line (LF-terminated).
pub fn mcp_write<W: Write>(w: &mut W, msg: &JsonRpc) -> io::Result<()> {
    // serde_json escapes embedded newlines inside strings as \n, so the
    // serialized object is guaranteed to contain no raw newline.
    let bytes = serde_json::to_vec(msg)?;
    w.write_all(&bytes)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

// ----------------------------------------------------------------------------
// 3. Internal bridge envelope (MCP server <-> native host <-> extension)
// ----------------------------------------------------------------------------

/// The INTERNAL bridge protocol version (MCP server <-> native host <->
/// extension). This is NOT the MCP JSON-RPC version (that is the date string
/// "2025-06-18", see docs/adr/0007) and NOT the extension release version
/// (Cargo is the release version source). It is a small monotonically
/// increasing integer, bumped only when the bridge wire contract
/// ([`BridgeReq`]/[`BridgeResp`] shape, hello handshake, op/capability
/// semantics) changes incompatibly.
///
/// Intended compatibility handshake (design; layered on the hello
/// authentication of docs/adr/0002): on connect, the native host -> MCP
/// server exchange carries `{hello, protocolVersion, capabilities[]}` - after
/// the secret is validated, the extension advertises its available capability
/// ids (see [`crate::tools::CAPABILITIES`]) and its protocol version. On an
/// incompatible version the server rejects the connection with the
/// `PROTOCOL_MISMATCH` error (see `error::ERROR_SPECS`) instead of accepting
/// it and surfacing a confusing "unknown op" later; a tool whose required
/// capability is not advertised is rejected up front the same way.
pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;

/// The bridge authentication handshake, exchanged as two NDJSON frames right
/// after a connection is accepted. The server sends a `Challenge` carrying a
/// fresh random nonce; the client replies with a `Response` carrying
/// HMAC-SHA256(secret, nonce), proving it knows the per-run secret without
/// ever putting the secret on the wire. The optional `label` names the browser
/// the client fronts; the server keys its connection registry by it, which is
/// what lets several browsers stay attached at once. The label rides inside
/// the signed response and is honored only after the HMAC verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Handshake {
    Challenge {
        nonce: String,
    },
    Response {
        mac: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

/// A relay's kernel-attested harness (parent) identity, carried in
/// [`AttachRequest::Client`] so the broker can check it against the
/// trusted-client allowlist. It is trustworthy not because of this frame's
/// contents but because the connection carrying it already passed
/// `attest_peer` (the relay is our own binary, which measures its parent
/// honestly via `getppid`). `name` is a self-asserted label for logs only and
/// is NEVER the authorization key. See ADR-0024.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessId {
    /// The parent's attested image hash (macOS cdhash / Linux exe SHA256).
    pub hash: String,
    /// The parent's macOS signing Team ID, when Team-ID signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Self-asserted human label (claude-code/copilot/codex/...); logs only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The role-declaration frame a peer sends over the bridge socket immediately
/// after the HMAC handshake, before any session traffic. It tells the broker
/// which kind of peer this is: a Chrome-spawned native host fronting a browser,
/// or a sibling MCP-server instance relaying its harness's tool calls. Reading
/// exactly one of these after the handshake is mandatory and fail-closed: an
/// EOF or a malformed frame drops the connection. See ADR-0024.
///
/// `Browser` is an empty struct variant (not a unit variant) because serde
/// silently skips `deny_unknown_fields` for unit variants of internally
/// tagged enums; the empty-struct form serializes identically and rejects
/// extra fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "attach", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachRequest {
    /// A native host fronting a browser. The browser label was already carried
    /// (MAC-signed) in the handshake `Response`; this frame only declares the
    /// role, so the browser leg's label authentication is unchanged.
    Browser {},
    /// A sibling MCP-server-mode instance relaying its harness's tool calls to
    /// the broker. `harness` is the relay's getppid-attested parent identity
    /// (absent only when the relay could not measure its parent, which the
    /// broker treats as unmeasured -> fail closed once enrolled).
    Client {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        harness: Option<HarnessId>,
    },
}

/// The broker's reply to an [`AttachRequest`]. `Accepted` lets the peer proceed
/// to session traffic. `Refused` names an authorization denial (allowlist miss)
/// and the peer must fail closed. `Unavailable` names a transient condition
/// (capacity, or the broker shutting down) and the peer should retry -- which,
/// for a relay, may mean becoming the broker itself. Making these explicit
/// (rather than a bare socket close) lets a relay tell "not admitted" apart
/// from "broker went away" apart from "denied".
///
/// `Accepted` is an empty struct variant for the same serde reason as
/// [`AttachRequest::Browser`]: unit variants ignore `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "attach_reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachReply {
    Accepted {},
    Refused { reason: String },
    Unavailable { reason: String },
}

/// A request from the MCP server to the extension, exchanged over the
/// localhost TCP socket as newline-delimited JSON. Carries an `id` the
/// extension echoes back so we can correlate (the socket is one-shot per
/// request/response today, but the id future-proofs multiplexing).
///
/// `deny_unknown_fields` guards the envelope only; `args` stays free-form
/// (it is validated per-op downstream against the tool catalogue). This
/// makes adding an envelope field a breaking protocol change - an older
/// peer rejects the frame rather than misreading it - so new per-op data
/// belongs inside `args`, and a new envelope field needs a protocol-version
/// bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BridgeReq {
    /// Correlation id, echoed back on the matching [`BridgeResp`]. Assigned
    /// only by the MCP server (a monotonic `AtomicU64` counter starting at
    /// 0), so every id that legitimately appears is a small non-negative
    /// integer - far inside the JS-safe integer bound the extension's Zod
    /// validator enforces. The extension side stays deliberately wider
    /// (integer-or-string, for forward compatibility); this side stays
    /// narrow on purpose: a string id can only come from a misbehaving peer,
    /// and rejecting it is fail-closed. Widening would also thread a new id
    /// type through the correlation maps in `session.rs` - if a string id
    /// ever becomes real, that is a deliberate protocol change, not a parse
    /// tweak.
    pub id: u64,
    pub op: String,
    /// Optional target tab, `tabId` on the wire (the contract and the
    /// extension use camelCase envelope fields).
    #[serde(default, rename = "tabId", skip_serializing_if = "Option::is_none")]
    pub tab_id: Option<i64>,
    /// The op's argument object, free-form at the envelope layer (each op's
    /// shape is validated downstream against the tool catalogue; the
    /// extension enforces the generated Zod validators). Required on the
    /// wire - an op without arguments sends `{}` (see tools/handlers.rs) -
    /// so both readers reject a frame that omits it, matching the
    /// extension's validator.
    pub args: Value,
    /// The label of the browser this request was routed to. The MCP server
    /// resolves the tool call's `browser` argument against its connection
    /// registry and stamps the outcome here, so the envelope records which
    /// browser was addressed. Omitted when unset (older peers, tests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
}

/// A response from the extension back to the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BridgeResp {
    /// Correlation id echoed from the [`BridgeReq`]. `u64` for the same
    /// deliberate reason as [`BridgeReq::id`]: the server assigned it, so
    /// anything else coming back is a protocol violation.
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl BridgeResp {
    #[allow(dead_code)]
    pub fn ok(id: u64, data: Value) -> Self {
        BridgeResp {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    #[allow(dead_code)]
    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        BridgeResp {
            id,
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// Read/write bridge messages as NDJSON lines over a TCP stream.
///
/// The read is bounded to [`BRIDGE_MAX_LINE`] bytes per line (including the
/// trailing newline), the same 64 MB order of magnitude [`nm_read_frame`]
/// clamps inbound frames to. `bridge_read` runs only after the peer is
/// attested, but zero trust means even an attested peer must not be able to
/// exhaust memory by sending one newline-less line, so the line is capped
/// rather than trusting the peer to terminate it.
pub const BRIDGE_MAX_LINE: usize = 64 * 1024 * 1024;

pub fn bridge_read<R: io::BufRead, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> io::Result<Option<T>> {
    bridge_read_capped(r, BRIDGE_MAX_LINE)
}

fn bridge_read_capped<R: io::BufRead, T: for<'de> Deserialize<'de>>(
    r: &mut R,
    max_line: usize,
) -> io::Result<Option<T>> {
    // Loop (not recurse) over skipped blank lines: a peer that floods blank
    // lines must not grow the stack, which under panic=abort would abort the
    // process.
    loop {
        let mut line = Vec::new();
        // Take bounds how many bytes read_until will pull in. The +1 sentinel
        // byte lets a full-but-legal line (exactly at the cap) be told apart
        // from one that ran past it: only an overrun leaves line.len() above
        // max_line.
        let n = (&mut *r)
            .take(max_line as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(None);
        }
        if line.len() > max_line {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bridge frame exceeds the line-length cap",
            ));
        }
        while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        let msg = serde_json::from_slice(&line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bridge json decode: {e}"),
            )
        })?;
        return Ok(Some(msg));
    }
}

pub fn bridge_write<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    w.write_all(&bytes)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Enclave enrollment control frames (native messaging, extension <-> host)
// ----------------------------------------------------------------------------

/// Control frames for the enrollment ceremony (ADR-0021), spoken over the
/// native-messaging channel between the extension and the native host. They
/// are HANDLED BY THE HOST ITSELF: the stdin->socket pump answers an
/// `enclave_challenge` locally (signing with the Secure Enclave key, which
/// raises the user-presence prompt) and never forwards these frames to the
/// MCP server. Everything without one of these `type` tags forwards
/// byte-for-byte as before, so the protocol is fully backward compatible —
/// an extension that never sends a challenge sees no change.
///
/// Contract (the extension side consumes this):
/// - `enclave_challenge { nonce, context? }`: `nonce` is a non-empty NUL-free
///   string of at most 256 bytes; `context` an optional NUL-free string of at
///   most 4096 bytes. The host keeps no replay state and will sign any valid
///   challenge (raising the presence prompt), so freshness is NORMATIVE on
///   the extension side: the nonce MUST be freshly generated per challenge
///   from a cryptographic RNG (e.g. 32 bytes of `crypto.getRandomValues`,
///   encoded), MUST be single-use, and a proof MUST only be accepted for the
///   exact nonce the extension itself just issued. A proof over any other
///   nonce, or a second proof over a used nonce, MUST be rejected.
/// - `enclave_proof { sig, key_id, pubkey }`: `sig` is base64 of the raw
///   64-byte IEEE P1363 `r||s` ECDSA P-256/SHA-256 signature over
///   `UTF8("chromium-bridge-enclave-v1") || 0x00 || UTF8(nonce) || 0x00 ||
///   UTF8(context or "")`; `key_id` is the lowercase-hex SHA-256 of the
///   65-byte X9.63 public key; `pubkey` is base64 of those 65 bytes. The
///   extension MUST verify `sig` against its PINNED key, not against the
///   `pubkey` field (which is trustworthy only during the user-verified
///   enrollment ceremony itself).
/// - `enclave_error { reason }`: stable codes `unsupported_platform`,
///   `not_enrolled`, `invalid_challenge`, `key_invalid`, `keychain_error`,
///   `signing_failed`.
/// - `enclave_revoke {}` (extension -> host, ADR-0025): delete the enrollment
///   key from the keychain, remove the recorded policy, and bump the
///   revocation epoch. Deletion is not presence-gated (ADR-0021: it only ever
///   reduces capability). Answered with `enclave_revoked` on success (also
///   when no key existed -- the requested end state holds either way) or
///   `enclave_error { keychain_error }` on failure.
/// - `enclave_revoked {}` (host -> extension, ADR-0025): the enrollment key is
///   gone. Sent as the acknowledgement of `enclave_revoke`, and PUSHED
///   host-originated when the host observes the key was revoked out-of-band
///   (`chromium-bridge revoke`, `pair --reset`), so a pinned extension flips
///   to its fail-closed compromised state without waiting for an opt-in
///   reverify. The extension treats it as capability reduction only: with a
///   pin it marks the bridge compromised; without one it is a no-op.
///
/// The PER-ACTION presence frames (ADR-0031) ride the same channel and are
/// likewise host-handled, one round per confirmation of a crown-jewel tool
/// (`page_eval`, `page_upload`):
///
/// - `presence_challenge { nonce, context? }` (extension -> host): same field
///   bounds and freshness rules as `enclave_challenge` (fresh CSPRNG nonce,
///   single-use, proof accepted only for the extension's own outstanding
///   nonce). The signature covers `UTF8("chromium-bridge-presence-v1") ||
///   0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")` - a DIFFERENT
///   domain from the enrollment proof, so neither statement type can ever be
///   replayed as the other. Signing raises the Secure Enclave user-presence
///   prompt; the Touch ID tap is the approval. The host refuses (without
///   prompting) while the kill switch is engaged (`bridge_killed`) and while
///   another presence round is in flight (`busy`).
/// - `presence_proof { sig, key_id, pubkey }` (host -> extension): same
///   encoding as `enclave_proof`, under the presence domain. The extension
///   MUST verify against its PINNED key.
/// - `presence_error { reason }` (host -> extension): the enclave reason
///   codes plus `bridge_killed` and `busy`. Every error is a denial; the
///   extension must fail the confirmation closed, never fall back to a
///   softer surface (the no-downgrade rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnclaveControl {
    EnclaveChallenge {
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    EnclaveProof {
        sig: String,
        key_id: String,
        pubkey: String,
    },
    EnclaveError {
        reason: String,
    },
    /// Extension -> host: delete the enrollment key (ADR-0025). An empty
    /// struct variant so `deny_unknown_fields` applies (unit variants of
    /// internally tagged enums silently skip it).
    EnclaveRevoke {},
    /// Host -> extension: the enrollment key is gone (ack or proactive push).
    EnclaveRevoked {},
    /// Extension -> host: ask for one per-action user-presence approval
    /// (ADR-0031).
    PresenceChallenge {
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    /// Host -> extension: the signed presence approval.
    PresenceProof {
        sig: String,
        key_id: String,
        pubkey: String,
    },
    /// Host -> extension: the presence round failed; the confirmation is
    /// denied.
    PresenceError {
        reason: String,
    },
}

/// Host-admin control frames (ADR-0025/0030), spoken over the native-messaging
/// channel and handled by the native host itself, exactly like
/// [`EnclaveControl`]: never forwarded to the MCP server, and dropped if the
/// server leg tries to inject one. They give the extension's options UI a
/// managed path to the trusted-client allowlist, the global kill switch, and
/// the audit trail:
///
/// - `client_list {}` -> `client_list_result { ok, enrolled, clients, error? }`
///   Read-only. `enrolled` mirrors the CLI's unenrolled/enrolled distinction;
///   `clients` reuses the on-disk entry shape (`{name, anchor: {kind, value},
///   added_unix}`). A load failure (including the ADR-0025 tamper case) comes
///   back as `ok: false` with the error text -- the UI shows it, nothing is
///   guessed.
/// - `client_revoke { name }` -> `client_revoke_result { ok, error? }`
///   Removes one trusted client and bumps the revocation epoch in the same
///   critical section, so a live broker drops that client's connections.
/// - `kill_status {}` / `kill_engage {}` / `kill_release {}` ->
///   `kill_status_result { ok, killed?, error? }` (ADR-0030). The result frame
///   is also PUSHED host-originated, unsolicited: at startup and whenever the
///   host's revocation watch sees the kill marker move, so the extension's
///   SW-only mirror tracks CLI-driven transitions without polling. `ok: false`
///   (state unreadable) carries no `killed` claim; the extension treats it as
///   unknown and fails closed.
/// - `audit_event { kind, outcome?, tool?, name?, detail? }` (ADR-0030,
///   fire-and-forget, no reply): the extension reports one of ITS OWN
///   user-facing decisions (confirmations, enrollment approvals) for the
///   host's on-disk audit trail. The host accepts only the extension-owned
///   kinds ([`crate::audit::extension_kind`]) and stamps the surface itself,
///   so the frame cannot forge host-side events like admissions or kills.
///
/// Trust: these frames arrive only from the extension Chrome connected to
/// this host (`allowed_origins`). The list/revoke pair adds no capability
/// beyond the CLI's (capability reduction); `kill_engage` is also reduction.
/// `kill_release` RESTORES capability and is the one deliberate exception,
/// accepted because the extension's options page is a trusted surface on par
/// with the CLI (ADR-0030 records the decision and the page-can-never-reach-it
/// gating that keeps it true).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminControl {
    /// Extension -> host: report the trusted-client allowlist.
    ClientList {},
    /// Host -> extension: the allowlist (or the load error, fail closed).
    ClientListResult {
        ok: bool,
        /// Whether admission is enforced (an allowlist exists). `false` with
        /// `ok: true` is the unenrolled bootstrap posture.
        enrolled: bool,
        clients: Vec<crate::allowlist::ClientEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: revoke one trusted client by name.
    ClientRevoke { name: String },
    /// Host -> extension: the revocation outcome.
    ClientRevokeResult {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: report the kill-switch state (ADR-0030).
    KillStatus {},
    /// Extension -> host: engage the global kill switch.
    KillEngage {},
    /// Extension -> host: release the global kill switch.
    KillRelease {},
    /// Host -> extension: the kill-switch state. The reply to all three kill
    /// frames, and pushed unsolicited on observed transitions. `killed` is
    /// absent when `ok` is false (the state could not be read; the extension
    /// fails closed on unknown).
    KillStatusResult {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        killed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: one extension-side decision for the audit trail
    /// (ADR-0030). Fire-and-forget; no reply frame.
    AuditEvent {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// How the native host's stdin->socket pump must treat one inbound frame.
#[derive(Debug)]
pub enum FrameDisposition {
    /// Not a control frame: forward to the MCP server unchanged.
    Forward,
    /// A well-formed `enclave_challenge`: answer it locally, do not forward.
    Challenge {
        nonce: String,
        context: Option<String>,
    },
    /// A well-formed `enclave_revoke` (ADR-0025): delete the enrollment key
    /// locally, bump the revocation epoch, reply `enclave_revoked`.
    RevokeHostKey,
    /// A well-formed `presence_challenge` (ADR-0031): sign the per-action
    /// presence statement locally (raising the user-presence prompt), do not
    /// forward.
    PresenceChallenge {
        nonce: String,
        context: Option<String>,
    },
    /// A well-formed `client_list` (ADR-0025): report the allowlist.
    ClientList,
    /// A well-formed `client_revoke` (ADR-0025): revoke the named client.
    ClientRevoke { name: String },
    /// A well-formed `kill_status` (ADR-0030): report the kill-switch state.
    KillStatus,
    /// A well-formed `kill_engage` (ADR-0030): engage the kill switch.
    KillEngage,
    /// A well-formed `kill_release` (ADR-0030): release the kill switch.
    KillRelease,
    /// A well-formed `audit_event` (ADR-0030): record one extension-side
    /// decision in the audit trail. Fire-and-forget, no reply.
    AuditEvent {
        kind: String,
        outcome: Option<String>,
        tool: Option<String>,
        name: Option<String>,
        detail: Option<String>,
    },
    /// A control-frame `type` that is not addressed to the host (a stray
    /// proof/error/revoked/result, or a malformed host-directed frame with no
    /// defined error reply) — drop it, never forward it.
    Drop(&'static str),
    /// Carries the `enclave_challenge` type but does not parse as that frame:
    /// reply `enclave_error { reason: "invalid_challenge" }`, do not forward.
    Malformed,
    /// Carries the `presence_challenge` type but does not parse as that
    /// frame: reply `presence_error { reason: "invalid_challenge" }`, do not
    /// forward.
    MalformedPresence,
    /// Carries a `client_*` request type but does not parse as that frame:
    /// reply the matching `*_result { ok: false }`, do not forward.
    MalformedAdmin(&'static str),
}

/// Classify one native-messaging frame for the pump. Pure, so the
/// handled-vs-forwarded decision is unit-testable without a socket. Keyed on
/// the exact `type` tags of [`EnclaveControl`] and [`AdminControl`]: bridge
/// requests carry `op` (no `type`), and the socket handshake frames
/// (`challenge`/`response`) never traverse the pump, so nothing legitimate
/// collides.
pub fn classify_nm_frame(frame: &Value) -> FrameDisposition {
    let tag = frame.get("type").and_then(Value::as_str);
    match tag {
        Some("enclave_challenge") => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::EnclaveChallenge { nonce, context }) => {
                FrameDisposition::Challenge { nonce, context }
            }
            _ => FrameDisposition::Malformed,
        },
        Some("enclave_revoke") => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::EnclaveRevoke {}) => FrameDisposition::RevokeHostKey,
            // No error-reply contract exists for a malformed revoke (the
            // genuine extension sends the exact empty shape); dropping it
            // fails closed without inventing a misleading reason code.
            _ => FrameDisposition::Drop("malformed enclave_revoke"),
        },
        Some("presence_challenge") => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::PresenceChallenge { nonce, context }) => {
                FrameDisposition::PresenceChallenge { nonce, context }
            }
            _ => FrameDisposition::MalformedPresence,
        },
        Some("client_list") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::ClientList {}) => FrameDisposition::ClientList,
            _ => FrameDisposition::MalformedAdmin("client_list"),
        },
        Some("client_revoke") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::ClientRevoke { name }) => FrameDisposition::ClientRevoke { name },
            _ => FrameDisposition::MalformedAdmin("client_revoke"),
        },
        Some("kill_status") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillStatus {}) => FrameDisposition::KillStatus,
            _ => FrameDisposition::MalformedAdmin("kill_status"),
        },
        Some("kill_engage") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillEngage {}) => FrameDisposition::KillEngage,
            _ => FrameDisposition::MalformedAdmin("kill_engage"),
        },
        Some("kill_release") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillRelease {}) => FrameDisposition::KillRelease,
            _ => FrameDisposition::MalformedAdmin("kill_release"),
        },
        Some("audit_event") => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::AuditEvent {
                kind,
                outcome,
                tool,
                name,
                detail,
            }) => FrameDisposition::AuditEvent {
                kind,
                outcome,
                tool,
                name,
                detail,
            },
            // Fire-and-forget has no reply contract; a malformed event is
            // dropped (and logged), never recorded as if it were valid.
            _ => FrameDisposition::Drop("malformed audit_event"),
        },
        Some("enclave_proof") => FrameDisposition::Drop("enclave_proof"),
        Some("enclave_error") => FrameDisposition::Drop("enclave_error"),
        Some("enclave_revoked") => FrameDisposition::Drop("enclave_revoked"),
        Some("presence_proof") => FrameDisposition::Drop("presence_proof"),
        Some("presence_error") => FrameDisposition::Drop("presence_error"),
        Some("client_list_result") => FrameDisposition::Drop("client_list_result"),
        Some("client_revoke_result") => FrameDisposition::Drop("client_revoke_result"),
        Some("kill_status_result") => FrameDisposition::Drop("kill_status_result"),
        _ => FrameDisposition::Forward,
    }
}

/// The host-control `type` tag carried by `frame` — any [`EnclaveControl`] or
/// [`AdminControl`] tag — or `None` for everything else. The native host's
/// socket->stdout pump uses this to drop control frames arriving FROM the MCP
/// server: the ceremony and the admin exchange run strictly between the
/// extension and the host itself, so the server leg has no legitimate reason
/// to ever carry one. Zero trust applies to our own server too — an
/// attested-but-misbehaving server must not be able to inject an
/// `enclave_error` that burns the extension's outstanding nonce, an
/// `enclave_revoked` that provokes a false fail-closed "compromised" mark, or
/// a forged `client_list_result` (ADR-0021/0025).
pub fn host_control_type(frame: &Value) -> Option<&str> {
    match frame.get("type").and_then(Value::as_str) {
        tag @ Some(
            "enclave_challenge"
            | "enclave_proof"
            | "enclave_error"
            | "enclave_revoke"
            | "enclave_revoked"
            | "presence_challenge"
            | "presence_proof"
            | "presence_error"
            | "client_list"
            | "client_list_result"
            | "client_revoke"
            | "client_revoke_result"
            | "kill_status"
            | "kill_engage"
            | "kill_release"
            | "kill_status_result"
            | "audit_event",
        ) => tag,
        _ => None,
    }
}

// ----------------------------------------------------------------------------
// Utilities
// ----------------------------------------------------------------------------

/// Install a panic hook that writes to stderr instead of stdout. Critical:
/// the MCP server and native host both speak binary protocols over stdout,
/// and a default panic message (printed to stdout) would corrupt the stream
/// and tear down the connection. Combined with `panic = "abort"` in the
/// release profile this is belt-and-braces.
pub fn install_stderr_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = writeln!(io::stderr(), "[chromium-bridge] panic: {info}");
        default(info);
    }));
}

/// SIGPIPE protection. On Unix, writing to a closed stdout/socket raises
/// SIGPIPE by default and kills the process. Rust disables SIGPIPE for its
/// own I/O but not for the inherited disposition everywhere; ignore it so we
/// get EPIPE errors instead of dying. Safe to call once at startup.
pub fn ignore_sigpipe() {
    crate::sys::ignore_sigpipe();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn nm_frame_roundtrip() {
        let v = json!({ "op": "tab_list", "id": 1 });
        let mut buf = Vec::new();
        nm_write_frame(&mut buf, &v).unwrap();
        // 4-byte LE length prefix precedes the JSON body.
        let body_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(body_len, buf.len() - 4);
        let mut cur = Cursor::new(buf);
        assert_eq!(nm_read_frame(&mut cur).unwrap().unwrap(), v);
    }

    #[test]
    fn nm_read_eof_is_none() {
        let mut cur = Cursor::new(Vec::<u8>::new());
        assert!(nm_read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn nm_write_rejects_oversize() {
        let v = json!({ "s": "x".repeat(NM_MAX_OUTGOING + 10) });
        let err = nm_write_frame(&mut Vec::new(), &v).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn nm_read_rejects_huge_prefix() {
        // 0xFFFFFFFF length (~4 GB) exceeds the 64 MB inbound clamp.
        let mut cur = Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        let err = nm_read_frame(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn mcp_ndjson_single_line_roundtrip() {
        // Embedded newline must be escaped so the frame stays one NDJSON line.
        let msg = JsonRpc::ok(json!(1), json!({ "text": "a\nb" }));
        let mut buf = Vec::new();
        mcp_write(&mut buf, &msg).unwrap();
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
        assert!(buf.ends_with(b"\n"));
        let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
        assert_eq!(got.id, Some(json!(1)));
    }

    #[test]
    fn mcp_read_rejects_a_line_over_the_cap() {
        // A newline-less client line longer than the cap is rejected instead of
        // being buffered in full (the memory-exhaustion path on the client
        // leg). A tiny cap keeps the test fast; mcp_read wires the real 64 MB.
        let mut r = Cursor::new(vec![b'x'; 64]); // no newline, cap is 16
        let err = mcp_read_capped(&mut r, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn mcp_read_cap_boundary_is_exact() {
        // The cap counts the whole line, newline included. A line whose length
        // equals the cap parses; one byte tighter rejects it. Pins the
        // off-by-one the +1 sentinel guards.
        let mut wire = br#"{"jsonrpc":"2.0","id":1}"#.to_vec();
        wire.push(b'\n');
        let total = wire.len();

        let got = mcp_read_capped(&mut Cursor::new(wire.clone()), total).unwrap();
        assert_eq!(got.unwrap().id, Some(json!(1)));

        let err = mcp_read_capped(&mut Cursor::new(wire), total - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn mcp_read_skips_blank_lines_without_recursing() {
        // A large flood of blank lines: the iterative loop skips them in
        // constant stack, whereas the old `return mcp_read(r)` recursion would
        // grow the stack once per blank and overflow (aborting under
        // panic=abort). Sized well past any plausible stack depth, so a
        // regression back to recursion makes this test crash rather than pass.
        let mut buf = vec![b'\n'; 200_000];
        let msg = JsonRpc::ok(json!(2), json!({}));
        mcp_write(&mut buf, &msg).unwrap();
        let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
        assert_eq!(got.id, Some(json!(2)));
    }

    #[test]
    fn bridge_envelope_roundtrip() {
        let req = BridgeReq {
            id: 7,
            op: "page_click".into(),
            tab_id: Some(3),
            args: json!({ "ref": "e3" }),
            browser: Some("brave".into()),
        };
        let mut buf = Vec::new();
        bridge_write(&mut buf, &req).unwrap();
        // The wire form uses the contract's camelCase field name, not the
        // Rust field name.
        let wire: Value = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(wire["tabId"], 3);
        assert!(wire.get("tab_id").is_none());
        let got: BridgeReq = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
        assert_eq!(got.id, 7);
        assert_eq!(got.op, "page_click");
        assert_eq!(got.tab_id, Some(3));
        assert_eq!(got.args, json!({ "ref": "e3" }));
        assert_eq!(got.browser.as_deref(), Some("brave"));

        // A request without the browser field (older peer) deserializes with
        // browser defaulted to None, and None is omitted on the wire.
        let bare: BridgeReq = bridge_read(&mut Cursor::new(
            b"{\"id\":1,\"op\":\"tab_list\",\"args\":{}}\n".to_vec(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(bare.browser, None);
        let mut buf = Vec::new();
        bridge_write(&mut buf, &bare).unwrap();
        assert!(!String::from_utf8(buf).unwrap().contains("browser"));
    }

    #[test]
    fn bridge_read_rejects_a_line_over_the_cap() {
        // A newline-less line longer than the cap is rejected instead of being
        // buffered in full (the memory-exhaustion path). A tiny cap keeps the
        // test fast; the public bridge_read wires the real 64 MB ceiling.
        let mut r = Cursor::new(vec![b'x'; 64]); // no newline, cap is 16
        let err = bridge_read_capped::<_, Value>(&mut r, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bridge_read_cap_boundary_is_exact() {
        // The cap counts the whole line, newline included. A line whose length
        // equals the cap parses; one byte tighter rejects it rather than
        // truncating. This pins the off-by-one the +1 sentinel guards.
        let mut wire = br#"{"id":1,"op":"x","args":{}}"#.to_vec();
        wire.push(b'\n');
        let total = wire.len();

        let got: Option<BridgeReq> =
            bridge_read_capped(&mut Cursor::new(wire.clone()), total).unwrap();
        assert_eq!(got.unwrap().id, 1);

        let err =
            bridge_read_capped::<_, BridgeReq>(&mut Cursor::new(wire), total - 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bridge_read_skips_blank_lines_without_recursing() {
        // A large flood of blank lines is skipped iteratively, in constant
        // stack; a recursive skip would grow the stack once per blank and
        // overflow (aborting under panic=abort). Sized well past any plausible
        // stack depth, so a regression to recursion crashes rather than passes.
        let mut wire = vec![b'\n'; 200_000];
        bridge_write(
            &mut wire,
            &BridgeReq {
                id: 9,
                op: "noop".into(),
                tab_id: None,
                args: json!({}),
                browser: None,
            },
        )
        .unwrap();
        let got: BridgeReq = bridge_read(&mut Cursor::new(wire)).unwrap().unwrap();
        assert_eq!(got.id, 9);
    }

    #[test]
    fn handshake_challenge_and_response_roundtrip() {
        // Challenge frame carries the tagged type + nonce.
        let chal = Handshake::Challenge {
            nonce: "abc123".into(),
        };
        let mut buf = Vec::new();
        bridge_write(&mut buf, &chal).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&buf[..buf.len() - 1]).unwrap(),
            json!({ "type": "challenge", "nonce": "abc123" })
        );
        let back: Handshake = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
        assert!(matches!(back, Handshake::Challenge { nonce } if nonce == "abc123"));

        // Response frame: label is optional and omitted when None.
        let resp = Handshake::Response {
            mac: "deadbeef".into(),
            label: None,
        };
        let mut buf = Vec::new();
        bridge_write(&mut buf, &resp).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&buf[..buf.len() - 1]).unwrap(),
            json!({ "type": "response", "mac": "deadbeef" })
        );
        // A response with no label deserializes with label defaulted to None.
        let back: Handshake = bridge_read(&mut Cursor::new(
            b"{\"type\":\"response\",\"mac\":\"x\"}\n".to_vec(),
        ))
        .unwrap()
        .unwrap();
        assert!(matches!(back, Handshake::Response { label: None, .. }));
    }

    #[test]
    fn attach_frames_roundtrip_and_are_tagged() {
        // Browser attach is a bare role marker (its label rode the signed
        // handshake response, not this frame).
        assert_eq!(
            serde_json::to_value(AttachRequest::Browser {}).unwrap(),
            json!({ "attach": "browser" })
        );
        // Client attach carries the relay's attested harness identity; a name
        // is optional and is a log label only.
        let client = AttachRequest::Client {
            harness: Some(HarnessId {
                hash: "abc123".into(),
                team_id: Some("3ZMH96L4V9".into()),
                name: Some("claude-code".into()),
            }),
        };
        let v = serde_json::to_value(&client).unwrap();
        assert_eq!(v["attach"], "client");
        assert_eq!(v["harness"]["hash"], "abc123");
        assert_eq!(v["harness"]["team_id"], "3ZMH96L4V9");
        let back: AttachRequest = serde_json::from_value(v).unwrap();
        assert!(matches!(back, AttachRequest::Client { harness: Some(h) } if h.hash == "abc123"));

        // A client attach with no measurable harness omits the field.
        let bare = AttachRequest::Client { harness: None };
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            json!({ "attach": "client" })
        );

        // Replies are tagged and roundtrip.
        for reply in [
            AttachReply::Accepted {},
            AttachReply::Refused {
                reason: "not allowlisted".into(),
            },
            AttachReply::Unavailable {
                reason: "capacity".into(),
            },
        ] {
            let v = serde_json::to_value(&reply).unwrap();
            let back: AttachReply = serde_json::from_value(v).unwrap();
            assert_eq!(
                serde_json::to_value(back).unwrap(),
                serde_json::to_value(reply).unwrap()
            );
        }
    }

    #[test]
    fn wire_types_reject_unknown_fields() {
        // Zero trust, fail closed: an unexpected field on any bridge wire
        // frame is a protocol violation (a newer peer, a confused peer, or an
        // attacker probing the parser) and must be rejected, never silently
        // ignored. Each case pairs the reject with a positive control so a
        // failure here means the deny, not a broken fixture.

        // Handshake: both variants.
        for (bad, good) in [
            (
                json!({ "type": "challenge", "nonce": "n", "extra": 1 }),
                json!({ "type": "challenge", "nonce": "n" }),
            ),
            (
                json!({ "type": "response", "mac": "m", "label": "b", "extra": 1 }),
                json!({ "type": "response", "mac": "m", "label": "b" }),
            ),
        ] {
            assert!(
                serde_json::from_value::<Handshake>(bad.clone()).is_err(),
                "should reject: {bad}"
            );
            assert!(serde_json::from_value::<Handshake>(good).is_ok());
        }

        // AttachRequest: the browser role frame (empty struct variant exists
        // exactly so this reject works), the client frame, and an extra field
        // nested inside the harness identity.
        for (bad, good) in [
            (
                json!({ "attach": "browser", "extra": 1 }),
                json!({ "attach": "browser" }),
            ),
            (
                json!({ "attach": "client", "extra": 1 }),
                json!({ "attach": "client" }),
            ),
            (
                json!({ "attach": "client", "harness": { "hash": "h", "extra": 1 } }),
                json!({ "attach": "client", "harness": { "hash": "h" } }),
            ),
        ] {
            assert!(
                serde_json::from_value::<AttachRequest>(bad.clone()).is_err(),
                "should reject: {bad}"
            );
            assert!(serde_json::from_value::<AttachRequest>(good).is_ok());
        }

        // HarnessId directly.
        assert!(serde_json::from_value::<HarnessId>(
            json!({ "hash": "h", "team_id": "t", "name": "n", "extra": 1 })
        )
        .is_err());

        // AttachReply: all three variants.
        for (bad, good) in [
            (
                json!({ "attach_reply": "accepted", "extra": 1 }),
                json!({ "attach_reply": "accepted" }),
            ),
            (
                json!({ "attach_reply": "refused", "reason": "r", "extra": 1 }),
                json!({ "attach_reply": "refused", "reason": "r" }),
            ),
            (
                json!({ "attach_reply": "unavailable", "reason": "r", "extra": 1 }),
                json!({ "attach_reply": "unavailable", "reason": "r" }),
            ),
        ] {
            assert!(
                serde_json::from_value::<AttachReply>(bad.clone()).is_err(),
                "should reject: {bad}"
            );
            assert!(serde_json::from_value::<AttachReply>(good).is_ok());
        }

        // Bridge envelope: the deny guards the envelope only; `args` stays
        // free-form (validated per-op downstream).
        assert!(serde_json::from_value::<BridgeReq>(
            json!({ "id": 1, "op": "tab_list", "args": {}, "extra": 1 })
        )
        .is_err());
        // The pre-rename snake_case field is an unknown field now. Safe: no
        // released peer ever emitted it (the field was always None/omitted),
        // and a peer that does send it is out of contract.
        assert!(serde_json::from_value::<BridgeReq>(
            json!({ "id": 1, "op": "tab_list", "tab_id": 3, "args": {} })
        )
        .is_err());
        assert!(serde_json::from_value::<BridgeReq>(
            json!({ "id": 1, "op": "tab_list", "tabId": 3, "args": {} })
        )
        .is_ok());
        // A string id is rejected on both envelopes: the server is the sole
        // assigner and only assigns integers; the contract's string arm is
        // forward-compat only (see the field docs on BridgeReq::id).
        assert!(serde_json::from_value::<BridgeReq>(
            json!({ "id": "s-1", "op": "tab_list", "args": {} })
        )
        .is_err());
        // `args` is a required envelope field: every builder sends an object
        // (`{}` for arg-less ops, see tools/handlers.rs), and the reader
        // rejects a frame that omits it - the same language the extension's
        // Zod validator enforces.
        assert!(serde_json::from_value::<BridgeReq>(json!({ "id": 1, "op": "tab_list" })).is_err());
        assert!(serde_json::from_value::<BridgeResp>(json!({ "id": "s-1", "ok": true })).is_err());
        let req: BridgeReq =
            serde_json::from_value(json!({ "id": 1, "op": "x", "args": { "free": "form" } }))
                .unwrap();
        assert_eq!(req.args["free"], "form");
        assert!(serde_json::from_value::<BridgeResp>(
            json!({ "id": 1, "ok": true, "data": {}, "extra": 1 })
        )
        .is_err());
        assert!(
            serde_json::from_value::<BridgeResp>(json!({ "id": 1, "ok": true, "data": {} }))
                .is_ok()
        );

        // Enclave control frames: all five variants reject an unexpected
        // field, and a challenge carrying one is classified Malformed
        // (answered with an error), never signed.
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "enclave_proof", "sig": "s", "key_id": "k", "pubkey": "p", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "enclave_error", "reason": "r", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "enclave_revoke", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "enclave_revoked", "extra": 1 })
        )
        .is_err());
        assert!(
            serde_json::from_value::<EnclaveControl>(json!({ "type": "enclave_revoke" })).is_ok()
        );
        assert!(
            serde_json::from_value::<EnclaveControl>(json!({ "type": "enclave_revoked" })).is_ok()
        );
        // The presence frames (ADR-0031) reject unknown fields the same way,
        // with positive controls.
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "presence_challenge", "nonce": "n", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "presence_proof", "sig": "s", "key_id": "k", "pubkey": "p",
                    "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "presence_error", "reason": "r", "extra": 1 })
        )
        .is_err());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "presence_challenge", "nonce": "n", "context": "c" })
        )
        .is_ok());
        assert!(serde_json::from_value::<EnclaveControl>(
            json!({ "type": "presence_proof", "sig": "s", "key_id": "k", "pubkey": "p" })
        )
        .is_ok());
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n", "extra": 1 })),
            FrameDisposition::Malformed
        ));

        // Admin control frames (ADR-0025): every variant rejects an
        // unexpected field, with positive controls.
        for (bad, good) in [
            (
                json!({ "type": "client_list", "extra": 1 }),
                json!({ "type": "client_list" }),
            ),
            (
                json!({ "type": "client_revoke", "name": "codex", "extra": 1 }),
                json!({ "type": "client_revoke", "name": "codex" }),
            ),
            (
                json!({ "type": "client_revoke_result", "ok": true, "extra": 1 }),
                json!({ "type": "client_revoke_result", "ok": true }),
            ),
            (
                json!({ "type": "client_list_result", "ok": true, "enrolled": false,
                        "clients": [], "extra": 1 }),
                json!({ "type": "client_list_result", "ok": true, "enrolled": false,
                        "clients": [] }),
            ),
        ] {
            assert!(
                serde_json::from_value::<AdminControl>(bad.clone()).is_err(),
                "should reject: {bad}"
            );
            assert!(serde_json::from_value::<AdminControl>(good).is_ok());
        }
    }

    #[test]
    fn bridge_envelope_wire_keys_are_pinned() {
        // These Rust types ARE the canonical envelope contract (ADR-0028);
        // the extension's Zod validators are checked against them by the CI
        // double-derivation diff (scripts/check-envelope-parity.ts). This
        // test pins the exact wire field names locally, so a rename or an
        // added field fails `cargo test` immediately (this is the test that
        // would have caught tab_id-vs-tabId) instead of waiting for the
        // cross-language diff.
        fn wire_keys<T: Serialize>(v: &T) -> std::collections::BTreeSet<String> {
            serde_json::to_value(v)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        }
        fn expected(keys: &[&str]) -> std::collections::BTreeSet<String> {
            keys.iter().map(|s| s.to_string()).collect()
        }

        let req = BridgeReq {
            id: 1,
            op: "tab_list".into(),
            tab_id: Some(2),
            args: json!({}),
            browser: Some("brave".into()),
        };
        assert_eq!(
            wire_keys(&req),
            expected(&["args", "browser", "id", "op", "tabId"]),
            "BridgeReq wire fields changed - update the Zod validator \
             (src/packages/shared/src/envelope.ts) and bump BRIDGE_PROTOCOL_VERSION \
             if the change is incompatible"
        );

        let resp = BridgeResp {
            id: 1,
            ok: false,
            data: Some(json!({})),
            error: Some("e".into()),
        };
        assert_eq!(
            wire_keys(&resp),
            expected(&["data", "error", "id", "ok"]),
            "BridgeResp wire fields changed - update the Zod validator \
             (src/packages/shared/src/envelope.ts) and bump BRIDGE_PROTOCOL_VERSION \
             if the change is incompatible"
        );
    }

    #[test]
    fn enclave_control_serde_roundtrip() {
        // Challenge with and without context; the tag is the snake_case name.
        let chal = EnclaveControl::EnclaveChallenge {
            nonce: "n1".into(),
            context: Some("ctx".into()),
        };
        let v = serde_json::to_value(&chal).unwrap();
        assert_eq!(
            v,
            json!({ "type": "enclave_challenge", "nonce": "n1", "context": "ctx" })
        );
        let no_ctx = EnclaveControl::EnclaveChallenge {
            nonce: "n2".into(),
            context: None,
        };
        assert_eq!(
            serde_json::to_value(&no_ctx).unwrap(),
            json!({ "type": "enclave_challenge", "nonce": "n2" })
        );

        let proof = EnclaveControl::EnclaveProof {
            sig: "c2ln".into(),
            key_id: "ab".repeat(32),
            pubkey: "cHViCg==".into(),
        };
        let v = serde_json::to_value(&proof).unwrap();
        assert_eq!(v.get("type").unwrap(), "enclave_proof");
        let back: EnclaveControl = serde_json::from_value(v).unwrap();
        assert!(matches!(back, EnclaveControl::EnclaveProof { .. }));

        let err = EnclaveControl::EnclaveError {
            reason: "not_enrolled".into(),
        };
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({ "type": "enclave_error", "reason": "not_enrolled" })
        );
    }

    #[test]
    fn classify_forwards_ordinary_frames() {
        // Bridge requests (op, no type) and arbitrary JSON forward untouched.
        for frame in [
            json!({ "op": "tab_list", "id": 1 }),
            json!({ "id": 7, "ok": true, "data": {} }),
            json!({ "type": "challenge", "nonce": "socket-handshake-shape" }),
            json!({ "type": "response", "mac": "aa" }),
            json!({ "type": 42 }),
            json!("just a string"),
            json!(null),
        ] {
            assert!(
                matches!(classify_nm_frame(&frame), FrameDisposition::Forward),
                "should forward: {frame}"
            );
        }
    }

    #[test]
    fn classify_handles_challenge_locally_and_never_forwards_control_types() {
        match classify_nm_frame(
            &json!({ "type": "enclave_challenge", "nonce": "n", "context": "c" }),
        ) {
            FrameDisposition::Challenge { nonce, context } => {
                assert_eq!(nonce, "n");
                assert_eq!(context.as_deref(), Some("c"));
            }
            other => panic!("expected Challenge, got {other:?}"),
        }
        // Context is optional.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": "n" })),
            FrameDisposition::Challenge { context: None, .. }
        ));
        // A challenge missing its nonce is malformed — answered with an
        // error, never forwarded.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_challenge" })),
            FrameDisposition::Malformed
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_challenge", "nonce": 5 })),
            FrameDisposition::Malformed
        ));
        // Stray proof/error frames are dropped, not forwarded.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_proof", "sig": "s" })),
            FrameDisposition::Drop("enclave_proof")
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_error", "reason": "r" })),
            FrameDisposition::Drop("enclave_error")
        ));
    }

    #[test]
    fn classify_handles_presence_frames_locally() {
        // A well-formed presence_challenge is handled by the host (ADR-0031),
        // never forwarded.
        match classify_nm_frame(&json!({ "type": "presence_challenge", "nonce": "n",
                                         "context": "c" }))
        {
            FrameDisposition::PresenceChallenge { nonce, context } => {
                assert_eq!(nonce, "n");
                assert_eq!(context.as_deref(), Some("c"));
            }
            other => panic!("expected PresenceChallenge, got {other:?}"),
        }
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "presence_challenge", "nonce": "n" })),
            FrameDisposition::PresenceChallenge { context: None, .. }
        ));
        // Malformed presence challenges are answered with a presence_error,
        // never signed and never forwarded.
        for bad in [
            json!({ "type": "presence_challenge" }),
            json!({ "type": "presence_challenge", "nonce": 5 }),
            json!({ "type": "presence_challenge", "nonce": "n", "extra": 1 }),
        ] {
            assert!(
                matches!(classify_nm_frame(&bad), FrameDisposition::MalformedPresence),
                "{bad}"
            );
        }
        // Stray presence proof/error frames from the browser leg are dropped:
        // they are host-originated frames only.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "presence_proof", "sig": "s" })),
            FrameDisposition::Drop("presence_proof")
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "presence_error", "reason": "r" })),
            FrameDisposition::Drop("presence_error")
        ));
        // And the socket->stdout pump recognizes all three as host control
        // types, so a misbehaving server cannot inject a forged presence
        // verdict (the signature check would catch it, but it must not even
        // reach the extension).
        for tag in ["presence_challenge", "presence_proof", "presence_error"] {
            assert_eq!(
                host_control_type(&json!({ "type": tag })),
                Some(tag),
                "{tag}"
            );
        }
    }

    #[test]
    fn classify_handles_revoke_and_admin_frames_locally() {
        // A well-formed enclave_revoke is handled by the host (ADR-0025).
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_revoke" })),
            FrameDisposition::RevokeHostKey
        ));
        // A malformed one is dropped: no error-reply contract exists for it,
        // and dropping fails closed without a misleading reason code.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_revoke", "extra": 1 })),
            FrameDisposition::Drop(_)
        ));
        // A stray enclave_revoked from the extension is dropped (it is a
        // host-originated frame only).
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "enclave_revoked" })),
            FrameDisposition::Drop("enclave_revoked")
        ));

        // Admin requests classify to their handlers...
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "client_list" })),
            FrameDisposition::ClientList
        ));
        match classify_nm_frame(&json!({ "type": "client_revoke", "name": "codex" })) {
            FrameDisposition::ClientRevoke { name } => assert_eq!(name, "codex"),
            other => panic!("expected ClientRevoke, got {other:?}"),
        }
        // ...malformed admin requests get the matching {ok:false} reply...
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "client_list", "extra": 1 })),
            FrameDisposition::MalformedAdmin("client_list")
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "client_revoke" })),
            FrameDisposition::MalformedAdmin("client_revoke")
        ));
        // ...and stray result frames from the browser side are dropped.
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "client_list_result", "ok": true })),
            FrameDisposition::Drop("client_list_result")
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "client_revoke_result", "ok": true })),
            FrameDisposition::Drop("client_revoke_result")
        ));
    }

    #[test]
    fn admin_control_serde_roundtrips() {
        use crate::allowlist::{Anchor, ClientEntry};
        let result = AdminControl::ClientListResult {
            ok: true,
            enrolled: true,
            clients: vec![ClientEntry {
                name: "claude-code".into(),
                anchor: Anchor::TeamId("3ZMH96L4V9".into()),
                added_unix: 42,
            }],
            error: None,
        };
        let v = serde_json::to_value(&result).unwrap();
        assert_eq!(v["type"], "client_list_result");
        assert_eq!(v["clients"][0]["anchor"]["kind"], "team_id");
        // `error: None` is omitted on the wire.
        assert!(v.get("error").is_none());
        let back: AdminControl = serde_json::from_value(v).unwrap();
        assert!(matches!(
            back,
            AdminControl::ClientListResult { ok: true, .. }
        ));

        let revoke_err = AdminControl::ClientRevokeResult {
            ok: false,
            error: Some("no trusted client named 'x'".into()),
        };
        let v = serde_json::to_value(&revoke_err).unwrap();
        assert_eq!(v["type"], "client_revoke_result");
        assert_eq!(v["ok"], false);
        let back: AdminControl = serde_json::from_value(v).unwrap();
        assert!(matches!(
            back,
            AdminControl::ClientRevokeResult { ok: false, .. }
        ));
    }

    #[test]
    fn classify_handles_kill_and_audit_frames_locally() {
        // ADR-0030: the three kill requests classify to their handlers...
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "kill_status" })),
            FrameDisposition::KillStatus
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "kill_engage" })),
            FrameDisposition::KillEngage
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "kill_release" })),
            FrameDisposition::KillRelease
        ));
        // ...malformed variants get the matching ok:false reply path...
        for tag in ["kill_status", "kill_engage", "kill_release"] {
            assert!(matches!(
                classify_nm_frame(&json!({ "type": tag, "extra": 1 })),
                FrameDisposition::MalformedAdmin(k) if k == tag
            ));
        }
        // ...a result frame never legitimately arrives inbound...
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "kill_status_result", "ok": true })),
            FrameDisposition::Drop(_)
        ));
        // ...an audit event carries its fields to the handler...
        match classify_nm_frame(&json!({
            "type": "audit_event", "kind": "confirm_denied", "tool": "eval"
        })) {
            FrameDisposition::AuditEvent { kind, tool, .. } => {
                assert_eq!(kind, "confirm_denied");
                assert_eq!(tool.as_deref(), Some("eval"));
            }
            other => panic!("expected AuditEvent, got {other:?}"),
        }
        // ...and a malformed one is dropped (fire-and-forget: no reply
        // contract to honor, and nothing may be recorded from garbage).
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "audit_event" })),
            FrameDisposition::Drop(_)
        ));
        assert!(matches!(
            classify_nm_frame(&json!({ "type": "audit_event", "kind": 5 })),
            FrameDisposition::Drop(_)
        ));
    }

    #[test]
    fn host_control_type_matches_exactly_the_control_tags() {
        // Every host-handled control tag is recognized (the socket->stdout
        // pump drops all of them when the server leg tries to inject one)...
        for tag in [
            "enclave_challenge",
            "enclave_proof",
            "enclave_error",
            "enclave_revoke",
            "enclave_revoked",
            "client_list",
            "client_list_result",
            "client_revoke",
            "client_revoke_result",
            "kill_status",
            "kill_engage",
            "kill_release",
            "kill_status_result",
            "audit_event",
        ] {
            assert_eq!(
                host_control_type(&json!({ "type": tag })),
                Some(tag),
                "tag {tag} must be recognized as host control"
            );
        }
        // ...while bridge traffic and near-misses pass through untouched.
        assert_eq!(
            host_control_type(&json!({ "id": 1, "op": "tab_list" })),
            None
        );
        assert_eq!(host_control_type(&json!({ "type": "enclave_other" })), None);
        assert_eq!(host_control_type(&json!({ "type": 5 })), None);
        assert_eq!(host_control_type(&json!("enclave_error")), None);
    }
}

/// Property-based (`proptest`) coverage of the parsing boundary. Three
/// families, matching the fuzzing item on the roadmap:
///   1. Roundtrip — `write` then `read` recovers the original payload.
///   2. Never-panics — arbitrary bytes fed to a reader return `Ok`/`Err` but
///      never panic (the key robustness guarantee for a security boundary).
///   3. Size guard — any length prefix above the cap is always rejected,
///      before any unbounded allocation or read.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Map;
    use std::io::Cursor;

    /// A bounded, arbitrary JSON string built from arbitrary Unicode scalar
    /// values (control chars included — serde escapes them). Avoids the
    /// `regex-syntax` proptest feature so the dependency tree stays lean.
    fn arb_string() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..12).prop_map(|cs| cs.into_iter().collect())
    }

    /// A bounded, arbitrary JSON value. Numbers are integers only: JSON cannot
    /// represent NaN/Infinity, and `serde_json::Number` rejects them, so a
    /// float strategy would generate unserializable values. Depth and breadth
    /// are capped to keep each case small and fast.
    fn arb_json() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(|n| Value::Number(n.into())),
            arb_string().prop_map(Value::String),
        ];
        leaf.prop_recursive(4, 48, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::vec((arb_string(), inner), 0..6)
                    .prop_map(|kvs| Value::Object(kvs.into_iter().collect::<Map<String, Value>>())),
            ]
        })
    }

    /// Like [`arb_json`] but never `null` at the top level. For `Option<Value>`
    /// fields, `Some(Value::Null)` serializes as `null` and deserializes back
    /// as `None` — an intentional serde asymmetry that would make an exact
    /// roundtrip comparison spuriously fail. Nested nulls are still allowed.
    fn arb_json_non_null() -> impl Strategy<Value = Value> {
        arb_json().prop_filter("non-null at top level", |v| !v.is_null())
    }

    proptest! {
        // --- 1. Roundtrip ---------------------------------------------------

        /// Native-messaging framing carries arbitrary byte payloads faithfully
        /// (bytes modelled as a JSON array of integers, the shape the frame
        /// body actually transports).
        #[test]
        fn nm_frame_carries_bytes(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
            let payload = Value::Array(
                bytes.iter().map(|b| Value::Number((*b as u64).into())).collect(),
            );
            let mut buf = Vec::new();
            nm_write_frame(&mut buf, &payload).unwrap();
            // 4-byte LE length prefix precedes the body.
            let body_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            prop_assert_eq!(body_len, buf.len() - 4);
            let got = nm_read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
            prop_assert_eq!(got, payload);
        }

        /// Any bounded JSON value survives a native-messaging frame roundtrip.
        #[test]
        fn nm_frame_value_roundtrip(v in arb_json()) {
            let mut buf = Vec::new();
            nm_write_frame(&mut buf, &v).unwrap();
            let got = nm_read_frame(&mut Cursor::new(buf)).unwrap().unwrap();
            prop_assert_eq!(got, v);
        }

        /// A JSON-RPC message survives an MCP NDJSON roundtrip, and always
        /// serializes to exactly one line.
        #[test]
        fn mcp_roundtrip(
            jsonrpc in prop::option::of(arb_string()),
            id in prop::option::of(arb_json_non_null()),
            method in prop::option::of(arb_string()),
            params in prop::option::of(arb_json_non_null()),
        ) {
            let msg = JsonRpc {
                jsonrpc,
                id,
                method,
                params,
                result: None,
                error: None,
            };
            let mut buf = Vec::new();
            mcp_write(&mut buf, &msg).unwrap();
            // NDJSON invariant: exactly one newline, the frame terminator.
            prop_assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
            let got = mcp_read(&mut Cursor::new(buf)).unwrap().unwrap();
            prop_assert_eq!(
                serde_json::to_value(&got).unwrap(),
                serde_json::to_value(&msg).unwrap(),
            );
        }

        /// A bridge request survives an NDJSON roundtrip over the envelope.
        #[test]
        fn bridge_req_roundtrip(
            id in any::<u64>(),
            op in arb_string(),
            tab_id in prop::option::of(any::<i64>()),
            args in arb_json(),
            browser in prop::option::of(arb_string()),
        ) {
            let req = BridgeReq { id, op, tab_id, args, browser };
            let mut buf = Vec::new();
            bridge_write(&mut buf, &req).unwrap();
            let got: BridgeReq = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
            prop_assert_eq!(
                serde_json::to_value(&got).unwrap(),
                serde_json::to_value(&req).unwrap(),
            );
        }

        /// A bridge response survives an NDJSON roundtrip over the envelope.
        #[test]
        fn bridge_resp_roundtrip(
            id in any::<u64>(),
            ok in any::<bool>(),
            data in prop::option::of(arb_json_non_null()),
            error in prop::option::of(arb_string()),
        ) {
            let resp = BridgeResp { id, ok, data, error };
            let mut buf = Vec::new();
            bridge_write(&mut buf, &resp).unwrap();
            let got: BridgeResp = bridge_read(&mut Cursor::new(buf)).unwrap().unwrap();
            prop_assert_eq!(
                serde_json::to_value(&got).unwrap(),
                serde_json::to_value(&resp).unwrap(),
            );
        }

        // --- 2. Never panics on arbitrary input (the fuzz property) ---------

        /// `nm_read_frame` on arbitrary bytes yields `Ok`/`Err`, never a panic.
        #[test]
        fn nm_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = nm_read_frame(&mut Cursor::new(data));
        }

        /// `mcp_read` on arbitrary bytes yields `Ok`/`Err`, never a panic.
        #[test]
        fn mcp_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = mcp_read(&mut Cursor::new(data));
        }

        /// `bridge_read` on arbitrary bytes yields `Ok`/`Err`, never a panic.
        #[test]
        fn bridge_read_never_panics(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _: io::Result<Option<Value>> = bridge_read(&mut Cursor::new(data));
        }

        // --- 3. Size guard --------------------------------------------------

        /// Any length prefix above the 64 MB inbound clamp is rejected with
        /// `InvalidData`, before allocating or reading the claimed body.
        #[test]
        fn nm_oversize_prefix_always_rejected(len in (64u32 * 1024 * 1024 + 1)..=u32::MAX) {
            let mut framed = len.to_le_bytes().to_vec();
            // Trailing bytes the guard must refuse to read past.
            framed.extend_from_slice(&[0u8; 8]);
            let err = nm_read_frame(&mut Cursor::new(framed)).unwrap_err();
            prop_assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }
}
