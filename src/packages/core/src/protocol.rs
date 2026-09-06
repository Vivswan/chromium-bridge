//! Wire protocols for chromium-bridge.
//!
//! Three protocols live here:
//! 1. Chrome Native Messaging framing (4-byte LE length prefix + UTF-8 JSON)
//!    - used between the native-host subprocess and the Chrome extension.
//! 2. MCP JSON-RPC 2.0 messages (NDJSON over stdio) - used between the MCP
//!    server and the MCP client.
//! 3. The internal "bridge" envelope - request/response exchanged between the
//!    MCP server and the native-host subprocess over the bridge socket
//!    (newline-delimited JSON).
//!
//! The host-handled control frames spoken over (1) and their classifier live
//! in [`control`].

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
    let len = u32::from_le_bytes(header);
    // Defensive bound: a corrupted prefix yielding a huge value would OOM us.
    // Inbound limit is 64 MB per the spec; clamp well above any legitimate use.
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native-messaging frame too large: {len} bytes"),
        ));
    }
    let len = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native-messaging frame length exceeds addressable memory",
        )
    })?;
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
    let len = u32::try_from(json.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native-messaging frame length overflows the u32 prefix",
        )
    })?;
    w.write_all(&len.to_le_bytes())?;
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
    // Take bounds how many bytes read_until will pull in. The +1 sentinel
    // byte lets a full-but-legal line (exactly at the cap) be told apart
    // from one that ran past it: only an overrun leaves line.len() above
    // max_line.
    let take_cap = u64::try_from(max_line)
        .ok()
        .and_then(|cap| cap.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mcp line cap out of range"))?;
    // Loop (not recurse) over skipped blank lines: a client flooding blank
    // lines must not grow the stack, which under panic=abort would abort the
    // process.
    loop {
        let mut line = Vec::new();
        let n = (&mut *r).take(take_cap).read_until(b'\n', &mut line)?;
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

/// The newest MCP JSON-RPC protocol revision this server implements:
/// `2026-07-28`, the stateless era (ADR-0034, superseding ADR-0007's pinned
/// `2025-06-18`). The protocol layer itself is the official `rmcp` SDK
/// (see [`crate::mcp`]); this pin exists so the repository keeps one source
/// of truth for the revision - the contract emitter carries it into the
/// generated TS (protocol.gen.ts), docs literals are checked against it,
/// and a unit test (mcp/handler.rs) asserts it equals the newest revision
/// rmcp serves, so the pin can never drift from the wire.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// How long (milliseconds) a client may cache the `server/discover` and
/// `tools/list` results, stamped as `ttlMs` (MCP 2026-07-28). One hour: the
/// catalogue and capabilities are static per binary, so the TTL only bounds
/// how stale a client can be across an upgrade.
pub const MCP_CACHE_TTL_MS: u64 = 3_600_000;

/// The `params._meta` key carrying a request's claimed protocol revision
/// (MCP 2026-07-28, ADR-0034). rmcp owns the enforcement; these key consts
/// exist so the TS side (protocol.gen.ts, via the contract emitter) spells
/// each wire literal exactly once, and a unit test (mcp/handler.rs) pins
/// every const to the key rmcp actually reads and writes.
pub const MCP_META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// The `params._meta` key carrying the client's declared capabilities.
/// rmcp requires this on every stateless (2026-07-28) request, alongside
/// [`MCP_META_PROTOCOL_VERSION`]; an empty object is sufficient.
pub const MCP_META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// The `_meta` key on modern results carrying the server identity
/// (`{name, version}`) - MCP 2026-07-28's replacement for the `initialize`
/// result's `serverInfo` field.
pub const MCP_META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// The INTERNAL bridge protocol version (MCP server <-> native host <->
/// extension). This is NOT the MCP JSON-RPC version (that is the date string
/// [`MCP_PROTOCOL_VERSION`], see docs/adr/0034) and NOT the extension release version
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

/// A [`BridgeResp`] parsed past its flat wire shape into the two states a
/// response can actually be in: success with data, or failure with an error.
/// The flat `{ ok, data?, error? }` triple stays the pinned wire contract
/// (ADR-0028: the Zod validators and the envelope schema are derived from
/// [`BridgeResp`]), but it can spell contradictions - `ok: true` with an
/// `error`, `ok: false` with `data`, or a bare `ok: false` claiming failure
/// with no error - and the attested-but-untrusted extension must not be able
/// to hand the session a response it has to re-interpret. Parsing goes
/// through [`TryFrom<BridgeResp>`] (wired into serde via `try_from`), so a
/// contradictory frame is refused at the read boundary as `InvalidData` -
/// the session drops the offending connection, fail closed - and everything
/// downstream matches on `outcome` with no mixture left to misread.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "BridgeResp")]
pub struct ParsedResp {
    /// Correlation id echoed from the [`BridgeReq`].
    pub id: u64,
    /// Exactly success-with-data or failure-with-error. A success frame that
    /// omitted `data` (legal on the wire for ops with nothing to return)
    /// parses as `Ok(Value::Null)`, so the omission is resolved once, here.
    pub outcome: Result<Value, String>,
}

impl TryFrom<BridgeResp> for ParsedResp {
    type Error = String;

    fn try_from(wire: BridgeResp) -> Result<Self, String> {
        let outcome = match (wire.ok, wire.data, wire.error) {
            (true, data, None) => Ok(data.unwrap_or(Value::Null)),
            (false, None, Some(error)) => Err(error),
            (true, _, Some(_)) => {
                return Err(format!(
                    "contradictory bridge response (id {}): ok with an error",
                    wire.id
                ));
            }
            (false, Some(_), _) => {
                return Err(format!(
                    "contradictory bridge response (id {}): failure carrying data",
                    wire.id
                ));
            }
            (false, None, None) => {
                return Err(format!(
                    "bridge response (id {}) claims failure with no error",
                    wire.id
                ));
            }
        };
        Ok(ParsedResp {
            id: wire.id,
            outcome,
        })
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
    // Take bounds how many bytes read_until will pull in. The +1 sentinel
    // byte lets a full-but-legal line (exactly at the cap) be told apart
    // from one that ran past it: only an overrun leaves line.len() above
    // max_line.
    let take_cap = u64::try_from(max_line)
        .ok()
        .and_then(|cap| cap.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bridge line cap out of range")
        })?;
    // Loop (not recurse) over skipped blank lines: a peer that floods blank
    // lines must not grow the stack, which under panic=abort would abort the
    // process.
    loop {
        let mut line = Vec::new();
        let n = (&mut *r).take(take_cap).read_until(b'\n', &mut line)?;
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

/// Host-handled control frames and the frame classifier; see the module docs.
pub mod control;

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
mod tests;

/// Property-based (`proptest`) coverage of the parsing boundary. Three
/// families, matching the fuzzing item on the roadmap:
///   1. Roundtrip - `write` then `read` recovers the original payload.
///   2. Never-panics - arbitrary bytes fed to a reader return `Ok`/`Err` but
///      never panic (the key robustness guarantee for a security boundary).
///   3. Size guard - any length prefix above the cap is always rejected,
///      before any unbounded allocation or read.
#[cfg(test)]
mod proptests;
