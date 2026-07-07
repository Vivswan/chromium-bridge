//! Wire protocols for browser-bridge.
//!
//! Three protocols live here:
//! 1. Chrome Native Messaging framing (4-byte LE length prefix + UTF-8 JSON)
//!    — used between the native-host subprocess and the Chrome extension.
//! 2. MCP JSON-RPC 2.0 messages (NDJSON over stdio) — used between the MCP
//!    server and ZCode.
//! 3. The internal "bridge" envelope — request/response exchanged between the
//!    MCP server and the native-host subprocess over a localhost TCP socket
//!    (newline-delimited JSON).

use std::io::{self, Read, Write};

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
    let value = serde_json::from_slice(&buf).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("nm json decode: {e}"))
    })?;
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

/// Read one NDJSON line from `r` and parse it as JSON-RPC. Returns `Ok(None)`
/// on EOF (client gone → shut down).
pub fn mcp_read<R: io::BufRead>(r: &mut R) -> io::Result<Option<JsonRpc>> {
    let mut line = Vec::new();
    let n = r.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    // Trim a trailing newline; tolerate CRLF.
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        // Blank line: treat as no-op, signal "retry" via None-with-flag.
        // Simplest: return an empty-payload parse attempt that will fail.
        // Instead we recurse once to skip.
        return mcp_read(r);
    }
    let msg: JsonRpc = serde_json::from_slice(&line).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("mcp json decode: {e}"))
    })?;
    Ok(Some(msg))
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

/// A request from the MCP server to the extension, exchanged over the
/// localhost TCP socket as newline-delimited JSON. Carries an `id` the
/// extension echoes back so we can correlate (the socket is one-shot per
/// request/response today, but the id future-proofs multiplexing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeReq {
    pub id: u64,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub args: Value,
}

/// A response from the extension back to the MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeResp {
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
        BridgeResp { id, ok: true, data: Some(data), error: None }
    }
    #[allow(dead_code)]
    pub fn err(id: u64, msg: impl Into<String>) -> Self {
        BridgeResp { id, ok: false, data: None, error: Some(msg.into()) }
    }
}

/// Read/write bridge messages as NDJSON lines over a TCP stream.
pub fn bridge_read<R: io::BufRead, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<Option<T>> {
    let mut line = Vec::new();
    let n = r.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Ok(None);
    }
    while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.is_empty() {
        return bridge_read(r);
    }
    let msg = serde_json::from_slice(&line).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bridge json decode: {e}"))
    })?;
    Ok(Some(msg))
}

pub fn bridge_write<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    w.write_all(&bytes)?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
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
        let _ = writeln!(io::stderr(), "[browser-bridge] panic: {info}");
        default(info);
    }));
}

/// SIGPIPE protection. On Unix, writing to a closed stdout/socket raises
/// SIGPIPE by default and kills the process. Rust disables SIGPIPE for its
/// own I/O but not for the inherited disposition everywhere; ignore it so we
/// get EPIPE errors instead of dying. Safe to call once at startup.
pub fn ignore_sigpipe() {
    #[cfg(unix)]
    unsafe {
        // libc::SIG_IGN = 1
        let _ = libc_signal_ignore(13 /* SIGPIPE */);
    }
}

#[cfg(unix)]
unsafe fn libc_signal_ignore(sig: i32) {
    // Avoid pulling in the libc crate; call the syscall via raw extern.
    // signal(sig, SIG_IGN) where SIG_IGN = 1 (the standard sentinel pointer).
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    let _ = signal(sig, 1);
}

