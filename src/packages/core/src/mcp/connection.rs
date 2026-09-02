//! The seam between the synchronous serve loop and the rmcp services.
//!
//! One [`Connection`] per harness connection: an rmcp server service
//! running on a small shared tokio runtime, fed typed JSON-RPC messages
//! through in-memory channels. The synchronous side (broker.rs
//! `serve_jsonrpc`) keeps owning the wire and every security gate - line
//! caps, parse-error replies, attestation, per-relay rate limiting, and
//! the per-request revocation recheck all run BEFORE a message is handed
//! to [`Connection::handle`] - and this side owns nothing but protocol.
//!
//! The blocking model rests on one LOAD-BEARING invariant: at most one
//! request is in flight per connection, enforced structurally by
//! `handle(&mut self)` inside the serial serve loop. Under it, "send one
//! in, wait for one out" cannot interleave: our handler never originates
//! server-side traffic (no sampling, no subscriptions, no tasks, no
//! progress - `assert_quiescent` and `non_tool_surfaces_stay_refused` in
//! this module's tests pin that an rmcp upgrade does not change this), and
//! a `notifications/cancelled` can never slip
//! between a request and its reply, so rmcp's cancellation path can never
//! swallow a reply we are waiting for. If the service dies instead of
//! answering - an invalid opener, an internal rmcp task failure - its
//! channel ends or its runtime task finishes, and [`Connection::handle`]
//! returns an error: the caller drops the connection, fail closed, never
//! a hang. rmcp (3.1.4+) answers an invalid opener with a descriptive
//! error BEFORE failing the service, so the first non-ping exchange reads
//! the opener verdict before the reply: a refused opener drops with that
//! flushed refusal unread, and a bare probe gets EOF, never a reply
//! confirming the bridge exists.

use std::io;
use std::sync::OnceLock;

use futures::channel::{mpsc, oneshot};
use futures::future::{self, Either};
use futures::{SinkExt, StreamExt};
use rmcp::service::{RoleServer, RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::ServiceExt;

use crate::protocol::JsonRpc;
use crate::session::Session;

use super::handler::BridgeHandler;

/// Channel headroom beyond the single in-flight request the serial loop
/// permits, covering rmcp's opener bookkeeping. The cost of slack is bytes.
const CHANNEL_CAPACITY: usize = 8;

/// The shared tokio runtime the rmcp services run on. Lazy - built on the
/// first connection - and never torn down (it dies with the process). Two
/// worker threads suffice: per-connection protocol work is tiny, and tool
/// execution runs on the runtime's separate blocking pool.
fn runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RT: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcp-rt")
            .enable_time()
            .build()
            .map_err(|e| log_error!("mcp", "cannot start the MCP runtime: {e}"))
            .ok()
    })
    .as_ref()
}

/// One harness connection's MCP protocol engine. See the module docs.
pub struct Connection {
    inbound: mpsc::Sender<RxJsonRpcMessage<RoleServer>>,
    outbound: mpsc::Receiver<TxJsonRpcMessage<RoleServer>>,
    service: Service,
}

/// The service lifecycle. Taken (leaving `Spent`) for every replied-to
/// exchange and restored only on success, so every error path leaves the
/// connection spent - fail closed by construction - and the contradictory
/// combinations (a verdict on an open session, a poll after the end was
/// observed) are unrepresentable.
enum Service {
    /// The opener verdict is pending: `verdict` resolves once rmcp's
    /// serve() accepts the first non-ping request and is canceled (sender
    /// dropped) when it refuses. The first reply is gated on it so rmcp's
    /// pre-init refusal flush (the error reply it writes before failing
    /// the service, rmcp 3.1.4+) stays off the wire.
    Opening {
        verdict: oneshot::Receiver<()>,
        task: tokio::task::JoinHandle<()>,
    },
    /// The opener was served. The task is awaited alongside `outbound` so
    /// a service that dies without replying (however it dies) reads as
    /// end-of-service, never as a wait on a reply that cannot come.
    Open { task: tokio::task::JoinHandle<()> },
    /// The end was observed: the caller was told to drop the connection,
    /// and this instance can never serve again. Holding no `JoinHandle`
    /// here matters - a tokio `JoinHandle` panics if polled again after
    /// completion, a process abort under `panic = "abort"` - so the spent
    /// state is unrepresentable instead of a doc-comment obligation.
    Spent,
}

/// The class of an opener failure, and ONLY the class: rmcp's opener error
/// embeds the whole client frame in its Display/Debug output, which is
/// peer-sized (up to the 64 MB line cap) and may carry page content, so it
/// must never reach stderr (the harness and Chrome persist it).
fn open_failure_class(e: &rmcp::service::ServerInitializeError) -> &'static str {
    use rmcp::service::ServerInitializeError as E;
    match e {
        E::ExpectedInitializeRequest(_) => {
            "the first request was neither initialize nor a valid stateless opener"
        }
        E::ConnectionClosed(_) => "the connection closed during the opener",
        E::UnexpectedInitializeResponse(_) => "unexpected initialize response",
        E::InitializeFailed(_) => "initialize failed",
        E::TransportError { .. } => "transport error during the opener",
        E::Cancelled => "cancelled",
        // ServerInitializeError is non_exhaustive.
        _ => "opener failure",
    }
}

impl Connection {
    /// Spawn the rmcp service for one connection over the shared session.
    /// `Err` (the runtime could not be started) fails the connection closed.
    pub fn open(session: Session) -> io::Result<Connection> {
        let rt = runtime().ok_or_else(|| io::Error::other("MCP runtime unavailable"))?;
        let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (out_tx, out_rx) = mpsc::channel::<TxJsonRpcMessage<RoleServer>>(CHANNEL_CAPACITY);
        let (open_tx, open_rx) = oneshot::channel::<()>();
        let service = rt.spawn(async move {
            // serve() runs the opener exchange (legacy `initialize`, or a
            // stateless 2026-07-28 request carrying its own `_meta`) and
            // resolves without needing further input; an invalid opener
            // ends the service here, with `open_tx` dropped unsent so the
            // sync side refuses before reading the error reply rmcp
            // flushed. Either way, when this task finishes the transport -
            // and with it `out_tx` - drops, which the sync side observes
            // as end-of-service.
            match BridgeHandler::new(session).serve((out_tx, in_rx)).await {
                Ok(running) => {
                    let _ = open_tx.send(());
                    let _ = running.waiting().await;
                }
                Err(e) => {
                    log_warn!(
                        "mcp",
                        "mcp session ended at open: {}",
                        open_failure_class(&e)
                    );
                }
            }
        });
        Ok(Connection {
            inbound: in_tx,
            outbound: out_rx,
            service: Service::Opening {
                verdict: open_rx,
                task: service,
            },
        })
    }

    /// Feed one already-gated inbound message; returns the reply to write
    /// (`None` for notifications), blocking until the service answers.
    /// `Err` means the service is gone and the caller must drop the
    /// connection (fail closed).
    pub fn handle(&mut self, msg: &JsonRpc) -> io::Result<Option<JsonRpc>> {
        // A service observed dead stays dead: the caller was told to drop
        // the connection, and this instance can never serve again.
        if matches!(self.service, Service::Spent) {
            return Err(io::Error::other("mcp service already ended"));
        }
        // Refusals for frames that never reach the service. Only a frame
        // with an id can be answered; a malformed notification is swallowed.
        let invalid = |detail: String| {
            msg.id
                .clone()
                .map(|id| JsonRpc::err(id, -32600, format!("invalid request: {detail}")))
        };
        let inbound = match to_client_message(msg) {
            // It parsed as lax JSON-RPC upstream but is not a well-formed
            // MCP client frame (a fractional id, a missing jsonrpc member).
            Err(e) => return Ok(invalid(e.to_string())),
            Ok(m) => m,
        };
        // Whether a reply will come back is decided by the CONVERTED frame,
        // never by the lax reader's view: rmcp's untagged model can re-type
        // a degenerate request (say, a boolean id) as a notification, and
        // waiting on a reply for one of those would block the serve loop
        // forever. A frame the two layers disagree about is refused here.
        let expects_reply = matches!(inbound, rmcp::model::JsonRpcMessage::Request(_));
        if msg.id.is_some() && !expects_reply {
            return Ok(invalid(
                "a frame carrying an id must be a well-formed request".to_owned(),
            ));
        }
        futures::executor::block_on(self.inbound.send(inbound))
            .map_err(|_| io::Error::other("mcp service ended (inbound channel closed)"))?;
        if !expects_reply {
            return Ok(None);
        }
        // Take the lifecycle, leaving Spent: it is restored only when the
        // whole exchange - reply taken AND validated - succeeds, so every
        // error return below leaves the connection spent without per-arm
        // bookkeeping.
        let wire = match std::mem::replace(&mut self.service, Service::Spent) {
            Service::Spent => return Err(io::Error::other("mcp service already ended")),
            Service::Opening { verdict, task } => self.first_reply(msg, verdict, task)?,
            Service::Open { task } => self.next_reply(msg, task)?,
        };
        Ok(Some(wire))
    }

    /// Take the reply deciding the opener. rmcp (3.1.4+) answers an invalid
    /// opener with a descriptive error BEFORE failing the service, and
    /// delivering it would turn the fail-closed EOF into an oracle
    /// confirming the bridge to unauthenticated probes - so for a non-ping
    /// request the opener verdict is read FIRST (rmcp adjudicates the
    /// opener on the first non-ping frame without needing further input,
    /// so the verdict cannot hang), and a refusal returns `Err` with the
    /// flushed reply left unread. A genuine pre-open ping is answered
    /// WITHOUT resolving the opener (spec-legal), so a ping waits on
    /// reply-or-verdict instead; the only error reply a pre-open ping can
    /// draw is the refusal flush for a frame that names ping but is not
    /// one, so an error there also drops unanswered.
    fn first_reply(
        &mut self,
        msg: &JsonRpc,
        verdict: oneshot::Receiver<()>,
        task: tokio::task::JoinHandle<()>,
    ) -> io::Result<JsonRpc> {
        let refused =
            || io::Error::other("mcp service refused the opener (drop the connection unanswered)");
        if msg.method.as_deref() != Some("ping") {
            return match futures::executor::block_on(verdict) {
                Ok(()) => self.next_reply(msg, task),
                Err(oneshot::Canceled) => Err(refused()),
            };
        }
        match futures::executor::block_on(future::select(self.outbound.next(), verdict)) {
            Either::Left((Some(reply), verdict)) => {
                if matches!(reply, rmcp::model::JsonRpcMessage::Error(_)) {
                    return Err(refused());
                }
                let wire = check_reply(&reply, msg)?;
                // Still pre-open: a ping does not open the session.
                self.service = Service::Opening { verdict, task };
                Ok(wire)
            }
            Either::Left((None, _)) => Err(io::Error::other("mcp service ended without replying")),
            Either::Right((Ok(()), _)) => self.next_reply(msg, task),
            Either::Right((Err(oneshot::Canceled), _)) => Err(refused()),
        }
    }

    /// Take and validate the reply for one in-flight request on an open
    /// session; `Err` leaves the connection spent.
    fn next_reply(
        &mut self,
        msg: &JsonRpc,
        mut task: tokio::task::JoinHandle<()>,
    ) -> io::Result<JsonRpc> {
        // Wait on the reply AND on the service task: a service that dies
        // without replying (an rmcp-internal task failure, an opener error)
        // must read as end-of-service, not as a wait forever. select polls
        // the reply side first, so a reply already buffered when the service
        // exits is still delivered.
        let outcome = futures::executor::block_on(future::select(self.outbound.next(), &mut task));
        match outcome {
            Either::Left((Some(reply), _)) => {
                let wire = check_reply(&reply, msg)?;
                self.service = Service::Open { task };
                Ok(wire)
            }
            Either::Left((None, _)) => {
                // The transport is gone, so the service is finished or about
                // to be; stay spent on this path too rather than relying on
                // rmcp dropping both channel ends together.
                Err(io::Error::other("mcp service ended without replying"))
            }
            Either::Right((_, _)) => {
                // The JoinHandle has yielded; dropping it here (staying
                // Spent) guarantees it is never polled again.
                Err(io::Error::other("mcp service died mid-request"))
            }
        }
    }
}

/// Validate one outbound message as THE reply to `msg` and re-type it for
/// the wire. Only a reply may cross: rmcp's outbound side can also carry
/// server-originated requests and notifications, and writing one where a
/// response belongs would desynchronize the harness. This handler never
/// originates any (the quiescence tests pin it), so anything else is an
/// rmcp behavior change - fail closed rather than desync.
fn check_reply(reply: &TxJsonRpcMessage<RoleServer>, msg: &JsonRpc) -> io::Result<JsonRpc> {
    use rmcp::model::JsonRpcMessage as M;
    if !matches!(reply, M::Response(_) | M::Error(_)) {
        return Err(io::Error::other(
            "mcp service emitted non-reply traffic mid-request",
        ));
    }
    let wire = to_wire(reply)?;
    if wire.id != msg.id {
        return Err(io::Error::other("mcp reply id does not match the request"));
    }
    Ok(wire)
}

/// Re-type one lax inbound frame as rmcp's client message.
fn to_client_message(msg: &JsonRpc) -> serde_json::Result<RxJsonRpcMessage<RoleServer>> {
    serde_json::to_value(msg).and_then(serde_json::from_value)
}

/// Re-type one rmcp reply as the wire frame the serve loop writes.
fn to_wire(reply: &TxJsonRpcMessage<RoleServer>) -> io::Result<JsonRpc> {
    serde_json::to_value(reply)
        .and_then(serde_json::from_value)
        .map_err(|e| io::Error::other(format!("mcp reply could not be reserialized: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn frame(raw: Value) -> JsonRpc {
        serde_json::from_value(raw).unwrap()
    }

    fn request(conn: &mut Connection, raw: Value) -> JsonRpc {
        let reply = conn
            .handle(&frame(raw))
            .expect("service alive")
            .expect("requests get replies");
        assert_quiescent(conn);
        reply
    }

    /// Pin the one-reply-per-request invariant the blocking seam rests on:
    /// after a reply is taken, nothing else may be pending outbound. An rmcp
    /// upgrade that starts emitting unsolicited server->client traffic for
    /// this handler fails here instead of desynchronizing the wire.
    fn assert_quiescent(conn: &mut Connection) {
        assert!(
            matches!(conn.outbound.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "unsolicited outbound message, or a dead service, after a completed exchange"
        );
    }

    fn open() -> Connection {
        Connection::open(Session::new()).unwrap()
    }

    /// A stateless request's `_meta`: the 2026-07-28 lifecycle requires the
    /// protocol version AND the client capabilities on every request.
    fn stateless_meta(version: &str) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    /// The pre-2026 opener: initialize negotiates the requested legacy
    /// revision and the reply carries our identity.
    #[test]
    fn legacy_initialize_negotiates_the_requested_revision() {
        // 2025-11-25 is the real-world canary: Claude Code 2.1.226 opens
        // with it. rmcp echoes any supported LEGACY requested revision
        // (2026-07-28+ has no initialize handshake and negotiates down to
        // the newest legacy one). The string
        // request id (spec-legal, rarer than numeric) also exercises the
        // seam's reply-id equality check on the non-numeric arm.
        for requested in ["2025-06-18", "2025-11-25"] {
            let mut conn = open();
            let reply = request(
                &mut conn,
                json!({
                    "jsonrpc": "2.0", "id": "open-1", "method": "initialize",
                    "params": {
                        "protocolVersion": requested,
                        "capabilities": {},
                        "clientInfo": { "name": "test-harness", "version": "0" },
                    }
                }),
            );
            assert_eq!(reply.id, Some(json!("open-1")));
            let result = reply.result.unwrap();
            assert_eq!(result["protocolVersion"], json!(requested));
        }

        let mut conn = open();
        let reply = request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test-harness", "version": "0" },
                }
            }),
        );
        let result = reply.result.unwrap();
        assert_eq!(result["protocolVersion"], json!("2025-06-18"));
        assert_eq!(result["serverInfo"]["name"], json!("chromium-bridge"));
        assert_eq!(
            result["serverInfo"]["version"],
            json!(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(result["capabilities"]["tools"], json!({}));

        // notifications/initialized is swallowed: no reply.
        let none = conn
            .handle(&frame(json!({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            })))
            .unwrap();
        assert!(none.is_none());

        // Legacy tools/list serves the catalogue in the exact pre-migration
        // shape: no resultType (rmcp strips it for pre-2026 peers) and none
        // of the 2026-07-28 cache hints (the handler omits them for peers
        // below that revision).
        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        );
        let result = reply.result.unwrap();
        assert!(!result["tools"].as_array().unwrap().is_empty());
        for absent in ["resultType", "ttlMs", "cacheScope", "_meta"] {
            assert!(
                result.get(absent).is_none(),
                "legacy tools/list must not carry {absent}"
            );
        }

        // Legacy ping still answers.
        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" }),
        );
        assert_eq!(reply.result, Some(json!({})));
    }

    /// The 2026-07-28 opener: a server/discover probe carrying its own
    /// `_meta`, no initialize.
    #[test]
    fn a_discover_opener_is_served_statelessly() {
        let mut conn = open();
        let reply = request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "_meta": stateless_meta("2026-07-28") }
            }),
        );
        let result = reply.result.unwrap();
        assert_eq!(result["resultType"], json!("complete"));
        assert_eq!(result["cacheScope"], json!("private"));
        assert_eq!(
            result["ttlMs"],
            json!(crate::protocol::MCP_CACHE_TTL_MS),
            "our cache hint must survive the SDK default"
        );
        let versions = result["supportedVersions"].as_array().unwrap();
        assert!(versions.contains(&json!(crate::protocol::MCP_PROTOCOL_VERSION)));
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            json!("chromium-bridge")
        );

        // Subsequent stateless requests carry their own _meta and get the
        // modern shapes: resultType plus our cache hints on tools/list.
        let reply = request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                "params": { "_meta": stateless_meta("2026-07-28") }
            }),
        );
        let result = reply.result.unwrap();
        assert_eq!(result["resultType"], json!("complete"));
        assert_eq!(result["ttlMs"], json!(crate::protocol::MCP_CACHE_TTL_MS));
        assert_eq!(result["cacheScope"], json!("private"));
        assert!(!result["tools"].as_array().unwrap().is_empty());
    }

    /// A claimed revision outside the supported set is refused with the
    /// spec's -32022 and never served.
    #[test]
    fn an_unsupported_version_claim_is_refused_with_32022() {
        let mut conn = open();
        // Open legitimately first so the refusal below is a per-request
        // verdict, not an opener failure.
        request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "_meta": stateless_meta("2026-07-28") }
            }),
        );
        let reply = request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                "params": { "_meta": stateless_meta("1999-01-01") }
            }),
        );
        let err = reply.error.unwrap();
        assert_eq!(err.code, -32022);
        let data = err.data.unwrap();
        assert_eq!(data["requested"], json!("1999-01-01"));
        assert!(data["supported"]
            .as_array()
            .unwrap()
            .contains(&json!(crate::protocol::MCP_PROTOCOL_VERSION)));

        // The version gate runs BEFORE metadata completeness, so the claim
        // is refused even without clientCapabilities; and rmcp echoes the
        // claimed junk VERBATIM in data.requested with no size bound - the
        // only cap is the serve loop's 64 MB line limit. Documented residual
        // reflection risk (1:1, not amplifying); if rmcp starts bounding the
        // echo, this assertion fails and the risk note can be retired.
        let junk = "x".repeat(64 * 1024);
        let reply = request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": junk,
                } }
            }),
        );
        let err = reply.error.unwrap();
        assert_eq!(err.code, -32022);
        assert_eq!(err.data.unwrap()["requested"], json!(junk));
    }

    /// How rmcp adjudicates the request-metadata edge cases our original
    /// design and the black-box suites guessed at differently. These pin the
    /// ACTUALS (what the SDK does); the suites reconcile to them.
    #[test]
    fn request_metadata_edge_cases_follow_rmcp_not_our_old_design() {
        let mut conn = open();
        request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "_meta": stateless_meta("2026-07-28") }
            }),
        );

        // In a stateless session, incomplete metadata is -32602 (invalid
        // params), NOT -32022 and NOT the legacy shim: a NON-STRING version
        // claim (decodes as missing), an EMPTY _meta, a protocolVersion-only
        // _meta, and a missing _meta all land there.
        for (id, meta) in [
            (
                2,
                json!({ "io.modelcontextprotocol/protocolVersion": 7,
                        "io.modelcontextprotocol/clientCapabilities": {} }),
            ),
            (3, json!({})),
            (
                4,
                json!({ "io.modelcontextprotocol/protocolVersion": "2026-07-28" }),
            ),
        ] {
            let reply = request(
                &mut conn,
                json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list",
                        "params": { "_meta": meta } }),
            );
            let err = reply.error.unwrap();
            assert_eq!(err.code, -32602, "request {id} must be invalid params");
        }
        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }),
        );
        assert_eq!(reply.error.unwrap().code, -32602);
    }

    /// server/discover has no bare-request form in rmcp - there is no
    /// bare-discover exemption (our original hand-rolled design had one; the
    /// SDK wins), even inside a legacy-negotiated session. The refusal code
    /// depends on how far the frame parses: with no `params` at all the
    /// frame does not parse as a discover request (it demotes to rmcp's
    /// custom-request catch-all, -32601); with `params` present but the
    /// required metadata missing it is invalid params (-32602).
    #[test]
    fn discover_requires_metadata_even_in_a_legacy_session() {
        let mut conn = open();
        request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": { "name": "t", "version": "0" } }
            }),
        );
        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "server/discover" }),
        );
        assert_eq!(reply.error.unwrap().code, -32601);

        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 3, "method": "server/discover", "params": {} }),
        );
        assert_eq!(reply.error.unwrap().code, -32602);
    }

    /// A first request that is neither initialize nor a valid stateless
    /// opener ends the service; the caller sees end-of-service - never the
    /// descriptive -32602 refusal rmcp (3.1.4+) flushes before failing,
    /// which the opener gate keeps off the wire - not a hang.
    #[test]
    fn an_invalid_opener_fails_the_connection_closed() {
        let mut conn = open();
        let outcome = conn.handle(&frame(json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list"
        })));
        assert!(outcome.is_err(), "expected end-of-service, got {outcome:?}");
    }

    /// The spec permits ping before the opener: rmcp answers it without
    /// opening the session, so the ping reply passes the opener gate - and
    /// a bare opener afterwards still drops, fail closed.
    #[test]
    fn a_pre_open_ping_is_answered_without_opening() {
        let mut conn = open();
        let reply = request(
            &mut conn,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
        );
        assert_eq!(reply.result, Some(json!({})));
        let outcome = conn.handle(&frame(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list"
        })));
        assert!(
            outcome.is_err(),
            "a bare opener after a pre-open ping must still drop, got {outcome:?}"
        );
    }

    /// A frame whose id rmcp's model cannot represent (boolean) would be
    /// silently re-typed as a notification by the untagged wire enum; the
    /// seam refuses it as INVALID_REQUEST instead, so the serve loop can
    /// never end up waiting for a reply that will not come.
    #[test]
    fn a_boolean_id_frame_is_refused_as_invalid_request() {
        let mut conn = open();
        let reply = conn
            .handle(&frame(json!({
                "jsonrpc": "2.0", "id": true, "method": "tools/list"
            })))
            .unwrap()
            .unwrap();
        assert_eq!(reply.id, Some(json!(true)));
        assert_eq!(reply.error.unwrap().code, -32600);
    }

    /// An `id: null` frame counts as a notification at the lax layer (the
    /// pre-rmcp dispatcher swallowed it the same way): no reply. As the
    /// connection's FIRST frame it is also an invalid opener, so the rmcp
    /// service ends behind the swallowed frame and the next request reads
    /// end-of-service: the caller drops the connection, fail closed. (Until
    /// that next frame arrives the dead service just idles - the same
    /// resource profile as a live idle connection.)
    #[test]
    fn a_null_id_frame_is_swallowed_like_a_notification() {
        let mut conn = open();
        let none = conn
            .handle(&frame(json!({
                "jsonrpc": "2.0", "id": null, "method": "tools/list"
            })))
            .unwrap();
        assert!(none.is_none());
        let followup = conn.handle(&frame(json!({
            "jsonrpc": "2.0", "id": 2, "method": "server/discover",
            "params": { "_meta": stateless_meta("2026-07-28") }
        })));
        assert!(
            followup.is_err(),
            "the notification opener killed the service; the next request \
             must read end-of-service, got {followup:?}"
        );
        // And a spent connection STAYS spent - no abort, no revival.
        assert!(conn
            .handle(&frame(json!({
                "jsonrpc": "2.0", "id": 3, "method": "ping"
            })))
            .is_err());
    }

    /// The spent-state short-circuit itself: once `Spent` (as every failed
    /// exchange leaves it), handle() must refuse immediately - never touch
    /// the channels, and with no JoinHandle held there is nothing to
    /// re-poll (a re-poll of a yielded handle would abort the process
    /// under this workspace's panic = "abort").
    #[test]
    fn a_spent_connection_refuses_without_touching_the_service() {
        let mut conn = open();
        conn.service = Service::Spent;
        assert!(conn
            .handle(&frame(json!({
                "jsonrpc": "2.0", "id": 1, "method": "ping"
            })))
            .is_err());
    }

    /// Everything that is not the tools surface stays refused: the
    /// subscription and task methods (which could otherwise register
    /// server-originated traffic and break the one-reply pairing) and the
    /// prompt/resource/completion listings rmcp would answer with empty
    /// successes by default.
    #[test]
    fn non_tool_surfaces_stay_refused() {
        let mut conn = open();
        request(
            &mut conn,
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                "params": { "_meta": stateless_meta("2026-07-28") }
            }),
        );
        for (id, method, params) in [
            (2, "subscriptions/listen", json!({ "notifications": {} })),
            (3, "tasks/get", json!({ "taskId": "t1" })),
            (4, "resources/subscribe", json!({ "uri": "x://y" })),
            (5, "prompts/list", json!({})),
            (6, "resources/list", json!({})),
            (7, "resources/templates/list", json!({})),
            (
                8,
                "completion/complete",
                json!({ "ref": { "type": "ref/prompt", "name": "p" }, "argument": { "name": "a", "value": "v" } }),
            ),
        ] {
            let mut full = params;
            full.as_object_mut()
                .unwrap()
                .insert("_meta".into(), stateless_meta("2026-07-28"));
            let reply = request(
                &mut conn,
                json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": full }),
            );
            assert!(
                reply.error.is_some(),
                "{method} must be refused, got {:?}",
                reply.result
            );
        }
    }
}
