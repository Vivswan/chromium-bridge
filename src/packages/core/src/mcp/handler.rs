//! The rmcp [`ServerHandler`]: genkan's tool surface on the SDK's
//! protocol engine.
//!
//! rmcp owns the protocol semantics (lifecycle, version gate, `-32022`,
//! method-not-found, envelope stamping); this handler owns what is genuinely
//! ours: the tool catalogue and the guarded execution path every tool call
//! must take - the global kill switch, the audit record, and the
//! single-parse routing of `route_and_dispatch`.

use std::sync::{Arc, OnceLock};

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    DiscoverResult, Implementation, JsonObject, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ServerCapabilities, ServerConfig, Tool as McpTool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};

use crate::error::CallError;
use crate::protocol::MCP_CACHE_TTL_MS;
use crate::session::Session;
use crate::tools::{self, Tool, ToolCall};

/// The server implementation identity advertised where the protocol carries
/// it: the legacy `initialize` result's `serverInfo` and the modern
/// `server/discover` result's `_meta` (discover-only: other results carry no
/// identity, a known gap against the spec's SHOULD).
fn implementation() -> Implementation {
    Implementation::new("genkan", env!("CARGO_PKG_VERSION"))
}

/// The catalogue in rmcp's tool model, in [`tools::all`]'s static order
/// (deterministic, so clients may cache the list). Built once and shared:
/// the catalogue is immutable per binary.
fn shared_tools() -> Arc<[McpTool]> {
    static TOOLS: OnceLock<Arc<[McpTool]>> = OnceLock::new();
    Arc::clone(TOOLS.get_or_init(|| {
        tools::all()
            .map(|t| McpTool::new(t.name, t.description, t.input_schema()))
            .collect()
    }))
}

/// Whether this request's claimed (or legacy-negotiated) revision speaks the
/// 2026-07-28 result vocabulary - the same comparison rmcp itself uses to
/// strip `resultType` for older peers, so both halves of the result shape
/// stay in step: modern peers get `resultType` + cache hints, pre-2026 peers
/// get the exact pre-migration shape.
fn speaks_2026(context: &RequestContext<RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|v| v.as_str() >= ProtocolVersion::V_2026_07_28.as_str())
}

/// The `tools/list` result: the full catalogue, plus the 2026-07-28 cache
/// hints (SEP-2549) when the peer's revision knows that vocabulary.
fn tools_list_result(tools: &[McpTool], cacheable: bool) -> ListToolsResult {
    let result = ListToolsResult::with_all_items(tools.to_vec());
    if cacheable {
        result
            .with_ttl_ms(MCP_CACHE_TTL_MS)
            .with_cache_scope(CacheScope::Private)
    } else {
        result
    }
}

/// One finished tool call in rmcp's result model. Tool and validation
/// failures stay `isError: true` results carrying the stable taxonomy codes
/// of [`crate::error::ERROR_SPECS`] - never JSON-RPC protocol errors.
fn call_tool_result(out: &tools::Outcome) -> CallToolResult {
    // The fallback cannot fire for blocks we build ourselves; it exists because this layer never panics.
    let blocks: Vec<ContentBlock> = serde_json::from_value(out.content().clone())
        .unwrap_or_else(|_| vec![ContentBlock::text(out.content().to_string())]);
    if out.is_error() {
        CallToolResult::error(blocks)
    } else {
        CallToolResult::success(blocks)
    }
}

/// genkan as an rmcp server. One instance per harness connection
/// (cheap: [`Session`] is all-`Arc`, the catalogue is shared), created by
/// [`super::connection::Connection::open`].
#[derive(Clone)]
pub(crate) struct BridgeHandler {
    session: Session,
    tools: Arc<[McpTool]>,
}

impl BridgeHandler {
    pub(crate) fn new(session: Session) -> Self {
        BridgeHandler {
            session,
            tools: shared_tools(),
        }
    }
}

impl ServerHandler for BridgeHandler {
    /// Advertised identity and capabilities. `protocol_version` here is
    /// only the legacy `initialize` fallback seed: rmcp (3.2+) echoes a
    /// supported LEGACY requested revision and answers a modern
    /// (2026-07-28+, which has no initialize handshake) or unknown claim
    /// with the newest supported legacy revision - this value, being
    /// modern, defers to that computed fallback.
    /// The supported set stays rmcp's default - every revision the SDK
    /// implements - on purpose: pre-2026 harnesses keep negotiating their
    /// own revision via `initialize` until they migrate.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(rmcp::model::ProtocolVersion::V_2026_07_28)
            .with_server_info(implementation())
    }

    /// `server/discover` (the 2026-07-28 probe), with our cache hint on top
    /// of the SDK default (which advertises the supported revisions, the
    /// capabilities, and the server identity `_meta`).
    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, McpError> {
        Ok(DiscoverResult::from_server_info(
            ServerHandler::supported_protocol_versions(self).into_owned(),
            self.get_info(),
        )
        .with_ttl_ms(MCP_CACHE_TTL_MS))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(tools_list_result(&self.tools, speaks_2026(&context)))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        // Absent arguments are an empty object: a tool whose args are all
        // optional runs, one with a required arg refuses on the missing field.
        let args = request.arguments.unwrap_or_default();
        let session = self.session.clone();
        // Tool work blocks (bridge round-trips, up to the 12s connect wait),
        // so it runs on the blocking pool, keeping the protocol threads free.
        let outcome = tokio::task::spawn_blocking(move || execute_tool_call(&session, &name, args))
            .await
            .map_err(|e| {
                McpError::internal_error(format!("tool execution task failed: {e}"), None)
            })?;
        Ok(CallToolResponse::Complete(call_tool_result(&outcome)))
    }

    // The bridge serves TOOLS ONLY. rmcp's defaults answer the prompt,
    // resource, and completion listing methods with empty successes; the
    // fail-closed posture (and the pre-rmcp behavior) is refusing methods
    // the advertised capabilities do not include.

    async fn complete(
        &self,
        _request: rmcp::model::CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CompleteResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::CompleteRequestMethod,
        >())
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ListPromptsRequestMethod,
        >())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ListResourcesRequestMethod,
        >())
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, McpError> {
        Err(McpError::method_not_found::<
            rmcp::model::ListResourceTemplatesRequestMethod,
        >())
    }
}

/// Execute one tool call against the shared session: the boundary parse, the
/// kill-switch gate, the policy gate, the audit record, and the dispatch.
/// Serves every harness (the broker's own stdio harness and all relays route
/// here through their per-connection rmcp services).
fn execute_tool_call(session: &Session, name: &str, args: JsonObject) -> tools::Outcome {
    let req_id = next_request_id();
    let started = std::time::Instant::now();
    // The global kill switch gates EVERY tool call before any routing or bridge traffic, failing
    // closed on an engaged switch AND on an unreadable record; the harness connection stays up so
    // the typed refusal is delivered. The host-side policy gate runs alongside it: defense in depth
    // for the honest-host path, an unreadable store denying all.
    //   deadline unrepresentable (Instant near its bound) -> `started` itself: the call times out at once
    let (route, out) = route_and_dispatch(
        session,
        ToolCall::parse(name, args),
        crate::kill::check(),
        crate::policy::gating::check,
        started.checked_add(tools::CALL_BUDGET).unwrap_or(started),
    );
    let mut rec = crate::audit::AuditRecord::new(crate::audit::AuditKind::ToolCall);
    rec.req = Some(req_id);
    rec.conn = route.as_ref().map(|(_, g)| *g);
    rec.name = route.as_ref().map(|(l, _)| l.clone());
    rec.tool = Some(name.to_string());
    rec.outcome = Some(if out.is_error() { "error" } else { "ok" }.to_string());
    rec.code = out.error_code().map(str::to_string);
    rec.dur_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    crate::audit::record(rec);
    out
}

/// A monotonic per-call request id, used to correlate audit lines with the
/// tool invocation they describe. Process-wide; starts at 1.
fn next_request_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Route and dispatch one tool call from its SINGLE boundary parse: the audit route and the dispatch both consume
/// that one [`ToolCall`], so the trail can never record a default route for a call the parse refused. The kill
/// verdict arrives computed and the policy gate injected so the fail-closed matrix is unit-testable without the
/// runtime directory or the audit sink (both live in [`execute_tool_call`]). `deadline` is the call's whole
/// budget; the dispatch hands it to the session, which cancels the browser op when it passes.
///
/// ```text
/// route re-read after the dispatch -> a host may connect during the call's startup wait
/// kill, then parse, then policy    -> the kill switch is the global brake, so it wins over every other refusal;
///                                     the policy gate needs the parsed tool, so it runs after the parse
/// ```
fn route_and_dispatch(
    session: &Session,
    call: Result<ToolCall, CallError>,
    kill: Result<(), CallError>,
    policy: impl FnOnce(&Tool) -> Result<(), CallError>,
    deadline: std::time::Instant,
) -> (Option<(String, u64)>, tools::Outcome) {
    let addressed: Option<Option<String>> =
        call.as_ref().ok().map(|c| c.browser().map(str::to_owned));
    let route_now = || {
        addressed
            .as_ref()
            .and_then(|browser| session.route_info(browser.as_deref()))
    };
    let route = route_now();
    let out = match kill {
        Err(e) => tools::error_outcome(&e),
        Ok(()) => match call {
            Err(e) => tools::error_outcome(&e),
            Ok(call) => match policy(&call.tool()) {
                Err(e) => tools::error_outcome(&e),
                Ok(()) => tools::dispatch(session, call, deadline),
            },
        },
    };
    let route = route.or_else(route_now);
    (route, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_version_pin_matches_the_newest_revision_rmcp_serves() {
        // The repo-wide pin (protocol.rs, carried into the generated TS and
        // the docs gates) must be exactly the newest revision the SDK
        // implements and advertises; a silent rmcp upgrade that moves the
        // wire fails here instead of drifting past the docs.
        assert_eq!(
            ProtocolVersion::V_2026_07_28.as_str(),
            crate::protocol::MCP_PROTOCOL_VERSION
        );
        let newest = ProtocolVersion::KNOWN_VERSIONS
            .iter()
            .max_by(|a, b| a.as_str().cmp(b.as_str()))
            .map(ProtocolVersion::as_str);
        assert_eq!(newest, Some(crate::protocol::MCP_PROTOCOL_VERSION));
        // The legacy revision our pre-2026 harnesses negotiate stays served.
        assert!(ProtocolVersion::KNOWN_VERSIONS
            .iter()
            .any(|v| v.as_str() == "2025-06-18"));
    }

    #[test]
    fn the_meta_key_consts_match_what_rmcp_reads_and_writes() {
        // protocol.rs's key consts feed the generated TS contract; each must
        // be exactly the key rmcp enforces on requests and stamps on
        // results, or the single-sourcing is a lie.
        use rmcp::model::{ClientCapabilities, RequestMetaObject};
        let mut meta = RequestMetaObject::default();
        meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
        meta.set_client_capabilities(ClientCapabilities::default());
        let v = serde_json::to_value(&meta).unwrap();
        let keys = v.as_object().unwrap();
        assert!(keys.contains_key(crate::protocol::MCP_META_PROTOCOL_VERSION));
        assert!(keys.contains_key(crate::protocol::MCP_META_CLIENT_CAPABILITIES));

        let discover = DiscoverResult::from_server_info(
            vec![ProtocolVersion::V_2026_07_28],
            ServerConfig::new(ServerCapabilities::default()),
        );
        let v = serde_json::to_value(&discover).unwrap();
        assert!(v["_meta"]
            .as_object()
            .unwrap()
            .contains_key(crate::protocol::MCP_META_SERVER_INFO));
    }

    #[test]
    fn the_catalogue_maps_in_static_order_with_schemas() {
        // rmcp's Tool model is the external side of this mapping: an SDK
        // upgrade that normalizes or reorders what it is given fails here.
        let mapped = shared_tools();
        let catalogue: Vec<Tool> = tools::all().collect();
        assert_eq!(mapped.len(), catalogue.len());
        for (m, t) in mapped.iter().zip(catalogue.iter()) {
            assert_eq!(m.name, t.name);
            assert_eq!(m.description.as_deref(), Some(t.description));
            assert_eq!(
                *m.input_schema,
                t.input_schema(),
                "schema for {} must survive the mapping",
                t.name
            );
        }
    }

    #[test]
    fn tools_list_carries_the_cache_hints_only_for_2026_peers() {
        let modern = tools_list_result(&shared_tools(), true);
        assert_eq!(modern.ttl_ms, Some(crate::protocol::MCP_CACHE_TTL_MS));
        assert_eq!(modern.cache_scope, Some(CacheScope::Private));
        assert!(!modern.tools.is_empty());

        // A pre-2026 peer gets the exact pre-migration shape: the hints are
        // 2026-07-28 vocabulary (SEP-2549) and stay off the legacy wire.
        let legacy = tools_list_result(&shared_tools(), false);
        assert_eq!(legacy.ttl_ms, None);
        assert_eq!(legacy.cache_scope, None);
    }

    #[test]
    fn call_tool_result_keeps_each_outcome_class_and_content_block() {
        // rmcp's content model is the external side: an outcome's blocks must reach the client typed (an
        // image stays an image, never the stringified fallback) and tool failures stay isError results,
        // never protocol errors.
        enum Kind {
            Text,
            Image,
        }
        let cases = [
            (
                "success text",
                tools::Outcome::Success {
                    content: json!([{ "type": "text", "text": "{\"tabs\":[]}" }]),
                },
                false,
                Kind::Text,
            ),
            (
                "success image",
                tools::Outcome::Success {
                    content: json!([{ "type": "image", "data": "aGk=", "mimeType": "image/png" }]),
                },
                false,
                Kind::Image,
            ),
            (
                "error",
                tools::Outcome::Error {
                    content: json!([{ "type": "text", "text": "Error [BRIDGE_KILLED]: killed" }]),
                    code: "BRIDGE_KILLED",
                },
                true,
                Kind::Text,
            ),
        ];
        for (case, out, is_error, kind) in cases {
            let result = call_tool_result(&out);
            assert_eq!(result.is_error, Some(is_error), "{case}");
            assert_eq!(
                serde_json::to_value(&result.content).unwrap(),
                *out.content(),
                "{case}: the blocks must survive typed"
            );
            let typed = match kind {
                Kind::Text => matches!(result.content[0], ContentBlock::Text(_)),
                Kind::Image => matches!(result.content[0], ContentBlock::Image(_)),
            };
            assert!(typed, "{case}: the first block must keep its kind");
        }
    }

    fn call(name: &str, args: serde_json::Value) -> Result<ToolCall, CallError> {
        ToolCall::parse(name, serde_json::from_value(args).unwrap())
    }

    /// The deadline execute_tool_call hands every dispatch.
    fn budget() -> std::time::Instant {
        std::time::Instant::now() + tools::CALL_BUDGET
    }

    #[test]
    fn a_refused_parse_is_typed_and_skips_dispatch() {
        // A malformed `browser`, an unknown tool, and args outside the struct
        // are each refused by the one boundary parse with the stable
        // INVALID_ARGUMENT code, with no routing attempted (a fresh session
        // would otherwise block in the 12s startup wait - this test finishing
        // quickly is itself the assertion).
        let session = Session::new();
        for (name, args) in [
            ("tab_list", json!({ "browser": 123 })),
            ("no_such_tool", json!({})),
            ("tab_focus", json!({})),
            ("tab_list", json!({ "junk": 1 })),
        ] {
            let (_route, out) = route_and_dispatch(
                &session,
                call(name, args.clone()),
                Ok(()),
                |_| Ok(()),
                budget(),
            );
            assert!(out.is_error(), "{name} {args}");
            assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"), "{name} {args}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_refused_parse_records_no_route_even_with_a_browser_connected() {
        // The single-parse guard, non-vacuously: with a live connection, a
        // lax read would resolve the sole browser and stamp a route onto the
        // audit line of a call then refused. The one parse feeds routing and
        // dispatch from ONE result, so the refused call records no route.
        use std::io::{BufReader, BufWriter};
        use std::os::unix::net::UnixStream;

        let session = Session::new();
        let (srv, _cli) = UnixStream::pair().unwrap();
        let reader = BufReader::new(srv.try_clone().unwrap());
        let writer = BufWriter::new(srv);
        let label = crate::ipc::BrowserLabel::parse("chrome").unwrap();
        assert!(session.attach_browser(label, reader, writer));

        let (route, out) = route_and_dispatch(
            &session,
            call("tab_list", json!({ "browser": 123 })),
            Ok(()),
            |_| Ok(()),
            budget(),
        );
        assert_eq!(route, None, "a refused parse must not invent a route");
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"));

        // Control: the same session does route a well-formed call that a
        // later gate refuses (captured pre-dispatch from the same parse).
        let (route, out) = route_and_dispatch(
            &session,
            call("tab_list", json!({ "browser": "chrome" })),
            Ok(()),
            |_| Err(CallError::Killed),
            budget(),
        );
        assert_eq!(route.map(|(l, _)| l), Some("chrome".to_string()));
        assert!(out.is_error());
    }

    #[test]
    fn a_kill_refusal_is_typed_and_skips_dispatch() {
        // While killed, dispatch never runs: with an empty session a
        // dispatched tab_list would park in the 12s connect wait, so this
        // test finishing quickly is the assertion that the kill verdict
        // short-circuited it, and the refusal reaches the caller as the
        // typed BRIDGE_KILLED outcome. No claim is made about the route -
        // it is captured before the verdict on purpose (best-effort audit
        // diagnostics, unchanged from before this refactor).
        let session = Session::new();
        let (_route, out) = route_and_dispatch(
            &session,
            call("tab_list", json!({})),
            Err(CallError::Killed),
            |_| Ok(()),
            budget(),
        );
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("BRIDGE_KILLED"));
    }

    #[test]
    fn a_policy_refusal_is_typed_and_skips_dispatch() {
        // The host policy gate short-circuits dispatch exactly as the kill
        // verdict does: with an empty session a dispatched tab_list would park
        // in the 12s connect wait, so this test finishing quickly is the
        // assertion that the injected policy refusal skipped it, and the
        // refusal reaches the caller as the typed TOOL_DISABLED outcome. The
        // gate verdict itself (which tools, which stores) is unit-tested in
        // policy::gating; here only the injection seam is under test.
        let session = Session::new();
        let (_route, out) = route_and_dispatch(
            &session,
            call("page_eval", json!({ "code": "1" })),
            Ok(()),
            |tool| {
                Err(CallError::ToolDisabled {
                    tool: tool.name.into(),
                    reason: crate::error::ToolDisabledReason::GrantOff("pageEvalEnabled"),
                })
            },
            budget(),
        );
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("TOOL_DISABLED"));
    }
}
