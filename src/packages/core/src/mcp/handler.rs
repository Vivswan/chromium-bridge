//! The rmcp [`ServerHandler`]: chromium-bridge's tool surface on the SDK's
//! protocol engine.
//!
//! rmcp owns the protocol semantics (lifecycle, version gate, `-32022`,
//! method-not-found, envelope stamping); this handler owns what is genuinely
//! ours: the tool catalogue and the guarded execution path every tool call
//! must take - the global kill switch (ADR-0030), the audit record, and the
//! single-parse routing of `route_and_dispatch`.

use std::sync::{Arc, OnceLock};

use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    DiscoverResult, Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
    ServerCapabilities, ServerInfo, Tool as McpTool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::Value;

use crate::protocol::MCP_CACHE_TTL_MS;
use crate::session::Session;
use crate::tools;

/// The server implementation identity advertised where the protocol carries
/// it: the legacy `initialize` result's `serverInfo` and the modern
/// `server/discover` result's `_meta` (discover-only; ADR-0034 records the
/// SHOULD-gap on other results).
fn implementation() -> Implementation {
    Implementation::new("chromium-bridge", env!("CARGO_PKG_VERSION"))
}

/// The catalogue in rmcp's tool model, in [`tools::all`]'s static order
/// (deterministic, so clients may cache the list). Built once and shared:
/// the catalogue is immutable per binary.
fn shared_tools() -> Arc<[McpTool]> {
    static TOOLS: OnceLock<Arc<[McpTool]>> = OnceLock::new();
    Arc::clone(TOOLS.get_or_init(|| {
        tools::all()
            .iter()
            .map(|t| McpTool::new(t.name, t.description, t.input_schema.clone()))
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
    // The outcome's content is already MCP content blocks (built by
    // tools::dispatch); re-typing through rmcp's model validates the shape.
    // The fallback cannot fire for blocks we build ourselves and exists only
    // because this layer never panics: it degrades to the raw JSON as one
    // text block, losing formatting but no information.
    let blocks: Vec<ContentBlock> = serde_json::from_value(out.content().clone())
        .unwrap_or_else(|_| vec![ContentBlock::text(out.content().to_string())]);
    if out.is_error() {
        CallToolResult::error(blocks)
    } else {
        CallToolResult::success(blocks)
    }
}

/// chromium-bridge as an rmcp server. One instance per harness connection
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
    /// only the legacy `initialize` fallback when a client requests a
    /// revision outside [`ServerHandler::supported_protocol_versions`];
    /// a supported requested revision is echoed back (rmcp negotiates).
    /// The supported set stays rmcp's default - every revision the SDK
    /// implements - on purpose: pre-2026 harnesses keep negotiating their
    /// own revision via `initialize` until they migrate (ADR-0034 records
    /// the compatibility decision).
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
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
        // Absent arguments dispatch as Null, exactly as the pre-rmcp server
        // read them; each tool's builder decides what shapes it accepts.
        let args = request.arguments.map(Value::Object).unwrap_or(Value::Null);
        let session = self.session.clone();
        // Tool work blocks (bridge round-trips, up to the 12s connect wait),
        // so it runs on the blocking pool, keeping the protocol threads free.
        let outcome =
            tokio::task::spawn_blocking(move || execute_tool_call(&session, &name, &args))
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

/// Execute one tool call against the shared session: the kill-switch gate,
/// the audit record, and the dispatch, exactly as the pre-rmcp dispatcher
/// ran them. Serves every harness (the broker's own stdio harness and all
/// relays route here through their per-connection rmcp services).
fn execute_tool_call(session: &Session, name: &str, args: &Value) -> tools::Outcome {
    // Correlate every invocation with a per-call request id and record a
    // structured audit event (tool, outcome, taxonomy code, duration).
    let req_id = next_request_id();
    let started = std::time::Instant::now();
    // The global kill switch gates EVERY tool call, for every harness,
    // before any routing or bridge traffic (ADR-0030). Fail closed on an
    // engaged switch AND on an unreadable record; the harness connection
    // stays up so the typed refusal is delivered. The host-side policy gate
    // (ADR-0032 decision 4) runs alongside it, refusing a tool whose grant is
    // off or that the effective policy disables - defense in depth for the
    // honest-host path, an unreadable store denying all (decision 5). Both
    // verdicts are computed here, before dispatch, and injected so the
    // fail-closed matrix stays pure and unit-testable.
    let (route, out) = route_and_dispatch(
        session,
        name,
        args,
        crate::kill::check(),
        crate::policy::gating::check(name),
    );
    let mut rec = crate::audit::AuditRecord::new(crate::audit::AuditKind::ToolCall);
    rec.req = Some(req_id);
    rec.conn = route.as_ref().map(|(_, g)| *g);
    rec.name = route.as_ref().map(|(l, _)| l.clone());
    rec.tool = Some(name.to_string());
    rec.outcome = Some(if out.is_error() { "error" } else { "ok" }.to_string());
    rec.code = out.error_code().map(str::to_string);
    // Saturating: a duration too long for u64 milliseconds (~584M years)
    // clamps rather than fails the audit record.
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

/// Route and dispatch one tool call from a SINGLE parse of its `browser`
/// argument. `tools::extract_browser` runs exactly once here; the audit
/// route (browser label + connection generation, best-effort diagnostics)
/// and the dispatch both consume that one result, so the trail can never
/// record a default route for a call the strict parse refused. The route is
/// captured before the dispatch and refreshed after it (a host may connect
/// during the call's startup wait), and the pre-dispatch verdicts (the kill
/// switch, ADR-0030; the host policy gate, ADR-0032) arrive injected so the
/// fail-closed matrix is unit-testable without touching the runtime directory
/// or the audit sink (both live in [`execute_tool_call`]). The kill switch is
/// the global brake, so it is checked first; the policy gate is per-tool.
fn route_and_dispatch(
    session: &Session,
    name: &str,
    args: &Value,
    kill: Result<(), crate::error::CallError>,
    policy: Result<(), crate::error::CallError>,
) -> (Option<(String, u64)>, tools::Outcome) {
    let browser = tools::extract_browser(args);
    let route_now = || browser.as_ref().ok().and_then(|b| session.route_info(*b));
    let route = route_now();
    let out = match (kill, policy) {
        (Ok(()), Ok(())) => match &browser {
            Ok(b) => tools::dispatch(session, name, args, *b),
            Err(e) => tools::error_outcome(e),
        },
        (Err(e), _) => tools::error_outcome(&e),
        (Ok(()), Err(e)) => tools::error_outcome(&e),
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
        // The legacy revision our pre-2026 harnesses negotiate stays served
        // (the ADR-0034 compatibility decision).
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
            ServerInfo::new(ServerCapabilities::default()),
        );
        let v = serde_json::to_value(&discover).unwrap();
        assert!(v["_meta"]
            .as_object()
            .unwrap()
            .contains_key(crate::protocol::MCP_META_SERVER_INFO));
    }

    #[test]
    fn the_catalogue_maps_in_static_order_with_schemas() {
        let mapped = shared_tools();
        let catalogue = tools::all();
        assert_eq!(mapped.len(), catalogue.len());
        for (m, t) in mapped.iter().zip(catalogue.iter()) {
            assert_eq!(m.name, t.name);
            assert_eq!(m.description.as_deref(), Some(t.description));
            assert_eq!(
                *m.input_schema, t.input_schema,
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
    fn a_success_outcome_becomes_a_non_error_result() {
        let out = tools::Outcome::Success {
            content: json!([{ "type": "text", "text": "{\"tabs\":[]}" }]),
        };
        let result = call_tool_result(&out);
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.content.len(), 1);
    }

    #[test]
    fn an_error_outcome_stays_a_tool_level_error() {
        let out = tools::Outcome::Error {
            content: json!([{ "type": "text", "text": "Error [BRIDGE_KILLED]: killed" }]),
            code: "BRIDGE_KILLED",
        };
        let result = call_tool_result(&out);
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn an_image_content_block_survives_the_mapping() {
        // page_screenshot returns an image block; it must reach the client
        // as image content, not a stringified fallback.
        let out = tools::Outcome::Success {
            content: json!([{ "type": "image", "data": "aGk=", "mimeType": "image/png" }]),
        };
        let result = call_tool_result(&out);
        assert!(matches!(result.content[0], ContentBlock::Image(_)));
    }

    #[test]
    fn a_malformed_browser_arg_is_refused_with_the_typed_code() {
        // `browser: 123` used to be re-read here with laxer rules than
        // dispatch's (`as_str`, silently None); the strict parse runs once
        // and the refusal carries the stable INVALID_ARGUMENT code, with no
        // routing attempted (a fresh session would otherwise block in the
        // 12s startup wait - this test finishing quickly is itself the
        // assertion).
        let session = Session::new();
        let (_route, out) = route_and_dispatch(
            &session,
            "tab_list",
            &json!({ "browser": 123 }),
            Ok(()),
            Ok(()),
        );
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"));
    }

    #[cfg(unix)]
    #[test]
    fn a_malformed_browser_arg_records_no_route_even_with_a_browser_connected() {
        // The single-parse guard, non-vacuously: with a live connection, the
        // lax pre-refactor read would have resolved the sole browser and
        // stamped a route onto the audit line of a call dispatch then
        // refused. The strict parse feeds routing and dispatch from ONE
        // result, so the refused call records no route at all.
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
            "tab_list",
            &json!({ "browser": 123 }),
            Ok(()),
            Ok(()),
        );
        assert_eq!(route, None, "a refused parse must not invent a route");
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"));

        // Control: the same session does route a well-formed call (captured
        // pre-dispatch from the same single parse).
        let (route, _out) = route_and_dispatch(
            &session,
            "no_such_tool",
            &json!({ "browser": "chrome" }),
            Ok(()),
            Ok(()),
        );
        assert_eq!(route.map(|(l, _)| l), Some("chrome".to_string()));
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
            "tab_list",
            &json!({}),
            Err(crate::error::CallError::Killed),
            Ok(()),
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
            "page_eval",
            &json!({}),
            Ok(()),
            Err(crate::error::CallError::ToolDisabled {
                tool: "page_eval".into(),
                reason: crate::error::ToolDisabledReason::GrantOff("pageEvalEnabled"),
            }),
        );
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("TOOL_DISABLED"));
    }
}
