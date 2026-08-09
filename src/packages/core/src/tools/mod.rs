//! MCP tool definitions and their handlers.
//!
//! Each tool has:
//!   - a `name` and human-readable `description` (shown to the model),
//!   - an `inputSchema` (JSON Schema describing arguments),
//!   - a handler that converts the arguments into a `BridgeReq` op + args
//!     and calls the session.
//!
//! The extension side (background.js / content.js) recognizes the same `op`
//! strings - keep them in sync when editing.
//!
//! This module is split across:
//!   - [`catalogue`] - the [`Tool`] struct, [`all`] catalogue, and `schema` helper,
//!   - [`capabilities`] - the negotiable capability groupings over the catalogue,
//!   - [`handlers`] - the per-op `build_*` payload fns and arg helpers,
//!   - this root - [`dispatch`], [`Outcome`], and the `Handler`/`HANDLERS` registry.

pub mod capabilities;
mod catalogue;
mod handlers;

use serde_json::{json, Value};

use crate::error::CallError;
use crate::session::Session;

pub use capabilities::{Capability, CAPABILITIES};
pub use catalogue::{all, Confirmation, Permission, Risk, Scope, Tool};
pub use handlers::DEFAULT_WAIT_TIMEOUT_MS;

use handlers::{
    build_console_get, build_cookie_get, build_empty, build_page_click, build_page_eval,
    build_page_fill, build_page_handle_dialog, build_page_hover, build_page_navigate,
    build_page_press, build_page_scroll, build_page_select, build_page_snapshot_precise,
    build_page_upload, build_page_wait_for, build_storage_get, build_tab_close, build_tab_focus,
    build_tab_open, call,
};

/// A registered tool handler. The bridge `op` name equals the tool `name`;
/// `build_payload` parses the (schema-shaped) MCP args into the op's argument
/// object - fallibly, so a missing or mistyped required argument is a typed
/// `INVALID_ARGUMENT` refusal instead of a fabricated default riding to the
/// extension. Responses are formatted centrally in [`dispatch`]. `HANDLERS` is
/// the single dispatch registry - `registry_covers_catalogue` (tests) asserts
/// it stays in lockstep with [`all`], so a new tool can't be added to the
/// catalogue without a handler (or vice versa).
struct Handler {
    name: &'static str,
    build_payload: fn(&Value) -> Result<Value, CallError>,
}

const HANDLERS: &[Handler] = &[
    Handler {
        name: "list_browsers",
        // Answered by the MCP server itself (see `list_browsers` below), so
        // the built payload is never sent anywhere - but dispatch still runs
        // this builder to validate the arguments (the object-root chokepoint),
        // and the registry/catalogue parity test keeps covering the entry.
        build_payload: build_empty,
    },
    Handler {
        name: "tab_list",
        build_payload: build_empty,
    },
    Handler {
        name: "tab_focus",
        build_payload: build_tab_focus,
    },
    Handler {
        name: "tab_open",
        build_payload: build_tab_open,
    },
    Handler {
        name: "tab_close",
        build_payload: build_tab_close,
    },
    Handler {
        name: "page_snapshot",
        build_payload: build_empty,
    },
    Handler {
        name: "page_click",
        build_payload: build_page_click,
    },
    Handler {
        name: "page_fill",
        build_payload: build_page_fill,
    },
    Handler {
        name: "page_text",
        build_payload: build_empty,
    },
    Handler {
        name: "page_screenshot",
        build_payload: build_empty,
    },
    Handler {
        name: "page_scroll",
        build_payload: build_page_scroll,
    },
    Handler {
        name: "page_wait_for",
        build_payload: build_page_wait_for,
    },
    Handler {
        name: "page_eval",
        build_payload: build_page_eval,
    },
    Handler {
        name: "page_snapshot_precise",
        build_payload: build_page_snapshot_precise,
    },
    Handler {
        name: "cookie_get",
        build_payload: build_cookie_get,
    },
    Handler {
        name: "storage_get",
        build_payload: build_storage_get,
    },
    Handler {
        name: "page_navigate",
        build_payload: build_page_navigate,
    },
    Handler {
        name: "page_back",
        build_payload: build_empty,
    },
    Handler {
        name: "page_forward",
        build_payload: build_empty,
    },
    Handler {
        name: "page_reload",
        build_payload: build_empty,
    },
    Handler {
        name: "page_press",
        build_payload: build_page_press,
    },
    Handler {
        name: "page_hover",
        build_payload: build_page_hover,
    },
    Handler {
        name: "page_select",
        build_payload: build_page_select,
    },
    Handler {
        name: "console_get",
        build_payload: build_console_get,
    },
    Handler {
        name: "page_handle_dialog",
        build_payload: build_page_handle_dialog,
    },
    Handler {
        name: "page_upload",
        build_payload: build_page_upload,
    },
];

/// The result of dispatching one tool call: exactly success-with-content or
/// error-with-content-and-code. The taxonomy code travels only on the error
/// variant, so "an error with no code" and "a success carrying one" are
/// unrepresentable - the audit record's outcome/code fields are projections
/// of one state, not two fields kept aligned by hand.
pub enum Outcome {
    /// The MCP content blocks of a successful call.
    Success { content: Value },
    /// A tool-level error: the MCP content blocks plus the stable taxonomy
    /// code (`error::ERROR_SPECS`) so the caller can record it in the audit
    /// trail without re-parsing the text.
    Error { content: Value, code: &'static str },
}

impl Outcome {
    pub fn content(&self) -> &Value {
        match self {
            Outcome::Success { content } | Outcome::Error { content, .. } => content,
        }
    }

    pub fn is_error(&self) -> bool {
        match self {
            Outcome::Success { .. } => false,
            Outcome::Error { .. } => true,
        }
    }

    /// The taxonomy code - present exactly when this is an error, by
    /// construction.
    pub fn error_code(&self) -> Option<&'static str> {
        match self {
            Outcome::Success { .. } => None,
            Outcome::Error { code, .. } => Some(code),
        }
    }
}

/// Dispatch a tool call. Returns the MCP result `content` value (an array)
/// and the isError flag. Errors are tool-level (isError=true), not RPC-level.
///
/// `browser` is the tool call's already-parsed routing argument: the caller
/// (the MCP tool executor in [`crate::mcp::handler`]) extracts it once via [`extract_browser`]
/// and feeds routing, auditing, and this dispatch from that single parse, so
/// no layer re-reads the raw value under different rules. It is consumed here
/// (routing) and never forwarded in the op's own args. `list_browsers` is
/// answered by the server itself from its connection registry - it is the one
/// tool that does not translate into a bridge request - but its arguments
/// still go through its registered builder first, so the server-local branch
/// enforces the same object-root chokepoint as every bridge tool instead of
/// silently accepting shapes its schema refuses.
pub fn dispatch(session: &Session, name: &str, args: &Value, browser: Option<&str>) -> Outcome {
    let result = match HANDLERS.iter().find(|h| h.name == name) {
        Some(h) => (h.build_payload)(args).and_then(|payload| {
            if name == "list_browsers" {
                list_browsers(session)
            } else {
                call(session, name, None, payload, browser)
            }
        }),
        None => Err(CallError::UnknownTool(name.to_string())),
    };

    match result {
        Ok(data) => {
            // Screenshots come back as base64 PNG; expose as an image content
            // block so the model sees the picture directly.
            if name == "page_screenshot" {
                if let Some(png_b64) = data.get("image").and_then(|v| v.as_str()) {
                    return Outcome::Success {
                        content: json!([{
                            "type": "image",
                            "data": png_b64,
                            "mimeType": "image/png"
                        }]),
                    };
                }
            }
            Outcome::Success {
                content: json!([{ "type": "text", "text": data.to_string() }]),
            }
        }
        Err(e) => error_outcome(&e),
    }
}

/// The [`Outcome`] for a tool-level error: the stable taxonomy code prefixed
/// to the human-readable text, `isError` set. Shared by [`dispatch`] and the
/// pre-dispatch gates (the kill switch, ADR-0030; the `browser` argument
/// parse) so every refusal reaches the model in one shape.
pub(crate) fn error_outcome(e: &CallError) -> Outcome {
    // Prefix the stable cross-process code (error::ERROR_SPECS) so
    // clients can branch programmatically, while the text stays
    // human-readable.
    Outcome::Error {
        content: json!([{ "type": "text", "text": format!("Error [{}]: {e}", e.code()) }]),
        code: e.code(),
    }
}

/// Extract the `browser` routing argument. Absent and JSON `null` (how some
/// clients serialize an unset optional) both mean "unaddressed"; any other
/// non-string shape is rejected, because with a single browser connected a
/// silently-dropped malformed target would still route the call somewhere.
/// The ONE parse of this value: the MCP tool executor calls it once and both
/// the audit route and [`dispatch`] consume the same result.
pub(crate) fn extract_browser(args: &Value) -> Result<Option<&str>, CallError> {
    match args.get("browser") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(other) => Err(CallError::InvalidBrowserArg(other.to_string())),
    }
}

/// Answer `list_browsers` from the server's connection registry: one entry per
/// live, authenticated connection, enriched with that browser's open-tab count
/// (a routed `tab_list` round-trip per browser). A browser that fails to
/// answer stays in the list with `tabCount: null` and its error text - being
/// slow or broken should not hide it from enumeration. The per-browser
/// round-trip uses a short enumeration timeout (and no connect-wait), so one
/// wedged browser costs seconds, not the interactive 120s, and can never
/// starve discovery of the healthy ones. No browsers connected is a normal,
/// empty result, not an error.
fn list_browsers(session: &Session) -> Result<Value, CallError> {
    let labels = session.labels();
    let browsers: Vec<Value> = labels
        .into_iter()
        .map(|label| {
            match session.try_call(
                "tab_list",
                None,
                json!({}),
                Some(&label),
                std::time::Duration::from_secs(5),
            ) {
                Ok(data) => {
                    // tab_list returns an array of tabs; anything else counts
                    // as unknown rather than 0.
                    let count = data.as_array().map(|tabs| tabs.len());
                    json!({ "label": label, "tabCount": count })
                }
                Err(e) => json!({ "label": label, "tabCount": null, "error": e.to_string() }),
            }
        })
        .collect();
    Ok(json!({ "count": browsers.len(), "browsers": browsers }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The dispatch registry must stay in lockstep with the catalogue: every
    // tool has exactly one handler and every handler names a real tool. This
    // closes the only drift the catalogue tests can't see.
    #[test]
    fn registry_covers_catalogue() {
        use std::collections::BTreeSet;
        let catalogue: BTreeSet<&str> = all().iter().map(|t| t.name).collect();
        let registry: BTreeSet<&str> = HANDLERS.iter().map(|h| h.name).collect();
        assert_eq!(
            catalogue, registry,
            "every tool needs exactly one dispatch handler (and vice versa)"
        );
        assert_eq!(HANDLERS.len(), catalogue.len(), "duplicate handler name");
    }

    // Arg-shaping is pure, so verify the non-trivial builders here rather than
    // relying solely on the browser e2e (which the catalogue tests never cover).
    #[test]
    fn build_payload_shapes() {
        let build = |name: &str, args: Value| -> Value {
            let h = HANDLERS.iter().find(|h| h.name == name).unwrap();
            (h.build_payload)(&args).unwrap()
        };
        // page_fill merges ref/selector with the value.
        assert_eq!(
            build("page_fill", json!({ "ref": "e5", "value": "hi" })),
            json!({ "ref": "e5", "value": "hi" })
        );
        // page_wait_for defaults timeoutMs and passes selector through.
        assert_eq!(
            build("page_wait_for", json!({ "selector": "#x" })),
            json!({ "selector": "#x", "timeoutMs": DEFAULT_WAIT_TIMEOUT_MS })
        );
        // tab_focus forwards the (typed, required) tabId.
        assert_eq!(
            build("tab_focus", json!({ "tabId": 7 })),
            json!({ "tabId": 7 })
        );
        // Optional fields are omitted when absent.
        assert_eq!(
            build("cookie_get", json!({ "domain": "example.com" })),
            json!({ "domain": "example.com" })
        );
        // Empty builder ignores extraneous args.
        assert_eq!(build("page_snapshot", json!({ "junk": 1 })), json!({}));
        // The shared `browser` routing key rides in the same args object and
        // is never forwarded in the op payload.
        assert_eq!(
            build(
                "page_select",
                json!({ "ref": "e2", "value": "b", "browser": "brave" })
            ),
            json!({ "ref": "e2", "value": "b" })
        );
        // A null args value (an MCP client omitting `arguments`) means no
        // arguments for a tool whose args are all optional.
        assert_eq!(build("page_scroll", Value::Null), json!({}));
    }

    // The guard on the deleted sarg/iarg escape hatches: a missing or
    // mistyped required argument is a typed INVALID_ARGUMENT refusal, never a
    // fabricated ""/0 riding to the extension as a real-looking payload.
    #[test]
    fn builders_refuse_missing_or_mistyped_required_args() {
        let build = |name: &str, args: Value| -> Result<Value, CallError> {
            let h = HANDLERS.iter().find(|h| h.name == name).unwrap();
            (h.build_payload)(&args)
        };
        for (tool, args) in [
            // Absent required fields (the old builders fabricated 0/"").
            ("tab_focus", json!({})),
            ("tab_close", json!({})),
            ("tab_open", json!({})),
            ("page_eval", json!({})),
            ("page_navigate", json!({})),
            ("page_press", json!({})),
            ("page_fill", json!({ "ref": "e1" })),
            ("page_select", json!({ "selector": "#s" })),
            ("page_handle_dialog", json!({})),
            ("page_upload", json!({ "selector": "#f" })), // no path
            ("page_upload", json!({ "path": "/tmp/x" })), // no selector
            // Mistyped values (the old coercions silently dropped these).
            ("tab_focus", json!({ "tabId": "seven" })),
            ("tab_focus", json!({ "tabId": 7.5 })),
            ("page_eval", json!({ "code": 42 })),
            ("page_upload", json!({ "selector": "#f", "path": 5 })),
            // Mistyped OPTIONAL values are refused too, not silently dropped.
            ("cookie_get", json!({ "domain": 123 })),
            ("page_wait_for", json!({ "timeoutMs": "soon" })),
        ] {
            let err = build(tool, args.clone()).unwrap_err();
            assert!(
                matches!(err, CallError::InvalidArgument(_)),
                "{tool} with {args} must refuse, got {err:?}"
            );
            assert_eq!(err.code(), "INVALID_ARGUMENT", "{tool} with {args}");
        }
    }

    // Lockstep with the catalogue, derived from the schemas themselves so a
    // future schema edit cannot silently outrun its builder: for every tool,
    // a schema-valid argument object is accepted; removing any required field
    // is a refusal naming that field; a wrong-typed or explicitly-null value
    // for any declared property is a refusal; and a non-object argument root
    // is a refusal (every schema is `type: object`). The `browser` routing
    // property is dispatch's, parsed by `extract_browser`, so it is the one
    // schema property the builders deliberately ignore.
    #[test]
    fn builders_enforce_exactly_the_catalogue_required_args() {
        fn sample(ty: &str, tool: &str, key: &str) -> Value {
            match ty {
                "string" => json!("x"),
                "integer" => json!(1),
                "boolean" => json!(true),
                other => panic!("{tool}.{key}: no sample for schema type {other}"),
            }
        }
        fn mistyped(ty: &str, tool: &str, key: &str) -> Value {
            match ty {
                "string" => json!(7),
                "integer" => json!("seven"),
                "boolean" => json!("yes"),
                other => panic!("{tool}.{key}: no mistyped value for schema type {other}"),
            }
        }
        for tool in all() {
            let h = HANDLERS
                .iter()
                .find(|h| h.name == tool.name)
                .unwrap_or_else(|| panic!("no handler for {}", tool.name));
            let build = h.build_payload;
            let props = tool.input_schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{}: schema has no properties object", tool.name));
            let required: Vec<&str> = tool.input_schema["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{}: schema has no required array", tool.name))
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let prop_type = |key: &str| -> &str {
                props[key]["type"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{}.{key}: schema property has no type", tool.name))
            };

            // A full, schema-valid argument object is accepted.
            let full: serde_json::Map<String, Value> = required
                .iter()
                .map(|k| ((*k).to_string(), sample(prop_type(k), tool.name, k)))
                .collect();
            assert!(
                build(&Value::Object(full.clone())).is_ok(),
                "{}: schema-valid args were refused",
                tool.name
            );

            // Each required field, removed on its own, is a refusal that
            // names the missing field.
            for missing in &required {
                let mut args = full.clone();
                args.remove(*missing);
                match build(&Value::Object(args)) {
                    Err(CallError::InvalidArgument(msg)) => assert!(
                        msg.contains(missing),
                        "{}: refusal for missing {missing} does not name it: {msg}",
                        tool.name
                    ),
                    other => panic!(
                        "{}: schema requires {missing}, but the builder returned {other:?}",
                        tool.name
                    ),
                }
            }

            // Every declared property (except dispatch's `browser`) refuses a
            // wrong-typed value and an explicit null - the schema advertises
            // the type, never a nullable.
            for (key, _) in props.iter().filter(|(k, _)| k.as_str() != "browser") {
                let ty = prop_type(key);
                for bad in [mistyped(ty, tool.name, key), Value::Null] {
                    let mut args = full.clone();
                    args.insert(key.clone(), bad.clone());
                    assert!(
                        matches!(
                            build(&Value::Object(args)),
                            Err(CallError::InvalidArgument(_))
                        ),
                        "{}: {key} = {bad} must be refused",
                        tool.name
                    );
                }
            }

            // A non-object argument root is refused for every tool (null is
            // the documented omitted-arguments case and is not one).
            for root in [json!([]), json!("args"), json!(3), json!(true)] {
                assert!(
                    matches!(build(&root), Err(CallError::InvalidArgument(_))),
                    "{}: non-object arguments root {root} must be refused",
                    tool.name
                );
            }
        }
    }

    // The `browser` routing argument is strictly typed: absent/null route as
    // "unaddressed", strings route by label, anything else is rejected before
    // any bridge traffic (or connect-waiting) can happen.
    #[test]
    fn browser_arg_must_be_a_string() {
        assert_eq!(extract_browser(&json!({})).unwrap(), None);
        assert_eq!(extract_browser(&json!({ "browser": null })).unwrap(), None);
        assert_eq!(
            extract_browser(&json!({ "browser": "brave" })).unwrap(),
            Some("brave")
        );
        for bad in [json!(123), json!(true), json!(["chrome"]), json!({})] {
            let err = extract_browser(&json!({ "browser": bad })).unwrap_err();
            assert!(matches!(err, CallError::InvalidBrowserArg(_)), "{bad}");
        }
    }

    #[test]
    fn dispatch_refuses_bad_args_without_routing() {
        // A fresh session has no connections; a call would normally block in
        // the 12s startup wait. Malformed args must be refused by the builder
        // before that - this test finishing quickly is itself the assertion
        // that no routing was attempted.
        let session = Session::new();
        let out = dispatch(&session, "tab_focus", &json!({}), None);
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"));
        // An unknown tool is refused the same way, pre-routing.
        let out = dispatch(&session, "no_such_tool", &json!({}), None);
        assert!(out.is_error());
        assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"));
    }

    #[test]
    fn list_browsers_validates_its_arguments_before_answering_locally() {
        // list_browsers is answered by the server itself, never sent over the
        // bridge - which is exactly why dispatch must still run its builder:
        // without that, the server-local branch would accept argument shapes
        // its object schema refuses, and the "every tool" claim of the
        // catalogue lockstep test would be hollow for this one tool.
        let session = Session::new();
        for bad in [json!([]), json!("hi"), json!(42)] {
            let out = dispatch(&session, "list_browsers", &bad, None);
            assert!(out.is_error(), "non-object args {bad} must be refused");
            assert_eq!(out.error_code(), Some("INVALID_ARGUMENT"), "{bad}");
        }
        // An empty object and omitted arguments (Null) both answer from the
        // (empty) connection registry - a normal, empty result.
        for good in [json!({}), Value::Null] {
            let out = dispatch(&session, "list_browsers", &good, None);
            assert!(!out.is_error(), "{good} must answer locally");
        }
    }

    #[test]
    fn outcome_carries_a_code_exactly_when_it_is_an_error() {
        // The projection methods agree with the variant by construction; this
        // pins the shape the audit record and the MCP reply are built from.
        let ok = Outcome::Success {
            content: json!([{ "type": "text", "text": "hi" }]),
        };
        assert!(!ok.is_error());
        assert_eq!(ok.error_code(), None);
        let err = error_outcome(&CallError::NotConnected);
        assert!(err.is_error());
        assert_eq!(err.error_code(), Some("NOT_CONNECTED"));
        assert!(err.content()[0]["text"]
            .as_str()
            .unwrap()
            .starts_with("Error [NOT_CONNECTED]:"));
    }
}
