//! MCP tool definitions and their handlers.
//!
//! Each tool has:
//!   - a `name` and human-readable `description` (shown to the model),
//!   - an `inputSchema` (JSON Schema describing arguments),
//!   - a handler that converts the arguments into a `BridgeReq` op + args
//!     and calls the session.
//!
//! The extension side (background.js / content.js) recognizes the same `op`
//! strings — keep them in sync when editing.
//!
//! This module is split across:
//!   - [`catalogue`] — the [`Tool`] struct, [`all`] catalogue, and `schema` helper,
//!   - [`handlers`] — the per-op `build_*` payload fns and arg helpers,
//!   - this root — [`dispatch`], [`Outcome`], and the `Handler`/`HANDLERS` registry.

mod catalogue;
mod handlers;

use serde_json::{json, Value};

use crate::error::CallError;
use crate::session::Session;

pub use catalogue::{all, Tool};

use handlers::{
    build_console_get, build_cookie_get, build_empty, build_page_eval, build_page_fill,
    build_page_handle_dialog, build_page_navigate, build_page_press, build_page_scroll,
    build_page_select, build_page_snapshot_precise, build_page_upload, build_page_wait_for,
    build_storage_get, build_tab_close, build_tab_focus, build_tab_open, call, ref_or_selector,
};

/// A registered tool handler. The bridge `op` name equals the tool `name`;
/// `build_payload` maps the (schema-shaped) MCP args into the op's argument
/// object. Responses are formatted centrally in [`dispatch`]. `HANDLERS` is the
/// single dispatch registry — `registry_covers_catalogue` (tests) asserts it
/// stays in lockstep with [`all`], so a new tool can't be added to the
/// catalogue without a handler (or vice versa).
struct Handler {
    name: &'static str,
    build_payload: fn(&Value) -> Value,
}

const HANDLERS: &[Handler] = &[
    Handler {
        name: "list_browsers",
        // Answered by the MCP server itself (see `list_browsers` below);
        // registered here so the registry/catalogue parity test keeps covering
        // it. The builder is never used to send a bridge request.
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
        build_payload: ref_or_selector,
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
        build_payload: ref_or_selector,
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

/// The result of dispatching one tool call: the MCP content blocks, whether it
/// is an error, and — on error — the stable taxonomy code (contracts/errors.json)
/// so the caller can record it in the audit trail without re-parsing the text.
pub struct Outcome {
    pub content: Value,
    pub is_error: bool,
    pub error_code: Option<&'static str>,
}

/// Dispatch a tool call. Returns the MCP result `content` value (an array)
/// and the isError flag. Errors are tool-level (isError=true), not RPC-level.
///
/// Every tool accepts an optional `browser` argument naming which connected
/// browser to run on; it is consumed here (routing) and never forwarded in the
/// op's own args. `list_browsers` is answered by the server itself from its
/// connection registry — it is the one tool that does not translate into a
/// single bridge request.
pub fn dispatch(session: &Session, name: &str, args: &Value) -> Outcome {
    let result = extract_browser(args).and_then(|browser| {
        if name == "list_browsers" {
            list_browsers(session)
        } else {
            match HANDLERS.iter().find(|h| h.name == name) {
                Some(h) => call(session, name, None, (h.build_payload)(args), browser),
                None => Err(CallError::UnknownTool(name.to_string())),
            }
        }
    });

    match result {
        Ok(data) => {
            // Screenshots come back as base64 PNG; expose as an image content
            // block so the model sees the picture directly.
            if name == "page_screenshot" {
                if let Some(png_b64) = data.get("image").and_then(|v| v.as_str()) {
                    return Outcome {
                        content: json!([{
                            "type": "image",
                            "data": png_b64,
                            "mimeType": "image/png"
                        }]),
                        is_error: false,
                        error_code: None,
                    };
                }
            }
            Outcome {
                content: json!([{ "type": "text", "text": data.to_string() }]),
                is_error: false,
                error_code: None,
            }
        }
        Err(e) => Outcome {
            // Prefix the stable cross-process code (contracts/errors.json) so
            // clients can branch programmatically, while the text stays
            // human-readable. isError stays true.
            content: json!([{ "type": "text", "text": format!("Error [{}]: {e}", e.code()) }]),
            is_error: true,
            error_code: Some(e.code()),
        },
    }
}

/// Extract the `browser` routing argument. Absent and JSON `null` (how some
/// clients serialize an unset optional) both mean "unaddressed"; any other
/// non-string shape is rejected, because with a single browser connected a
/// silently-dropped malformed target would still route the call somewhere.
fn extract_browser(args: &Value) -> Result<Option<&str>, CallError> {
    match args.get("browser") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(other) => Err(CallError::InvalidBrowserArg(other.to_string())),
    }
}

/// Answer `list_browsers` from the server's connection registry: one entry per
/// live, authenticated connection, enriched with that browser's open-tab count
/// (a routed `tab_list` round-trip per browser). A browser that fails to
/// answer stays in the list with `tabCount: null` and its error text — being
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
            (h.build_payload)(&args)
        };
        // page_fill merges ref/selector with the value.
        assert_eq!(
            build("page_fill", json!({ "ref": "e5", "value": "hi" })),
            json!({ "ref": "e5", "value": "hi" })
        );
        // page_wait_for defaults timeoutMs and passes selector through.
        assert_eq!(
            build("page_wait_for", json!({ "selector": "#x" })),
            json!({ "selector": "#x", "timeoutMs": 30000 })
        );
        // tab_focus coerces tabId.
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
    fn dispatch_rejects_a_malformed_browser_arg_without_routing() {
        // A fresh session has no connections; a call would normally block in
        // the 12s startup wait. The malformed `browser` must be rejected
        // before that — this test finishing quickly is itself the assertion
        // that no routing was attempted.
        let session = Session::new();
        let out = dispatch(&session, "tab_list", &json!({ "browser": 123 }));
        assert!(out.is_error);
        assert_eq!(out.error_code, Some("INVALID_ARGUMENT"));
    }
}
