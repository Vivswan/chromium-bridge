//! The tool surface: the catalogue (`catalogue.rs`), the typed arguments
//! ([`args`]), the capability groupings (`capabilities.rs`), and the two
//! operations the MCP layer runs on them, [`ToolCall::parse`] at the request
//! boundary and [`dispatch`] after the gates.

pub mod args;
mod capabilities;
mod catalogue;

use serde_json::{json, Value};

use crate::error::CallError;
use crate::session::Session;

pub use capabilities::{capabilities, Capability, CapabilityId};
pub use catalogue::{
    all, BridgeCommand, Confirmation, Dispatch, Permission, ResultKind, Risk, Scope, Tool, ToolId,
};

/// One MCP `tools/call`, parsed: the typed command the bridge will carry and
/// the `browser` routing argument the server consumes. The only way to build
/// one is [`ToolCall::parse`], so a command reaching [`dispatch`] is already
/// a catalogue tool with schema-valid arguments, and a server-local call
/// never carries a browser.
#[derive(Debug, Clone)]
pub struct ToolCall {
    command: BridgeCommand,
    browser: Option<String>,
}

impl ToolCall {
    /// The record of the tool this call invokes.
    pub fn tool(&self) -> Tool {
        self.command.id().tool()
    }

    /// The addressed browser label; `None` when unaddressed, and always for a
    /// server-local tool, which takes no routing argument.
    pub fn browser(&self) -> Option<&str> {
        self.browser.as_deref()
    }

    /// Parse one tool call at the MCP boundary, fail closed: an unknown tool,
    /// a malformed `browser`, and an args object outside the tool's struct
    /// (missing, mistyped, null, or unknown fields) are each a typed
    /// `INVALID_ARGUMENT` refusal before any routing or bridge traffic.
    ///
    /// ```text
    /// browser absent or null  -> unaddressed (how some clients serialize an unset optional)
    /// browser a string        -> that label, removed from the args before the struct parse
    /// browser anything else   -> refused: with one browser connected, a silently dropped target
    ///                            would still route the call somewhere
    /// server-local tool       -> `browser` is not peeled off, so its struct refuses it like any
    ///                            other field it does not declare
    /// ```
    pub fn parse(name: &str, mut args: serde_json::Map<String, Value>) -> Result<Self, CallError> {
        let id = ToolId::from_name(name).ok_or_else(|| CallError::UnknownTool(name.to_string()))?;
        let tool = id.tool();
        let browser = match tool.dispatch {
            Dispatch::ServerLocal(_) => None,
            Dispatch::Bridge { .. } => match args.remove("browser") {
                None | Some(Value::Null) => None,
                Some(Value::String(label)) => Some(label),
                Some(other) => return Err(CallError::InvalidBrowserArg(other.to_string())),
            },
        };
        let command = id
            .parse_args(Value::Object(args))
            .map_err(|e| CallError::InvalidArgument(format!("{name}: {e}")))?;
        Ok(ToolCall { command, browser })
    }
}

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

/// Run a parsed tool call and shape its result into the MCP content blocks
/// and the isError flag; errors are tool-level, never RPC-level. The record's
/// [`Dispatch`] decides where the call runs and how its data is rendered.
pub fn dispatch(session: &Session, call: ToolCall) -> Outcome {
    let tool = call.tool();
    let ToolCall { command, browser } = call;
    let result = match tool.dispatch {
        Dispatch::ServerLocal(handler) => handler(session),
        Dispatch::Bridge { .. } => session.call(command, browser.as_deref()),
    };
    let data = match result {
        Ok(data) => data,
        Err(e) => return error_outcome(&e),
    };
    let content = match tool.dispatch {
        Dispatch::Bridge {
            result: ResultKind::Image,
            ..
        } => match data.get("image").and_then(Value::as_str) {
            Some(png_b64) => json!([{
                "type": "image",
                "data": png_b64,
                "mimeType": "image/png"
            }]),
            None => json!([{ "type": "text", "text": data.to_string() }]),
        },
        Dispatch::Bridge {
            result: ResultKind::Text,
            ..
        }
        | Dispatch::ServerLocal(_) => json!([{ "type": "text", "text": data.to_string() }]),
    };
    Outcome::Success { content }
}

/// The [`Outcome`] for a tool-level error: the stable taxonomy code prefixed
/// to the human-readable text, `isError` set. Shared by [`dispatch`] and the
/// pre-dispatch gates (the kill switch, the policy gate, the call parse) so
/// every refusal reaches the model in one shape.
pub(crate) fn error_outcome(e: &CallError) -> Outcome {
    // Prefix the stable cross-process code (error::ERROR_SPECS) so
    // clients can branch programmatically, while the text stays
    // human-readable.
    Outcome::Error {
        content: json!([{ "type": "text", "text": format!("Error [{}]: {e}", e.code()) }]),
        code: e.code(),
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
                BridgeCommand::TabList(args::NoArgs {}),
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
    use serde_json::Map;

    fn object(v: Value) -> Map<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    // The bridge payload is the args struct serialized through: optional
    // fields stay off the wire when absent, the one host-filled default
    // (page_wait_for's timeoutMs) is always present, and the `browser`
    // routing key never rides inside args. The extension's handlers read
    // exactly these shapes.
    #[test]
    fn the_bridge_payload_is_the_struct_serialized_through() {
        let payload = |name: &str, args: Value| -> Value {
            let call = ToolCall::parse(name, object(args)).unwrap();
            serde_json::to_value(&call.command).unwrap()["args"].clone()
        };
        assert_eq!(
            payload("page_fill", json!({ "ref": "e5", "value": "hi" })),
            json!({ "ref": "e5", "value": "hi" })
        );
        assert_eq!(
            payload("page_wait_for", json!({ "selector": "#x" })),
            json!({ "selector": "#x", "timeoutMs": args::DEFAULT_WAIT_TIMEOUT_MS })
        );
        assert_eq!(
            payload("tab_focus", json!({ "tabId": 7 })),
            json!({ "tabId": 7 })
        );
        assert_eq!(
            payload("cookie_get", json!({ "domain": "example.com" })),
            json!({ "domain": "example.com" })
        );
        assert_eq!(
            payload(
                "page_select",
                json!({ "ref": "e2", "value": "b", "browser": "brave" })
            ),
            json!({ "ref": "e2", "value": "b" })
        );
        assert_eq!(payload("page_scroll", json!({})), json!({}));
    }

    // Derived from the schemas themselves, so a future struct edit cannot
    // outrun this: for every tool, a schema-valid argument object is
    // accepted; removing any required field is a refusal naming that field;
    // a wrong-typed or explicitly-null value for any declared property is a
    // refusal (the schema advertises the type, never a nullable); and an
    // undeclared field is a refusal (the extension's strictObject agrees).
    #[test]
    fn every_tool_accepts_its_schema_and_refuses_everything_outside_it() {
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
        let refused = |name: &str, args: Map<String, Value>| -> Option<String> {
            match ToolCall::parse(name, args) {
                Err(CallError::InvalidArgument(msg)) => Some(msg),
                Err(other) => panic!("{name}: refused with the wrong class {other:?}"),
                Ok(_) => None,
            }
        };
        for tool in all() {
            let schema = tool.args_schema();
            let props = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let required: Vec<&str> = schema
                .get("required")
                .and_then(Value::as_array)
                .map(|r| r.iter().map(|v| v.as_str().unwrap()).collect())
                .unwrap_or_default();
            let prop_type = |key: &str| -> &str {
                props[key]["type"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{}.{key}: schema property has no type", tool.name))
            };

            let full: Map<String, Value> = required
                .iter()
                .map(|k| ((*k).to_string(), sample(prop_type(k), tool.name, k)))
                .collect();
            assert_eq!(
                refused(tool.name, full.clone()),
                None,
                "{}: schema-valid args were refused",
                tool.name
            );

            for missing in &required {
                let mut args = full.clone();
                args.remove(*missing);
                let msg = refused(tool.name, args)
                    .unwrap_or_else(|| panic!("{}: missing {missing} was accepted", tool.name));
                assert!(
                    msg.contains(missing),
                    "{}: refusal for missing {missing} does not name it: {msg}",
                    tool.name
                );
            }

            for (key, _) in &props {
                let ty = prop_type(key);
                for bad in [mistyped(ty, tool.name, key), Value::Null] {
                    let mut args = full.clone();
                    args.insert(key.clone(), bad.clone());
                    assert!(
                        refused(tool.name, args).is_some(),
                        "{}: {key} = {bad} must be refused",
                        tool.name
                    );
                }
            }

            let mut args = full.clone();
            args.insert("undeclared".into(), json!(1));
            assert!(
                refused(tool.name, args).is_some(),
                "{}: an undeclared field must be refused",
                tool.name
            );
        }
    }

    // The `browser` routing argument is strictly typed: absent/null route as
    // "unaddressed", strings route by label, anything else is rejected before
    // any bridge traffic (or connect-waiting) can happen. A server-local tool
    // takes no routing argument at all, so for it `browser` is an undeclared
    // field like any other.
    #[test]
    fn browser_routing_argument_is_peeled_strictly_and_only_for_bridge_tools() {
        let parse = |args: Value| ToolCall::parse("tab_list", object(args));
        assert_eq!(parse(json!({})).unwrap().browser(), None);
        assert_eq!(parse(json!({ "browser": null })).unwrap().browser(), None);
        assert_eq!(
            parse(json!({ "browser": "brave" })).unwrap().browser(),
            Some("brave")
        );
        for bad in [json!(123), json!(true), json!(["chrome"]), json!({})] {
            let err = parse(json!({ "browser": bad })).unwrap_err();
            assert!(matches!(err, CallError::InvalidBrowserArg(_)), "{bad}");
        }
        let err =
            ToolCall::parse("list_browsers", object(json!({ "browser": "brave" }))).unwrap_err();
        assert!(matches!(err, CallError::InvalidArgument(_)), "{err:?}");
    }

    #[test]
    fn an_unknown_tool_is_refused_before_any_args_are_read() {
        let err = ToolCall::parse("no_such_tool", object(json!({ "browser": 5 }))).unwrap_err();
        assert!(matches!(err, CallError::UnknownTool(_)), "{err:?}");
        assert_eq!(err.code(), "INVALID_ARGUMENT");
    }

    #[test]
    fn list_browsers_answers_locally_from_an_empty_registry() {
        // A fresh session has no connections, so a bridge tool would park in
        // the connect wait; list_browsers is answered by the server itself
        // and returns the (empty) registry at once.
        let session = Session::new();
        let call = ToolCall::parse("list_browsers", Map::new()).unwrap();
        let out = dispatch(&session, call);
        assert!(!out.is_error());
        assert_eq!(
            out.content()[0]["text"].as_str().unwrap(),
            json!({ "count": 0, "browsers": [] }).to_string()
        );
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
