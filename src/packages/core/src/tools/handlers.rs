//! Per-op payload builders and argument helpers.
//!
//! Each `build_*` fn maps the (schema-shaped) MCP args into the bridge op's
//! argument object. [`call`] forwards the built payload to the session, and
//! the small `sarg`/`iarg`/`ref_or_selector` helpers coerce individual args.

use serde_json::{json, Value};

use crate::error::CallError;
use crate::session::Session;

pub(super) fn build_empty(_args: &Value) -> Value {
    json!({})
}

pub(super) fn build_tab_focus(args: &Value) -> Value {
    json!({ "tabId": iarg(args, "tabId") })
}

pub(super) fn build_tab_open(args: &Value) -> Value {
    json!({ "url": sarg(args, "url") })
}

pub(super) fn build_tab_close(args: &Value) -> Value {
    json!({ "tabId": iarg(args, "tabId") })
}

pub(super) fn build_page_eval(args: &Value) -> Value {
    json!({ "code": sarg(args, "code") })
}

pub(super) fn build_page_fill(args: &Value) -> Value {
    let value = sarg(args, "value");
    let mut payload = ref_or_selector_map(args);
    payload.insert("value".into(), json!(value));
    Value::Object(payload)
}

pub(super) fn build_page_navigate(args: &Value) -> Value {
    json!({ "url": sarg(args, "url") })
}

pub(super) fn build_page_press(args: &Value) -> Value {
    json!({ "keys": sarg(args, "keys") })
}

pub(super) fn build_page_select(args: &Value) -> Value {
    let value = sarg(args, "value");
    let mut payload = ref_or_selector_map(args);
    payload.insert("value".into(), json!(value));
    Value::Object(payload)
}

pub(super) fn build_console_get(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(l) = args.get("limit").and_then(|v| v.as_i64()) {
        payload.insert("limit".into(), json!(l));
    }
    Value::Object(payload)
}

pub(super) fn build_page_handle_dialog(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("action".into(), json!(sarg(args, "action")));
    if let Some(t) = args.get("promptText").and_then(|v| v.as_str()) {
        payload.insert("promptText".into(), json!(t));
    }
    Value::Object(payload)
}

pub(super) fn build_page_upload(args: &Value) -> Value {
    json!({ "selector": sarg(args, "selector"), "path": sarg(args, "path") })
}

pub(super) fn build_page_scroll(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(d) = args.get("direction").and_then(|v| v.as_str()) {
        payload.insert("direction".into(), json!(d));
    }
    if let Some(p) = args.get("pixels").and_then(|v| v.as_i64()) {
        payload.insert("pixels".into(), json!(p));
    }
    Value::Object(payload)
}

pub(super) fn build_page_wait_for(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(s) = args.get("selector").and_then(|v| v.as_str()) {
        payload.insert("selector".into(), json!(s));
    }
    if let Some(t) = args.get("text").and_then(|v| v.as_str()) {
        payload.insert("text".into(), json!(t));
    }
    if let Some(n) = args.get("nav").and_then(|v| v.as_bool()) {
        payload.insert("nav".into(), json!(n));
    }
    payload.insert(
        "timeoutMs".into(),
        json!(args
            .get("timeoutMs")
            .and_then(|v| v.as_i64())
            .unwrap_or(30000)),
    );
    Value::Object(payload)
}

pub(super) fn build_page_snapshot_precise(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(f) = args.get("frameId").and_then(|v| v.as_str()) {
        payload.insert("frameId".into(), json!(f));
    }
    Value::Object(payload)
}

pub(super) fn build_cookie_get(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(u) = args.get("url").and_then(|v| v.as_str()) {
        payload.insert("url".into(), json!(u));
    }
    if let Some(d) = args.get("domain").and_then(|v| v.as_str()) {
        payload.insert("domain".into(), json!(d));
    }
    if let Some(n) = args.get("name").and_then(|v| v.as_str()) {
        payload.insert("name".into(), json!(n));
    }
    Value::Object(payload)
}

pub(super) fn build_storage_get(args: &Value) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(t) = args.get("type").and_then(|v| v.as_str()) {
        payload.insert("type".into(), json!(t));
    }
    if let Some(k) = args.get("key").and_then(|v| v.as_str()) {
        payload.insert("key".into(), json!(k));
    }
    Value::Object(payload)
}

pub(super) fn call(
    session: &Session,
    op: &str,
    tab_id: Option<i64>,
    args: Value,
    browser: Option<&str>,
) -> Result<Value, CallError> {
    session.call(op, tab_id, args, browser)
}

fn sarg(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn iarg(args: &Value, key: &str) -> i64 {
    args.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

pub(super) fn ref_or_selector(args: &Value) -> Value {
    Value::Object(ref_or_selector_map(args))
}

/// Map form of [`ref_or_selector`], for builders that add further fields:
/// inserting into the map directly avoids `Value` index-assignment (which
/// panics on a non-object) while keeping the payload construction identical.
fn ref_or_selector_map(args: &Value) -> serde_json::Map<String, Value> {
    let mut payload = serde_json::Map::new();
    if let Some(r) = args.get("ref").and_then(|v| v.as_str()) {
        payload.insert("ref".into(), json!(r));
    }
    if let Some(s) = args.get("selector").and_then(|v| v.as_str()) {
        payload.insert("selector".into(), json!(s));
    }
    payload
}
