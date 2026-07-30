//! Per-op payload builders and argument helpers.
//!
//! Each `build_*` fn parses the (schema-shaped) MCP args into the op's typed
//! argument shape and emits the bridge payload from it. The builders are
//! fallible on purpose: a missing or mistyped required argument is refused
//! with the stable `INVALID_ARGUMENT` taxonomy code, never papered over with
//! a fabricated default (`tab_focus` must not focus tab 0 because no tabId
//! arrived, and `page_upload` must not ship an empty path). [`call`] forwards
//! the built payload to the session.
//!
//! Unknown extra keys are ignored, matching the catalogue schemas (the shared
//! `browser` routing argument rides in the same args object and is consumed
//! by dispatch); the keys each tool DOES declare are parsed strictly.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::CallError;
use crate::session::Session;

/// Parse one tool's args into its typed shape, or refuse with the tool named
/// in the `INVALID_ARGUMENT` error. The single entry point every builder
/// funnels through, so no builder can quietly fall back to a default. A
/// `null` args value (an MCP client that omitted `arguments` entirely) means
/// "no arguments", the same as `{}`; any other non-object root is refused -
/// every catalogue schema is `type: object` - and a tool with required args
/// then refuses on the missing fields, one with only optional args proceeds.
fn parse<T: serde::de::DeserializeOwned>(tool: &str, args: &Value) -> Result<T, CallError> {
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        Value::Object(_) => args.clone(),
        other => {
            return Err(CallError::InvalidArgument(format!(
                "{tool}: arguments must be an object, got {other}"
            )));
        }
    };
    serde_json::from_value(args).map_err(|e| CallError::InvalidArgument(format!("{tool}: {e}")))
}

/// Deserializer for optional args that refuses an explicit `null`: the
/// catalogue advertises `string`/`integer`/`boolean`, never a nullable, so
/// "absent" is spelled by omitting the key (serde's `default` covers that
/// path) and a present key must carry the declared type. Without this,
/// `Option<T>` would silently read `null` as absent - a laxer contract than
/// the schema at a boundary that should refuse ambiguity. The refusal is
/// deliberate (fail closed on a shape the schema does not describe); the one
/// documented null-as-absent exception is the shared `browser` routing
/// argument, which is dispatch's, not any builder's, and carries its own
/// rule in `extract_browser` (some MCP clients serialize an unset optional
/// as `null`, and a wrongly-typed browser target has its own dedicated
/// error).
fn present_and_typed<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Insert `key` only when the value is present, keeping optional args off the
/// wire entirely (the payload shapes are pinned by `build_payload_shapes`).
fn insert_opt<T: serde::Serialize>(
    payload: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<T>,
) {
    if let Some(v) = value {
        payload.insert(key.into(), json!(v));
    }
}

/// The arg shape of the no-argument ops: any object (extraneous keys are
/// ignored, like everywhere else), never a non-object root.
#[derive(Deserialize)]
struct EmptyArgs {}

pub(super) fn build_empty(args: &Value) -> Result<Value, CallError> {
    let EmptyArgs {} = parse("(no-argument op)", args)?;
    Ok(json!({}))
}

#[derive(Deserialize)]
struct TabTargetArgs {
    #[serde(rename = "tabId")]
    tab_id: i64,
}

pub(super) fn build_tab_focus(args: &Value) -> Result<Value, CallError> {
    let a: TabTargetArgs = parse("tab_focus", args)?;
    Ok(json!({ "tabId": a.tab_id }))
}

pub(super) fn build_tab_close(args: &Value) -> Result<Value, CallError> {
    let a: TabTargetArgs = parse("tab_close", args)?;
    Ok(json!({ "tabId": a.tab_id }))
}

#[derive(Deserialize)]
struct UrlArgs {
    url: String,
}

pub(super) fn build_tab_open(args: &Value) -> Result<Value, CallError> {
    let a: UrlArgs = parse("tab_open", args)?;
    Ok(json!({ "url": a.url }))
}

pub(super) fn build_page_navigate(args: &Value) -> Result<Value, CallError> {
    let a: UrlArgs = parse("page_navigate", args)?;
    Ok(json!({ "url": a.url }))
}

#[derive(Deserialize)]
struct PageEvalArgs {
    code: String,
}

pub(super) fn build_page_eval(args: &Value) -> Result<Value, CallError> {
    let a: PageEvalArgs = parse("page_eval", args)?;
    Ok(json!({ "code": a.code }))
}

#[derive(Deserialize)]
struct PagePressArgs {
    keys: String,
}

pub(super) fn build_page_press(args: &Value) -> Result<Value, CallError> {
    let a: PagePressArgs = parse("page_press", args)?;
    Ok(json!({ "keys": a.keys }))
}

/// The shared element-target pair: `ref` preferred, `selector` the fallback,
/// both optional at this boundary (the extension resolves the target and
/// reports its own error when neither matches).
#[derive(Deserialize)]
struct RefOrSelectorArgs {
    #[serde(rename = "ref", default, deserialize_with = "present_and_typed")]
    element_ref: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    selector: Option<String>,
}

impl RefOrSelectorArgs {
    fn into_payload(self) -> serde_json::Map<String, Value> {
        let mut payload = serde_json::Map::new();
        insert_opt(&mut payload, "ref", self.element_ref);
        insert_opt(&mut payload, "selector", self.selector);
        payload
    }
}

/// page_click and page_hover read the same two optional keys; each keeps its
/// own thin builder so a refusal names the tool that was actually called.
fn ref_or_selector(tool: &str, args: &Value) -> Result<Value, CallError> {
    let a: RefOrSelectorArgs = parse(tool, args)?;
    Ok(Value::Object(a.into_payload()))
}

pub(super) fn build_page_click(args: &Value) -> Result<Value, CallError> {
    ref_or_selector("page_click", args)
}

pub(super) fn build_page_hover(args: &Value) -> Result<Value, CallError> {
    ref_or_selector("page_hover", args)
}

#[derive(Deserialize)]
struct TargetValueArgs {
    #[serde(flatten)]
    target: RefOrSelectorArgs,
    value: String,
}

pub(super) fn build_page_fill(args: &Value) -> Result<Value, CallError> {
    let a: TargetValueArgs = parse("page_fill", args)?;
    let mut payload = a.target.into_payload();
    payload.insert("value".into(), json!(a.value));
    Ok(Value::Object(payload))
}

pub(super) fn build_page_select(args: &Value) -> Result<Value, CallError> {
    let a: TargetValueArgs = parse("page_select", args)?;
    let mut payload = a.target.into_payload();
    payload.insert("value".into(), json!(a.value));
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct ConsoleGetArgs {
    #[serde(default, deserialize_with = "present_and_typed")]
    limit: Option<i64>,
}

pub(super) fn build_console_get(args: &Value) -> Result<Value, CallError> {
    let a: ConsoleGetArgs = parse("console_get", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "limit", a.limit);
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct PageHandleDialogArgs {
    action: String,
    #[serde(rename = "promptText", default, deserialize_with = "present_and_typed")]
    prompt_text: Option<String>,
}

pub(super) fn build_page_handle_dialog(args: &Value) -> Result<Value, CallError> {
    let a: PageHandleDialogArgs = parse("page_handle_dialog", args)?;
    let mut payload = serde_json::Map::new();
    payload.insert("action".into(), json!(a.action));
    insert_opt(&mut payload, "promptText", a.prompt_text);
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct PageUploadArgs {
    selector: String,
    path: String,
}

pub(super) fn build_page_upload(args: &Value) -> Result<Value, CallError> {
    let a: PageUploadArgs = parse("page_upload", args)?;
    Ok(json!({ "selector": a.selector, "path": a.path }))
}

#[derive(Deserialize)]
struct PageScrollArgs {
    #[serde(default, deserialize_with = "present_and_typed")]
    direction: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    pixels: Option<i64>,
}

pub(super) fn build_page_scroll(args: &Value) -> Result<Value, CallError> {
    let a: PageScrollArgs = parse("page_scroll", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "direction", a.direction);
    insert_opt(&mut payload, "pixels", a.pixels);
    Ok(Value::Object(payload))
}

/// The `page_wait_for` timeout applied when the caller sends none - the one
/// advertised default a builder applies. One home: the builder below applies
/// it, and a catalogue test asserts the advertised description embeds this
/// exact value, so the served contract cannot drift from the behavior. The
/// extension's own fallback (src/apps/extension/src/lib/dom/page-api.ts
/// waitFor) mirrors it and is pinned by a source-text test there.
pub const DEFAULT_WAIT_TIMEOUT_MS: i64 = 30_000;

#[derive(Deserialize)]
struct PageWaitForArgs {
    #[serde(default, deserialize_with = "present_and_typed")]
    selector: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    text: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    nav: Option<bool>,
    #[serde(rename = "timeoutMs", default, deserialize_with = "present_and_typed")]
    timeout_ms: Option<i64>,
}

pub(super) fn build_page_wait_for(args: &Value) -> Result<Value, CallError> {
    let a: PageWaitForArgs = parse("page_wait_for", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "selector", a.selector);
    insert_opt(&mut payload, "text", a.text);
    insert_opt(&mut payload, "nav", a.nav);
    payload.insert(
        "timeoutMs".into(),
        json!(a.timeout_ms.unwrap_or(DEFAULT_WAIT_TIMEOUT_MS)),
    );
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct PageSnapshotPreciseArgs {
    #[serde(rename = "frameId", default, deserialize_with = "present_and_typed")]
    frame_id: Option<String>,
}

pub(super) fn build_page_snapshot_precise(args: &Value) -> Result<Value, CallError> {
    let a: PageSnapshotPreciseArgs = parse("page_snapshot_precise", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "frameId", a.frame_id);
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct CookieGetArgs {
    #[serde(default, deserialize_with = "present_and_typed")]
    url: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    domain: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    name: Option<String>,
}

pub(super) fn build_cookie_get(args: &Value) -> Result<Value, CallError> {
    let a: CookieGetArgs = parse("cookie_get", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "url", a.url);
    insert_opt(&mut payload, "domain", a.domain);
    insert_opt(&mut payload, "name", a.name);
    Ok(Value::Object(payload))
}

#[derive(Deserialize)]
struct StorageGetArgs {
    #[serde(rename = "type", default, deserialize_with = "present_and_typed")]
    storage_type: Option<String>,
    #[serde(default, deserialize_with = "present_and_typed")]
    key: Option<String>,
}

pub(super) fn build_storage_get(args: &Value) -> Result<Value, CallError> {
    let a: StorageGetArgs = parse("storage_get", args)?;
    let mut payload = serde_json::Map::new();
    insert_opt(&mut payload, "type", a.storage_type);
    insert_opt(&mut payload, "key", a.key);
    Ok(Value::Object(payload))
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
