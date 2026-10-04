//! The typed arguments of every tool: one struct per argument shape, shared
//! where two tools take literally the same fields with the same wording.
//! Each struct is the single source of three things: the parse of an MCP
//! `tools/call` (serde), the `args` of the bridge request the extension
//! receives (the struct serialized through), and the JSON Schema the model
//! and the generated TypeScript validators see (schemars, field docs as the
//! property descriptions).
//!
//! `deny_unknown_fields` on every struct matches the extension's
//! `strictObject`, so both ends of the bridge refuse the same frames. An
//! optional field is spelled by omitting the key: an explicit `null` is
//! refused ([`present_and_typed`]), because the schema advertises
//! `string`/`integer`/`boolean`, never a nullable. Integers are [`JsInt`],
//! bounded as the extension's `z.int()` is.

use std::borrow::Cow;

use rmcp::schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// An integer argument both ends of the bridge read as the same number:
/// bounded to JavaScript's safe range at the parse, exactly as the
/// extension's `z.int()` is, so a frame the host accepts is one the
/// extension accepts. A plain `i64` would take 2^53 here and be refused
/// there. The schema carries the bounds, so the envelope parity gate
/// compares the two integer forms verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct JsInt(i64);

const JS_SAFE_INT: i64 = 9_007_199_254_740_991;
// One owner for the bound: the policy module's, which the generated policy
// validators mirror.
const _: () = assert!(
    JS_SAFE_INT.unsigned_abs() == crate::policy::JS_SAFE_INT_MAX,
    "the args integer bound must be the policy module's JS-safe bound"
);

/// An integer outside JavaScript's safe range, which the extension's parser
/// would refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("integer {0} is outside the JavaScript-safe range the extension accepts")]
pub struct OutOfJsRange(pub i64);

impl JsInt {
    pub const MIN: JsInt = JsInt(-JS_SAFE_INT);
    pub const MAX: JsInt = JsInt(JS_SAFE_INT);

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl TryFrom<i64> for JsInt {
    type Error = OutOfJsRange;

    fn try_from(value: i64) -> Result<Self, OutOfJsRange> {
        (JsInt::MIN.0..=JsInt::MAX.0)
            .contains(&value)
            .then_some(JsInt(value))
            .ok_or(OutOfJsRange(value))
    }
}

impl From<i32> for JsInt {
    fn from(value: i32) -> Self {
        JsInt(i64::from(value))
    }
}

impl<'de> Deserialize<'de> for JsInt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        JsInt::try_from(i64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for JsInt {
    fn schema_name() -> Cow<'static, str> {
        "JsInt".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "integer", "minimum": JsInt::MIN.0, "maximum": JsInt::MAX.0 })
    }
}

/// Deserializer for an optional argument that refuses an explicit `null`.
/// `Option<T>` alone would read `null` as absent, laxer than the schema and
/// than the extension's validator.
fn present_and_typed<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The tools that take no arguments. An empty object is still an object:
/// a non-object root or any key is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct NoArgs {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[schemars(crate = "rmcp::schemars")]
pub struct TabTargetArgs {
    /// Tab id from tab_list
    pub tab_id: JsInt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct TabOpenArgs {
    /// Absolute URL to open
    pub url: String,
}

/// The element target of page_click and page_hover: `ref` preferred,
/// `selector` the fallback, both optional at this boundary (the extension
/// resolves the target and reports its own error when neither matches).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct ElementTargetArgs {
    /// Element ref from page_snapshot, e.g. "e3"
    #[serde(
        rename = "ref",
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub element_ref: Option<String>,
    /// CSS selector fallback
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub selector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageFillArgs {
    /// Element ref from page_snapshot
    #[serde(
        rename = "ref",
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub element_ref: Option<String>,
    /// CSS selector fallback
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub selector: Option<String>,
    /// Text to type into the field
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageScrollArgs {
    /// One of: up, down, top, bottom
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub direction: Option<String>,
    /// Number of pixels to scroll (positive = down)
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsInt")]
    pub pixels: Option<JsInt>,
}

/// The `page_wait_for` timeout applied when the caller sends none: the one
/// default the host fills in before the request goes over the bridge, so
/// the extension always receives an explicit `timeoutMs`. The extension's
/// own waitFor keeps the same literal as a fallback for its tests, pinned
/// to this const by a source-text test there.
pub const DEFAULT_WAIT_TIMEOUT_MS: i64 = 30_000;

const fn default_wait_timeout_ms() -> JsInt {
    JsInt(DEFAULT_WAIT_TIMEOUT_MS)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[schemars(crate = "rmcp::schemars")]
pub struct PageWaitForArgs {
    /// Wait for this selector to match an element
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub selector: Option<String>,
    /// Wait for this text to appear in the page
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub text: Option<String>,
    /// Wait for a navigation event
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "bool")]
    pub nav: Option<bool>,
    /// Max wait in ms
    #[serde(default = "default_wait_timeout_ms")]
    pub timeout_ms: JsInt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageEvalArgs {
    /// JavaScript code to execute
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[schemars(crate = "rmcp::schemars")]
pub struct PageSnapshotPreciseArgs {
    /// Optional: limit to a specific frame's tree
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub frame_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct CookieGetArgs {
    /// Return cookies that would be sent to this URL
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub url: Option<String>,
    /// Match this domain and its subdomains
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub domain: Option<String>,
    /// Exact cookie name to match
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct StorageGetArgs {
    /// "local" (default) or "session"
    #[serde(
        rename = "type",
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub storage_type: Option<String>,
    /// Specific key to read; omit for all entries
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageNavigateArgs {
    /// Absolute http(s) URL to load in the active tab
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PagePressArgs {
    /// A single key or combo, e.g. "Enter", "Escape", "Tab", "a", or "Control+A". Modifiers: Control, Shift, Alt, Meta.
    pub keys: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageSelectArgs {
    /// Element ref from page_snapshot for the `<select>`
    #[serde(
        rename = "ref",
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub element_ref: Option<String>,
    /// CSS selector fallback for the `<select>`
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub selector: Option<String>,
    /// Option to choose: its value attribute, or its visible text
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct ConsoleGetArgs {
    /// Max entries to return (default 100)
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsInt")]
    pub limit: Option<JsInt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[schemars(crate = "rmcp::schemars")]
pub struct PageHandleDialogArgs {
    /// "accept" or "dismiss"
    pub action: String,
    /// Text to enter for a prompt() before accepting
    #[serde(
        default,
        deserialize_with = "present_and_typed",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "String")]
    pub prompt_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(crate = "rmcp::schemars")]
pub struct PageUploadArgs {
    /// CSS selector for the <input type=file> element
    pub selector: String,
    /// Absolute local filesystem path of the file to attach
    pub path: String,
}
