//! The tool catalogue. One `catalogue!` row per tool is the only place a
//! tool's wire name, variant, args type, and record meet, so no second table
//! (a handler map, a grant table, a capability roster) can drift from it. The
//! TypeScript side is generated from the records (`moon run gen` runs the
//! `emit_contract` example and feeds `scripts/gen-ops.ts`).

use std::sync::Arc;

use rmcp::model::JsonObject;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::args::{
    ConsoleGetArgs, CookieGetArgs, ElementTargetArgs, NoArgs, PageEvalArgs, PageFillArgs,
    PageHandleDialogArgs, PageNavigateArgs, PagePressArgs, PageScrollArgs, PageSelectArgs,
    PageSnapshotPreciseArgs, PageUploadArgs, PageWaitForArgs, StorageGetArgs, TabOpenArgs,
    TabTargetArgs,
};
use super::capabilities::CapabilityId;
use crate::error::CallError;
use crate::policy::gating::Grant;
use crate::session::Session;

/// How much damage a misused call can do, driving the extension's policy UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
            Risk::Critical => "critical",
        }
    }
}

/// Where a bridge-routed tool acts in the browser: against a tab, or inside
/// a page. A tool the server answers itself has no scope here; its wire
/// scope is [`Tool::scope_name`]'s `"server"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Tab,
    Page,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Tab => "tab",
            Scope::Page => "page",
        }
    }
}

/// The Chrome extension permission the tool's implementation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Tabs,
    Scripting,
    Debugger,
    Cookies,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Tabs => "tabs",
            Permission::Scripting => "scripting",
            Permission::Debugger => "debugger",
            Permission::Cookies => "cookies",
        }
    }
}

/// When the extension must ask the user before executing the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    None,
    Warn,
    HighRisk,
    EveryCall,
}

impl Confirmation {
    pub fn as_str(self) -> &'static str {
        match self {
            Confirmation::None => "none",
            Confirmation::Warn => "warn",
            Confirmation::HighRisk => "high-risk",
            Confirmation::EveryCall => "every-call",
        }
    }
}

/// How a bridge-routed tool's response becomes MCP content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    /// The response JSON as one text block.
    Text,
    /// The response's base64 PNG as one image block, so the model sees the
    /// picture directly.
    Image,
}

/// Where a tool runs. A server-local tool needs nothing from the browser, so
/// it has no scope, no capability, and takes no `browser` routing argument;
/// a bridge tool has all three. The pairing is one value so neither half can
/// be stated without the other.
#[derive(Debug, Clone, Copy)]
pub enum Dispatch {
    /// Answered by the MCP server itself from the session state, within the call's deadline.
    ServerLocal(fn(&Session, std::time::Instant) -> Result<Value, CallError>),
    /// Routed over the bridge to the extension of the addressed browser.
    Bridge {
        scope: Scope,
        capability: CapabilityId,
        result: ResultKind,
    },
}

/// The one record of a tool: everything the MCP layer, the policy gate, the
/// capability negotiation, the dispatcher, and the generated TypeScript need.
#[derive(Debug, Clone, Copy)]
pub struct Tool {
    /// The MCP tool name and the bridge `op` tag; one string, used for both.
    pub name: &'static str,
    pub risk: Risk,
    pub permission: Permission,
    pub confirmation: Confirmation,
    /// The tool's own capability grants, every one of which must be on in
    /// the effective policy for it to run. [`Tool::required_grants`] adds the
    /// debugger master grant on top.
    pub grants: &'static [Grant],
    pub dispatch: Dispatch,
    /// The model-facing description. English is canonical; any localization
    /// happens in UI tiers, never here.
    pub description: &'static str,
    args_schema: fn() -> Arc<JsonObject>,
}

/// The optional `browser` routing argument every bridge tool accepts (which
/// connected browser to run on). It is the MCP server's, consumed before the
/// args reach the tool's struct, so it lives in [`Tool::input_schema`] and
/// nowhere in the args structs.
const BROWSER_ARG_DESCRIPTION: &str =
    "Optional: which connected browser to run this on - a label from list_browsers. Required \
     when more than one browser is connected.";

impl Tool {
    /// The wire scope the generated TypeScript and the docs table carry.
    pub fn scope_name(&self) -> &'static str {
        match self.dispatch {
            Dispatch::ServerLocal(_) => "server",
            Dispatch::Bridge { scope, .. } => scope.as_str(),
        }
    }

    /// The capability a bridge tool is negotiated under; `None` for a tool
    /// the server answers itself.
    pub fn capability(&self) -> Option<CapabilityId> {
        match self.dispatch {
            Dispatch::ServerLocal(_) => None,
            Dispatch::Bridge { capability, .. } => Some(capability),
        }
    }

    /// Every grant that must be on for the tool to run: `cdpMode`, the
    /// master grant for using Chrome's debugger at all, for every tool whose
    /// implementation needs the debugger permission, then the tool's own.
    pub fn required_grants(&self) -> impl Iterator<Item = Grant> + '_ {
        let master = (self.permission == Permission::Debugger).then_some(Grant::CdpMode);
        master.into_iter().chain(self.grants.iter().copied())
    }

    /// The JSON Schema of the tool's arguments exactly as the extension
    /// receives them in the bridge request's `args`: derived from the args
    /// struct, stripped of the struct's own title and doc (Rust-facing), the
    /// property descriptions kept for the model.
    pub fn args_schema(&self) -> JsonObject {
        let mut schema = (*(self.args_schema)()).clone();
        schema.remove("$schema");
        schema.remove("title");
        schema.remove("description");
        schema
    }

    /// The MCP `inputSchema`: [`Tool::args_schema`] plus, for a bridge tool,
    /// the `browser` routing argument the server consumes.
    pub fn input_schema(&self) -> JsonObject {
        let mut schema = self.args_schema();
        if let Dispatch::Bridge { .. } = self.dispatch {
            let properties = schema
                .entry("properties")
                .or_insert_with(|| Value::Object(JsonObject::new()));
            if let Value::Object(properties) = properties {
                properties.insert(
                    "browser".to_string(),
                    json!({ "type": "string", "description": BROWSER_ARG_DESCRIPTION }),
                );
            }
        }
        schema
    }
}

/// Every tool, in catalogue order (deterministic, so MCP clients may cache
/// the list).
pub fn all() -> impl Iterator<Item = Tool> {
    ToolId::ALL.iter().map(|id| id.tool())
}

macro_rules! catalogue {
    ($(
        $name:literal => $Variant:ident($Args:ty) {
            risk: $risk:ident,
            permission: $permission:ident,
            confirmation: $confirmation:ident,
            grants: [$($grant:ident),* $(,)?],
            dispatch: $dispatch:expr,
            description: $description:literal $(,)?
        }
    )+) => {
        /// One bridge request body, `{"op": <name>, "args": {...}}` on the wire.
        /// The extension's generated `strictObject` validators derive from the
        /// same args structs, so both ends share one field inventory,
        /// required-ness, and integer range.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(tag = "op", content = "args", deny_unknown_fields)]
        #[schemars(crate = "rmcp::schemars")]
        pub enum BridgeCommand {
            $(
                #[doc = concat!("The `", $name, "` tool; its model-facing description is on the catalogue record.")]
                #[serde(rename = $name)]
                $Variant($Args),
            )+
        }

        /// A tool's identity, the index of the catalogue: one variant per
        /// tool, resolved from an MCP tool name by [`ToolId::from_name`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ToolId {
            $($Variant,)+
        }

        impl ToolId {
            /// Every tool, in catalogue order.
            pub const ALL: &'static [ToolId] = &[$(ToolId::$Variant),+];

            /// The tool named `name`, or `None` for a name outside the catalogue.
            pub fn from_name(name: &str) -> Option<ToolId> {
                match name {
                    $($name => Some(ToolId::$Variant),)+
                    _ => None,
                }
            }

            /// The tool's record.
            pub fn tool(self) -> Tool {
                match self {
                    $(ToolId::$Variant => Tool {
                        name: $name,
                        risk: Risk::$risk,
                        permission: Permission::$permission,
                        confirmation: Confirmation::$confirmation,
                        grants: &[$(Grant::$grant),*],
                        dispatch: $dispatch,
                        description: $description,
                        args_schema: rmcp::handler::server::common::schema_for_type::<$Args>,
                    },)+
                }
            }

            /// Parse `args` as this tool's typed arguments into the command
            /// the bridge carries. The same serde impl the frame reader uses,
            /// so a tool call and a bridge frame refuse the same shapes.
            pub fn parse_args(self, args: Value) -> Result<BridgeCommand, serde_json::Error> {
                match self {
                    $(ToolId::$Variant => {
                        serde_json::from_value::<$Args>(args).map(BridgeCommand::$Variant)
                    })+
                }
            }
        }

        impl BridgeCommand {
            /// The tool this command invokes.
            pub fn id(&self) -> ToolId {
                match self {
                    $(BridgeCommand::$Variant(_) => ToolId::$Variant,)+
                }
            }
        }
    };
}

catalogue! {
    "list_browsers" => ListBrowsers(NoArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::ServerLocal(super::list_browsers),
        description: "List the browsers currently connected to the bridge. Returns each browser's \
             label and its open-tab count. When more than one browser is connected, every \
             other tool needs a `browser` argument set to one of these labels.",
    }
    "tab_list" => TabList(NoArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "List all open browser tabs. Returns id, title, url, and which is active.",
    }
    "tab_focus" => TabFocus(TabTargetArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Bring a tab to the foreground (make it active).",
    }
    "tab_open" => TabOpen(TabOpenArgs) {
        risk: Medium,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Open a URL in a new tab. The host domain must be in the user's allowlist.",
    }
    "tab_close" => TabClose(TabTargetArgs) {
        risk: High,
        permission: Tabs,
        confirmation: EveryCall,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Close an http(s) tab after the user approves it in the extension's confirmation \
             window.",
    }
    "page_snapshot" => PageSnapshot(NoArgs) {
        risk: Low,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageSnapshot, result: ResultKind::Text },
        description: "Capture the active tab's interactive elements as an accessibility-style tree. \
             Each node has a stable `ref` (e.g. \"e3\"), a role, an accessible name, and a \
             fallback CSS selector. Use the `ref` in page_click/page_fill when possible.",
    }
    "page_click" => PageClick(ElementTargetArgs) {
        risk: High,
        permission: Scripting,
        confirmation: HighRisk,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Click an element on the active tab. Prefer passing `ref` (from page_snapshot); \
             fall back to `selector`. Clicking a submit button or a link triggers a \
             user-confirmation prompt.",
    }
    "page_fill" => PageFill(PageFillArgs) {
        risk: High,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Type a value into a form field on the active tab. Prefer `ref`; fall back to \
             `selector`. Password fields are masked in logs/history.",
    }
    "page_text" => PageText(NoArgs) {
        risk: Medium,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageRead, result: ResultKind::Text },
        description: "Return the visible text content of the active tab (sensitive fields masked).",
    }
    "page_screenshot" => PageScreenshot(NoArgs) {
        risk: Medium,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::TabControl, result: ResultKind::Image },
        description: "Capture the visible viewport of the active tab as a PNG (base64).",
    }
    "page_scroll" => PageScroll(PageScrollArgs) {
        risk: Low,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Scroll the active tab. Pass `direction` (up|down|top|bottom) or `pixels`.",
    }
    "page_wait_for" => PageWaitFor(PageWaitForArgs) {
        risk: Low,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Wait until a condition is met on the active tab, or until timeout. One of: \
             `selector` exists, `text` appears, or `nav` waits for page load completion.",
    }
    "page_eval" => PageEval(PageEvalArgs) {
        risk: Critical,
        permission: Scripting,
        confirmation: EveryCall,
        grants: [PageEval],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageEval, result: ResultKind::Text },
        description: "HIGH RISK - execute arbitrary JavaScript on the active tab. EVERY call shows the \
             user the full code in a confirmation prompt and waits for approval; there is no \
             silent same-origin grace window for eval, so every page_eval re-prompts. The \
             return value is \
             masked (JWT / long hex / long numbers / token-like strings) by default. This is \
             the most powerful tool: prefer page_click / page_fill / page_snapshot whenever \
             possible, and only use page_eval when those cannot achieve the goal (custom \
             events, reading framework state, SPA routing, canvas/WebGL, etc.). Code runs in \
             the page's global scope, wrapped as `async`, so you can `await` and `return` a \
             value. Async results are awaited. Errors are returned as {name, message}.",
    }
    "page_snapshot_precise" => PageSnapshotPrecise(PageSnapshotPreciseArgs) {
        risk: Medium,
        permission: Debugger,
        confirmation: Warn,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageSnapshotPrecise, result: ResultKind::Text },
        description: "Like page_snapshot, but uses Chrome's debugger (CDP Accessibility.getFullAXTree) \
             to capture the AUTHORITATIVE accessibility tree - accurate for shadow DOM and \
             complex ARIA where the content-script approximation misses. The user is warned \
             first (a brief on-page notice); Chrome then shows a 'Started debugging this \
             browser' banner on all tabs for ~1 second while the snapshot is taken, then it \
             disappears. Cannot run on chrome:// / web store pages, or tabs with DevTools \
             open. Refs use a 'p' prefix (p1, p2...) and work with page_click / page_fill \
             unchanged. Use this when page_snapshot misses elements or roles look wrong.",
    }
    "cookie_get" => CookieGet(CookieGetArgs) {
        risk: High,
        permission: Cookies,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::CookieRead, result: ResultKind::Text },
        description: "Read cookies for the active tab (or a url/domain you specify). Includes httpOnly \
             cookies (the main reason to use this over document.cookie). Scoped to hosts in \
             the user's allowlist - unauthorized hosts silently return nothing. Read-only; \
             there is no cookie_set (writing httpOnly cookies is a session-fixation risk). \
             Values are masked (JWT / long hex / long numbers) before being returned. If you \
             omit url/domain/name, cookies for the active tab's URL are returned.",
    }
    "storage_get" => StorageGet(StorageGetArgs) {
        risk: High,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::StorageRead, result: ResultKind::Text },
        description: "Read the page's localStorage or sessionStorage (where frameworks like Auth0 / \
             NextAuth / Firebase store tokens). Must run on the active tab; same-origin \
             only (cross-origin iframes are not readable). Pass `key` to fetch one entry, \
             or omit it to dump all entries (capped at 500). Values are ALWAYS masked \
             (JWT / long hex / long numbers) - this masking is not toggleable. Read-only.",
    }
    "page_navigate" => PageNavigate(PageNavigateArgs) {
        risk: Medium,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Navigate the active tab to an http(s) URL. The host domain must be in the user's \
             allowlist. This loads in the CURRENT tab (use tab_open to open a new tab \
             instead).",
    }
    "page_back" => PageBack(NoArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Navigate the active tab back one step in its session history (the browser Back \
             button). Errors if there is nothing to go back to.",
    }
    "page_forward" => PageForward(NoArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Navigate the active tab forward one step in its session history (the browser \
             Forward button). Errors if there is nothing to go forward to.",
    }
    "page_reload" => PageReload(NoArgs) {
        risk: Low,
        permission: Tabs,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Tab, capability: CapabilityId::TabControl, result: ResultKind::Text },
        description: "Reload the active tab (the browser Reload button).",
    }
    "page_press" => PagePress(PagePressArgs) {
        risk: High,
        permission: Scripting,
        confirmation: EveryCall,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Send a keyboard key or combo to the active tab, e.g. \"Enter\", \"Escape\", or \
             \"Control+A\". Dispatched as a synthetic keyboard event to the focused element, \
             so page JavaScript handlers see it; the event is not trusted, so it may not \
             trigger a native default action such as submitting a form (use page_click on the \
             submit control for that). Every press shows a user-confirmation prompt (in \
             the extension's own window), because a keypress can submit or trigger an \
             action.",
    }
    "page_hover" => PageHover(ElementTargetArgs) {
        risk: Low,
        permission: Scripting,
        confirmation: None,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Move the pointer over an element on the active tab (dispatches pointerover / \
             mouseover / mouseenter / mousemove), revealing hover menus or tooltips. Prefer \
             `ref` (from page_snapshot); fall back to `selector`.",
    }
    "page_select" => PageSelect(PageSelectArgs) {
        risk: High,
        permission: Scripting,
        confirmation: EveryCall,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::PageInteract, result: ResultKind::Text },
        description: "Choose an option in a <select> drop-down on the active tab. Prefer `ref` (from \
             page_snapshot); fall back to `selector`. `value` matches an option by its value \
             attribute, or by its visible text when no value matches. Fires input and change \
             events so frameworks react. Shows a user-confirmation prompt (in the \
             extension's own window), because it changes form state.",
    }
    "console_get" => ConsoleGet(ConsoleGetArgs) {
        risk: Medium,
        permission: Debugger,
        confirmation: Warn,
        grants: [],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::ConsoleRead, result: ResultKind::Text },
        description: "Return recent console output from the active tab, captured via Chrome's \
             debugger. Includes browser-logged entries (network, security, and deprecation \
             warnings, which the debugger replays on attach) plus any console.* calls and \
             uncaught errors during the short capture window; console.* output produced \
             before this call is generally not available. Values are masked (JWT / long hex \
             / long numbers / token-like strings), because console lines can carry tokens. \
             Attaching briefly shows the 'Started debugging this browser' banner. `limit` \
             caps the number of entries returned (default 100).",
    }
    "page_handle_dialog" => PageHandleDialog(PageHandleDialogArgs) {
        risk: High,
        permission: Debugger,
        confirmation: Warn,
        grants: [HandleDialog],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::DialogControl, result: ResultKind::Text },
        description: "Respond to a JavaScript dialog (alert / confirm / prompt) on the active tab: \
             `action` is \"accept\" or \"dismiss\", with optional `promptText` for a \
             prompt(). Uses Chrome's debugger (CDP Page.handleJavaScriptDialog). HIGH RISK, \
             because accepting a dialog can confirm a destructive action, so this tool is OFF \
             by default and must be enabled in the extension settings. A dialog blocks the \
             page, so the confirmation cannot be shown in-page; the settings opt-in is the \
             gate. Chrome needs the debugger attached when the dialog opens for it to be \
             handleable (turn on CDP mode), otherwise the dialog may not be capturable.",
    }
    "page_upload" => PageUpload(PageUploadArgs) {
        risk: Critical,
        permission: Debugger,
        confirmation: EveryCall,
        grants: [FileUpload],
        dispatch: Dispatch::Bridge { scope: Scope::Page, capability: CapabilityId::FileUpload, result: ResultKind::Text },
        description: "CRITICAL RISK - attach a LOCAL file from the user's disk to a file input \
             (<input type=file>) on the active tab so the page can upload it. `selector` \
             targets the file input; `path` is the absolute local file path. This can \
             exfiltrate private local files to a web page, so it is OFF by default (enable in \
             the extension settings) and EVERY call shows a user-confirmation prompt (in \
             the extension's own window) displaying the exact file path before it \
             proceeds. Uses Chrome's debugger (CDP \
             DOM.setFileInputFiles); the 'Started debugging this browser' banner flashes \
             while it runs. Do not use this unless the user explicitly asked to upload that \
             specific file.",
    }
}
