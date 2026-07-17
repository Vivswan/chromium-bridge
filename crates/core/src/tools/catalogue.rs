//! The tool catalogue: the [`Tool`] struct, the [`all`] catalogue, and the
//! [`schema`] helper used to build each tool's JSON-Schema `inputSchema`.

use serde_json::{json, Value};

/// A tool exposed over MCP.
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

pub fn all() -> Vec<Tool> {
    vec![
        Tool {
            name: "list_browsers",
            description:
                "List the browsers currently connected to the bridge. Returns each browser's \
                 label and its open-tab count. When more than one browser is connected, every \
                 other tool needs a `browser` argument set to one of these labels.",
            input_schema: schema(&[], &[]),
        },
        Tool {
            name: "tab_list",
            description: "List all open browser tabs. Returns id, title, url, and which is active.",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "tab_focus",
            description: "Bring a tab to the foreground (make it active).",
            input_schema: bridge_schema(
                &["tabId"],
                &[("tabId", "integer", "Tab id from tab_list")],
            ),
        },
        Tool {
            name: "tab_open",
            description:
                "Open a URL in a new tab. The host domain must be in the user's allowlist.",
            input_schema: bridge_schema(&["url"], &[("url", "string", "Absolute URL to open")]),
        },
        Tool {
            name: "tab_close",
            description:
                "Close an http(s) tab after showing a user-confirmation prompt in that page.",
            input_schema: bridge_schema(
                &["tabId"],
                &[("tabId", "integer", "Tab id from tab_list")],
            ),
        },
        Tool {
            name: "page_snapshot",
            description:
                "Capture the active tab's interactive elements as an accessibility-style tree. \
                 Each node has a stable `ref` (e.g. \"e3\"), a role, an accessible name, and a \
                 fallback CSS selector. Use the `ref` in page_click/page_fill when possible.",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_click",
            description:
                "Click an element on the active tab. Prefer passing `ref` (from page_snapshot); \
                 fall back to `selector`. Clicking a submit button or a link triggers a \
                 user-confirmation prompt.",
            input_schema: bridge_schema(
                &[],
                &[
                    (
                        "ref",
                        "string",
                        "Element ref from page_snapshot, e.g. \"e3\"",
                    ),
                    ("selector", "string", "CSS selector fallback"),
                ],
            ),
        },
        Tool {
            name: "page_fill",
            description:
                "Type a value into a form field on the active tab. Prefer `ref`; fall back to \
                 `selector`. Password fields are masked in logs/history.",
            input_schema: bridge_schema(
                &["value"],
                &[
                    ("ref", "string", "Element ref from page_snapshot"),
                    ("selector", "string", "CSS selector fallback"),
                    ("value", "string", "Text to type into the field"),
                ],
            ),
        },
        Tool {
            name: "page_text",
            description:
                "Return the visible text content of the active tab (sensitive fields masked).",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_screenshot",
            description: "Capture the visible viewport of the active tab as a PNG (base64).",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_scroll",
            description:
                "Scroll the active tab. Pass `direction` (up|down|top|bottom) or `pixels`.",
            input_schema: bridge_schema(
                &[],
                &[
                    ("direction", "string", "One of: up, down, top, bottom"),
                    (
                        "pixels",
                        "integer",
                        "Number of pixels to scroll (positive = down)",
                    ),
                ],
            ),
        },
        Tool {
            name: "page_wait_for",
            description:
                "Wait until a condition is met on the active tab, or until timeout. One of: \
                 `selector` exists, `text` appears, or `nav` waits for page load completion.",
            input_schema: bridge_schema(
                &[],
                &[
                    (
                        "selector",
                        "string",
                        "Wait for this selector to match an element",
                    ),
                    ("text", "string", "Wait for this text to appear in the page"),
                    ("nav", "boolean", "Wait for a navigation event"),
                    ("timeoutMs", "integer", "Max wait in ms (default 30000)"),
                ],
            ),
        },
        Tool {
            name: "page_eval",
            description:
                "HIGH RISK — execute arbitrary JavaScript on the active tab. EVERY call shows the \
                 user the full code in a confirmation prompt and waits for approval; there is no \
                 silent same-origin grace window for eval, so every page_eval re-prompts. The \
                 return value is \
                 masked (JWT / long hex / long numbers / token-like strings) by default. This is \
                 the most powerful tool: prefer page_click / page_fill / page_snapshot whenever \
                 possible, and only use page_eval when those cannot achieve the goal (custom \
                 events, reading framework state, SPA routing, canvas/WebGL, etc.). Code runs in \
                 the page's global scope, wrapped as `async`, so you can `await` and `return` a \
                 value. Async results are awaited. Errors are returned as {name, message}.",
            input_schema: bridge_schema(
                &["code"],
                &[("code", "string", "JavaScript code to execute")],
            ),
        },
        Tool {
            name: "page_snapshot_precise",
            description:
                "Like page_snapshot, but uses Chrome's debugger (CDP Accessibility.getFullAXTree) \
                 to capture the AUTHORITATIVE accessibility tree — accurate for shadow DOM and \
                 complex ARIA where the content-script approximation misses. The user is warned \
                 first (a brief on-page notice); Chrome then shows a 'Started debugging this \
                 browser' banner on all tabs for ~1 second while the snapshot is taken, then it \
                 disappears. Cannot run on chrome:// / web store pages, or tabs with DevTools \
                 open. Refs use a 'p' prefix (p1, p2...) and work with page_click / page_fill \
                 unchanged. Use this when page_snapshot misses elements or roles look wrong.",
            input_schema: bridge_schema(
                &[],
                &[(
                    "frameId",
                    "string",
                    "Optional: limit to a specific frame's tree",
                )],
            ),
        },
        Tool {
            name: "cookie_get",
            description:
                "Read cookies for the active tab (or a url/domain you specify). Includes httpOnly \
                 cookies (the main reason to use this over document.cookie). Scoped to hosts in \
                 the user's allowlist — unauthorized hosts silently return nothing. Read-only; \
                 there is no cookie_set (writing httpOnly cookies is a session-fixation risk). \
                 Values are masked (JWT / long hex / long numbers) before being returned. If you \
                 omit url/domain/name, cookies for the active tab's URL are returned.",
            input_schema: bridge_schema(
                &[],
                &[
                    (
                        "url",
                        "string",
                        "Return cookies that would be sent to this URL",
                    ),
                    ("domain", "string", "Match this domain and its subdomains"),
                    ("name", "string", "Exact cookie name to match"),
                ],
            ),
        },
        Tool {
            name: "storage_get",
            description:
                "Read the page's localStorage or sessionStorage (where frameworks like Auth0 / \
                 NextAuth / Firebase store tokens). Must run on the active tab; same-origin \
                 only (cross-origin iframes are not readable). Pass `key` to fetch one entry, \
                 or omit it to dump all entries (capped at 500). Values are ALWAYS masked \
                 (JWT / long hex / long numbers) — this masking is not toggleable. Read-only.",
            input_schema: bridge_schema(
                &[],
                &[
                    ("type", "string", "\"local\" (default) or \"session\""),
                    (
                        "key",
                        "string",
                        "Specific key to read; omit for all entries",
                    ),
                ],
            ),
        },
        Tool {
            name: "page_navigate",
            description:
                "Navigate the active tab to an http(s) URL. The host domain must be in the user's \
                 allowlist. This loads in the CURRENT tab (use tab_open to open a new tab \
                 instead).",
            input_schema: bridge_schema(
                &["url"],
                &[(
                    "url",
                    "string",
                    "Absolute http(s) URL to load in the active tab",
                )],
            ),
        },
        Tool {
            name: "page_back",
            description:
                "Navigate the active tab back one step in its session history (the browser Back \
                 button). Errors if there is nothing to go back to.",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_forward",
            description:
                "Navigate the active tab forward one step in its session history (the browser \
                 Forward button). Errors if there is nothing to go forward to.",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_reload",
            description: "Reload the active tab (the browser Reload button).",
            input_schema: bridge_schema(&[], &[]),
        },
        Tool {
            name: "page_press",
            description:
                "Send a keyboard key or combo to the active tab, e.g. \"Enter\", \"Escape\", or \
                 \"Control+A\". Dispatched as a synthetic keyboard event to the focused element, \
                 so page JavaScript handlers see it; the event is not trusted, so it may not \
                 trigger a native default action such as submitting a form (use page_click on the \
                 submit control for that). Every press shows an on-page confirmation prompt, \
                 because a keypress can submit or trigger an action.",
            input_schema: bridge_schema(
                &["keys"],
                &[(
                    "keys",
                    "string",
                    "A single key or combo, e.g. \"Enter\", \"Escape\", \"Tab\", \"a\", or \
                     \"Control+A\". Modifiers: Control, Shift, Alt, Meta.",
                )],
            ),
        },
        Tool {
            name: "page_hover",
            description:
                "Move the pointer over an element on the active tab (dispatches pointerover / \
                 mouseover / mouseenter / mousemove), revealing hover menus or tooltips. Prefer \
                 `ref` (from page_snapshot); fall back to `selector`.",
            input_schema: bridge_schema(
                &[],
                &[
                    (
                        "ref",
                        "string",
                        "Element ref from page_snapshot, e.g. \"e3\"",
                    ),
                    ("selector", "string", "CSS selector fallback"),
                ],
            ),
        },
        Tool {
            name: "page_select",
            description:
                "Choose an option in a <select> drop-down on the active tab. Prefer `ref` (from \
                 page_snapshot); fall back to `selector`. `value` matches an option by its value \
                 attribute, or by its visible text when no value matches. Fires input and change \
                 events so frameworks react. Shows an on-page confirmation prompt, because it \
                 changes form state.",
            input_schema: bridge_schema(
                &["value"],
                &[
                    (
                        "ref",
                        "string",
                        "Element ref from page_snapshot for the <select>",
                    ),
                    (
                        "selector",
                        "string",
                        "CSS selector fallback for the <select>",
                    ),
                    (
                        "value",
                        "string",
                        "Option to choose: its value attribute, or its visible text",
                    ),
                ],
            ),
        },
        Tool {
            name: "console_get",
            description: "Return recent console output from the active tab, captured via Chrome's \
                 debugger. Includes browser-logged entries (network, security, and deprecation \
                 warnings, which the debugger replays on attach) plus any console.* calls and \
                 uncaught errors during the short capture window; console.* output produced \
                 before this call is generally not available. Values are masked (JWT / long hex \
                 / long numbers / token-like strings), because console lines can carry tokens. \
                 Attaching briefly shows the 'Started debugging this browser' banner. `limit` \
                 caps the number of entries returned (default 100).",
            input_schema: bridge_schema(
                &[],
                &[("limit", "integer", "Max entries to return (default 100)")],
            ),
        },
        Tool {
            name: "page_handle_dialog",
            description:
                "Respond to a JavaScript dialog (alert / confirm / prompt) on the active tab: \
                 `action` is \"accept\" or \"dismiss\", with optional `promptText` for a \
                 prompt(). Uses Chrome's debugger (CDP Page.handleJavaScriptDialog). HIGH RISK, \
                 because accepting a dialog can confirm a destructive action, so this tool is OFF \
                 by default and must be enabled in the extension settings. A dialog blocks the \
                 page, so the confirmation cannot be shown in-page; the settings opt-in is the \
                 gate. Chrome needs the debugger attached when the dialog opens for it to be \
                 handleable (turn on CDP mode), otherwise the dialog may not be capturable.",
            input_schema: bridge_schema(
                &["action"],
                &[
                    ("action", "string", "\"accept\" or \"dismiss\""),
                    (
                        "promptText",
                        "string",
                        "Text to enter for a prompt() before accepting",
                    ),
                ],
            ),
        },
        Tool {
            name: "page_upload",
            description:
                "CRITICAL RISK - attach a LOCAL file from the user's disk to a file input \
                 (<input type=file>) on the active tab so the page can upload it. `selector` \
                 targets the file input; `path` is the absolute local file path. This can \
                 exfiltrate private local files to a web page, so it is OFF by default (enable in \
                 the extension settings) and EVERY call shows an on-page confirmation prompt \
                 displaying the exact file path before it proceeds. Uses Chrome's debugger (CDP \
                 DOM.setFileInputFiles); the 'Started debugging this browser' banner flashes \
                 while it runs. Do not use this unless the user explicitly asked to upload that \
                 specific file.",
            input_schema: bridge_schema(
                &["selector", "path"],
                &[
                    (
                        "selector",
                        "string",
                        "CSS selector for the <input type=file> element",
                    ),
                    (
                        "path",
                        "string",
                        "Absolute local filesystem path of the file to attach",
                    ),
                ],
            ),
        },
    ]
}

/// Helper to build a minimal JSON-Schema object schema with required + props.
fn schema(required: &[&str], props: &[(&str, &str, &str)]) -> Value {
    let properties: serde_json::Map<String, Value> = props
        .iter()
        .map(|(name, ty, desc)| {
            (
                (*name).to_string(),
                json!({ "type": *ty, "description": *desc }),
            )
        })
        .collect();
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    })
}

/// The optional `browser` routing argument every bridge-backed tool accepts
/// (which connected browser to run on). One tuple so the wording is identical
/// across the whole catalogue — the contract parity test compares it
/// byte-for-byte against contracts/tools.json.
const BROWSER_PROP: (&str, &str, &str) = (
    "browser",
    "string",
    "Optional: which connected browser to run this on - a label from list_browsers. Required \
     when more than one browser is connected.",
);

/// Like [`schema`], with the shared [`BROWSER_PROP`] appended. Used by every
/// tool whose call is routed over a bridge connection; `list_browsers` itself
/// (answered by the server, no routing) keeps the plain [`schema`].
fn bridge_schema(required: &[&str], props: &[(&str, &str, &str)]) -> Value {
    let mut with_browser = props.to_vec();
    with_browser.push(BROWSER_PROP);
    schema(required, &with_browser)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_unique() {
        let tools = all();
        let mut names: Vec<&str> = tools.iter().map(|t| t.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate tool names present");
    }

    #[test]
    fn tool_count_is_pinned() {
        // Bump deliberately when adding/removing a tool (keeps docs honest).
        assert_eq!(all().len(), 26);
    }

    // contracts/tools.json is the single source of truth for the catalogue.
    // tools.rs is verified against it here; the TS ops.ts is generated from it.
    #[test]
    fn matches_contract() {
        let contract: Value =
            serde_json::from_str(include_str!("../../../../contracts/tools.json")).unwrap();
        let ctools = contract["tools"].as_array().unwrap();
        let cnames: Vec<&str> = ctools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        let tools = all();
        let names: Vec<&str> = tools.iter().map(|t| t.name).collect();
        assert_eq!(
            names, cnames,
            "tools.rs names/order must match contracts/tools.json (run `make gen`)"
        );
        for t in &tools {
            let c = ctools.iter().find(|c| c["name"] == t.name).unwrap();
            assert_eq!(
                c["description"].as_str().unwrap(),
                t.description,
                "description mismatch for {} vs contract",
                t.name
            );
            assert_eq!(
                &t.input_schema, &c["inputSchema"],
                "inputSchema mismatch for {} vs contract",
                t.name
            );
        }
    }

    #[test]
    fn every_tool_has_object_schema() {
        for t in all() {
            assert_eq!(t.input_schema["type"], "object", "tool {}", t.name);
            assert!(t.input_schema["properties"].is_object(), "tool {}", t.name);
            assert!(t.input_schema["required"].is_array(), "tool {}", t.name);
        }
    }

    #[test]
    fn schema_builder_shape() {
        let s = schema(&["url"], &[("url", "string", "the url")]);
        assert_eq!(s["type"], "object");
        assert_eq!(s["required"][0], "url");
        assert_eq!(s["properties"]["url"]["type"], "string");
        assert_eq!(s["properties"]["url"]["description"], "the url");
    }
}
