# Tool risk matrix

Every tool the bridge exposes, with its risk level, what it reads and changes, whether it touches credentials, the Chrome permission it needs, and how the user is protected. This is the reference for security review: adding or changing a tool means updating this table, and the [review bar](../../.github/SECURITY.md#security-relevant-changes-review-bar) says what else the change carries.

Risk levels: **Low** (read-only, no sensitive data), **Medium** (reads page content or navigates), **High** (writes to the page, or reads credentials), **Critical** (arbitrary code or maximal blast radius).

The protections listed are the defaults. The confirmation gates are host-owned policy fields (`confirmHighRiskClick`, `confirmTabClose`, `confirmPageEval`, `presenceConfirm`, `confirmGraceMs`), edited with `genkan policy` (`set` signs a grant, `restrict` is free); the extension's options page can only tighten them. Relaxing one is an explicit, signed choice whose residual is tabulated in the [defaults table](../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe).

| Tool | Risk | Reads | Writes / effect | Credentials? | Chrome perm | User protection |
|------|------|-------|-----------------|--------------|-------------|-----------------|
| `list_browsers` | Low | connected browser labels + open-tab counts | - | no | `tabs` (via a routed `tab_list` per browser) | answered by the MCP server; no page access |
| `tab_list` | Low | tab titles/URLs | - | no | `tabs` | allowlist not required (metadata only) |
| `tab_focus` | Low | - | activates a tab | no | `tabs` | - |
| `tab_open` | Medium | - | opens a URL (navigation) | no | `tabs` | allowlist-gated origin |
| `tab_close` | High | tab title/URL | **closes a tab** (data loss) | no | `tabs` | extension-window confirm |
| `page_snapshot` | Low | interactive elements (a11y) | - | no | `scripting` | allowlist-gated; content injected |
| `page_click` | High [1] | element under ref | clicks (may submit/navigate) | no | `scripting` | extension-window confirm for submit/link |
| `page_fill` | High | - | types into a field | possibly (into password fields) | `scripting` | password value masked in the echo |
| `page_text` | Medium | visible page text | - | masked | `scripting` | passwords + long digit runs masked |
| `page_screenshot` | Medium | viewport pixels | - | possibly (whatever is on screen) | `tabs` | - |
| `page_scroll` | Low | scroll position | scrolls | no | `scripting` | - |
| `page_wait_for` | Low | selector/text presence | - | no | `scripting` | - |
| `page_navigate` | Medium | - | loads an http(s) URL in the active tab | no | `tabs` | allowlist-gated on the destination origin |
| `page_back` | Low | - | steps the active tab back in history | no | `tabs` | allowlist-gated on the current origin, not the destination ([residual](trust-boundaries.md#boundary-4-extension---web-page--chrome-api--content-script--dom)) |
| `page_forward` | Low | - | steps the active tab forward in history | no | `tabs` | allowlist-gated on the current origin, not the destination (the same residual) |
| `page_reload` | Low | - | reloads the active tab | no | `tabs` | allowlist-gated on the current origin |
| `page_press` | High | - | sends a synthetic key or combo to the page (may submit/navigate) | no | `scripting` | extension-window confirm, every call |
| `page_hover` | Low | - | moves the pointer over an element | no | `scripting` | allowlist-gated |
| `page_select` | High | - | chooses an option in a `<select>` | no | `scripting` | extension-window confirm, every call |
| `console_get` | Medium | recent console output incl. network errors | - | masked | `debugger` | allowlist-gated; output masked; "debugging" banner |
| `page_handle_dialog` | High | - | **accepts or dismisses** a JS dialog (alert/confirm/prompt) | no | `debugger` | **off by default** (opt-in); allowlist-gated; "debugging" banner |
| `page_upload` | **Critical** | the named local file's bytes | **attaches a local file** to a file input | possibly (any readable file) | `debugger` | **off by default** (opt-in); allowlist-gated; every-call extension-window confirm showing the exact path; the origin is rechecked after the confirm and the attach bound to the document node resolved then; see residual |
| `page_eval` | **Critical** | anything the page can | **arbitrary JS** in the page | yes (can read tokens/cookies) | `scripting` (host) | **off by default** under host-owned policy (`pageEvalEnabled`, granted with `policy set`); **every-call** extension-window confirm showing the full code; result masked |
| `page_snapshot_precise` | Medium | authoritative a11y tree (CDP) | - | no | `debugger` | pre-warn toast; "debugging" infobar flashes |
| `cookie_get` | High | cookies incl. **httpOnly** | - (read-only) | **yes** | `cookies` | allowlist-scoped; values masked; no `cookie_set` by design |
| `storage_get` | High | local/sessionStorage | - (read-only) | **yes** (tokens) | `scripting` | same-origin; values **always** masked |

[1] `page_click` is Medium for ordinary elements; **High** when the target is a submit button or a navigating link (those trigger the confirmation window).

## Cross-cutting protections

- **Browser routing never guesses:** with several browsers connected, a tool call must name one via its `browser` argument or it fails (`BROWSER_AMBIGUOUS`); an unknown label fails (`BROWSER_NOT_FOUND`). Each browser's connection is independently authenticated, and a connection that answers another browser's request is dropped.
- **Allowlist:** page-level tools run only on origins the user approved (a per-site prompt plus `chrome.permissions.request`). `allowAllSites` is an explicit opt-in.
- **Masking:** `page_text`, `cookie_get`, `storage_get`, and `page_eval` output run through the mask (JWTs, long hex, long digit runs, token-like strings). `storage_get` masking is not user-toggleable.
- **Confirmation grace window:** a repeated submit or link click under the [per-tab key](../../.github/SECURITY.md#page_eval-and-confirmation-defaults-fail-safe) skips the prompt within `confirmGraceMs`; `page_eval` never skips, so an earlier approval never lets later, unrelated code run. The same section owns the default.
- **Read-only by design:** no `cookie_set` or `storage_set` (writing httpOnly cookies is a session-fixation risk).
- **CDP mode (opt-in, off by default):** the `cdpMode` policy field reroutes every page-level tool through `chrome.debugger` in the page's MAIN world instead of a content script. No tool's contract, permission, confirmation, or masking changes; the protections above still apply.
  - **Its two costs:** it bypasses page CSP, so `page_eval` runs on strict-CSP sites, and it holds a persistent debugger attach for the tab, so the "Started debugging this browser" banner stays up the whole time it is on.

## When you add or change a tool

Update this table and follow the [review bar](../../.github/SECURITY.md#security-relevant-changes-review-bar). A change that raises a tool's blast radius (a new permission, a new sensitive read, a new write, a weaker confirmation, a wider masking bypass) also updates the [trust boundaries ledger](trust-boundaries.md) and takes a security-labeled review.
