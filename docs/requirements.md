# Requirements: browser-bridge

> Let MCP clients (such as Claude Code and Codex) operate **the real Chrome
> the user is already using** (real tabs, real login state, real cookies)
> instead of launching a blank simulated browser.

## 1. Background and problem

### 1.1 Current state
Users want to let an AI (via an MCP client) operate their own browser
directly: scrape logged-in pages, fill forms automatically, work with
information across tabs. But the AI has no such ability by default. It can
make HTTP requests, but it **cannot see or take over the browser sessions the
user already has open and logged in**.

### 1.2 Shortcomings of existing approaches

| Approach | Problem |
|------|------|
| CDP (launching Chrome specially with `--remote-debugging-port=9222`) | Requires a **browser restart**, breaking everyday usage; once the port is open, any process on the machine can control it, with no permission boundary |
| Playwright/Puppeteer launching a new instance | Not the user's browser: no login state, cookies, or extensions; requires logging in again every time |
| `chrome-devtools-mcp` (Microsoft) | Goes through CDP, so it still needs a special Chrome launch or an exposed debug port |
| Plain HTTP scraping | Cannot see login state; JS-rendered pages are unreachable |

### 1.3 The core problem we solve
**Without restarting Chrome and without exposing a debug port, let an AI
safely operate pages in the user's real browser.**

## 2. Goals and non-goals

### 2.1 Goals (v0.1)
- **G1 Real browser**: operate the Chrome the user is currently using, keeping all login state, extensions, and cookies
- **G2 Zero special launch**: install the extension once and it keeps working; no `--remote-debugging-port` launch each time
- **G3 Safe and controllable**: new sites require user authorization; high-risk actions (submit, navigation) get a real-time confirmation prompt
- **G4 MCP integration**: plugs into MCP clients as a standard MCP server, with a stable, composable tool set
- **G5 Single-binary distribution**: the entire backend compiles to one Rust binary; deployment = copying one file

### 2.2 Non-goals / deferred capabilities
- **`page_eval` has since been added**: early v0.1 did not implement arbitrary JS execution; phase two added it, with a high-risk confirmation channel + return-value masking. See [ADR-0008](./adr/0008-page-eval-confirmation-channel.md) (supersedes the earlier [ADR-0005](./adr/0005-page-eval-disabled-by-default.md))
- **Read-only cookie/storage has since been added**: phase three added `cookie_get` / `storage_get`, strictly read-only with masked output. See [ADR-0010](./adr/0010-cookie-storage-readonly.md)
- **Precise snapshot has since been added**: `page_snapshot_precise` uses chrome.debugger explicitly, warns the user before the call, and briefly shows an infobar while it runs. The default `page_snapshot` still uses the content script approximation. See [ADR-0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) and [ADR-0009](./adr/0009-page-snapshot-precise-debugger.md)
- **No recording/replay or batch task orchestration**. That is the phase-three playbook layer
- **No non-Chromium browsers**. Currently targets Google Chrome on macOS/Windows/Linux, plus Chromium on Linux

## 3. User stories

### US-1: Scrape a logged-in page
> As a developer, I want the AI to read the content of an internal system
> page I am **already logged into**, so it can help me analyze real data.

Acceptance: the AI calls `page_snapshot` + `page_text`; on first visit the
extension shows the authorization popup and I click Allow; after that it can
read the masked page text.

### US-2: Automatic form filling
> As an everyday user, I want the AI to fill a long list of fields (address,
> order details) in a web form for me, reducing manual typing.

Acceptance: the AI calls `page_snapshot` to get field refs, then `page_fill`
to fill them one by one; password fields are masked in the logs.

### US-3: Working across tabs
> As a researcher, I want the AI to list all my open tabs, locate one, and
> answer questions based on its content.

Acceptance: the AI calls `tab_list` -> `tab_focus` -> `page_snapshot` and
works across tabs.

### US-4: Safety confirmation
> As a user, when the AI is about to click "Submit order" or follow a link, I
> must have a chance to refuse, to avoid mistakes.

Acceptance: clicking a submit-type button or link shows a Toast in the top
right of the page; no response within 30 seconds rejects automatically; after
approval, same-origin actions of the same kind get a 60-second grace window.

### US-5: Developer extension integration
> As an MCP client user, I want to plug browser-bridge in as an MCP server so
> that saying "list my tabs" in a conversation just works.

Acceptance: after adding browser-bridge to the client's MCP server
configuration, the client's connection management UI shows `browser-bridge`
as connected and the tools are callable.

## 4. Functional requirements

### FR-1 Tab management
- `tab_list`: list all tabs (id/title/url/active)
- `tab_focus`: activate the given tab
- `tab_open(url)`: open a new tab (domain constrained by the allowlist)
- `tab_close(tabId)`: before closing an http(s) tab, show an in-page confirmation Toast

### FR-2 Page reading
- `page_snapshot`: returns an a11y-style tree of interactive elements; every node has a stable `ref`, role, accessible name, and a fallback selector
- `page_snapshot_precise`: the **precise version**: uses chrome.debugger + CDP to fetch Chrome's authoritative a11y tree, covering shadow DOM/complex ARIA; shows a notification Toast before attaching, during which Chrome's debug infobar flashes at the top (about 1 second); refs use a `p` prefix, and page_click/fill need no changes. See [ADR-0009](./adr/0009-page-snapshot-precise-debugger.md)
- `page_text`: returns the body text (password fields and suspected card numbers masked)
- `page_screenshot`: returns a PNG of the visible viewport (base64)

### FR-3 Page actions
- `page_click(ref|selector)`: click; submit/link types trigger the confirmation Toast
- `page_fill(ref|selector, value)`: fill a form field; uses native setters so frameworks (React/Vue) see the change; password field values are masked in logs
- `page_scroll(direction|pixels)`: scroll
- `page_wait_for(selector|text|nav, timeoutMs)`: wait for a selector/text, or wait for the page load to finish
- `page_eval(code)`: **high-risk**: executes arbitrary JS. Every call shows an enlarged Toast with the full code; same-origin 60s grace window; return values are masked by default (JWT/long hex/long digit runs/sensitive keywords), and masking can be turned off in the popup. Runs via `new Function` in the global scope, supporting await/return. See [ADR-0008](./adr/0008-page-eval-confirmation-channel.md)

### FR-4 Security controls
- **FR-4.1 Domain allowlist**: on the first operation against a new origin, the extension opens a popup requesting authorization; granting it also requests that domain's host permission via `chrome.permissions.request`. The allowlist is stored in `chrome.storage.local` and revocable from the popup. See [ADR-0004](./adr/0004-allowlist-with-optional-host-permissions.md)
- **FR-4.2 High-risk Toast**: submit clicks and link navigation trigger an in-page Toast; a 30-second timeout rejects; after approval, same-origin actions of the same kind get a 60-second grace window. See [ADR-0006](./adr/0006-toast-confirmation-for-high-risk.md)
- **FR-4.3 host authentication**: the native messaging manifest's `allowed_origins` hardcodes the extension ID; the bridge socket authenticates with a per-run secret + a lock file in the user directory (Unix mode 0600)
- **FR-4.4 Masking**: `page_text` masks `<input type=password>` and long digit runs; `page_fill` masks password field values when echoing arguments

### FR-5 Read-only cookie/storage (phase three)
- **FR-5.1 `cookie_get`**: reads cookies (including httpOnly), naturally constrained by host_permissions (reusing the allowlist); output values are masked, while structural fields (name/domain/httpOnly) are kept
- **FR-5.2 `storage_get`**: reads the page's localStorage/sessionStorage (content script, same origin); output is always masked (not governed by the evalMask switch, because the token-leak risk of a silent read is equivalent to eval)
- **FR-5.3 No writes**: no cookie_set / cookie_remove / storage_set. cookie_set could forge httpOnly cookies (session fixation), which not even XSS can do. See [ADR-0010](./adr/0010-cookie-storage-readonly.md)

## 5. Non-functional requirements

| Dimension | Requirement |
|------|------|
| **NFR-1 Performance** | Single tool-call round trip (excluding user confirmation) < 500ms (local path) |
| **NFR-2 Resources** | release binary < 1MB; resident MCP server memory < 20MB |
| **NFR-3 Zero runtime dependencies** | The user's machine needs Rust only at compile time; no Python/Node/any runtime at run time; no native dependencies beyond libc |
| **NFR-4 Robustness** | Recovers the connection automatically after the SW's 5-minute restart, a native host crash, or a Chrome restart |
| **NFR-5 Auditability** | Every security-relevant decision (authorization, confirmation, rejection) has an ADR; extension permission declarations are minimal |
| **NFR-6 PATH independence** | The host manifest uses absolute paths; no dependency on the user's shell PATH (known constraint: the user's PATH lacks `/opt/homebrew/bin`) |

## 6. Scope boundaries

### 6.1 Included in v0.1
- 11 tools (see FR-1 through FR-3); **phase two adds `page_eval` + `page_snapshot_precise`** (13 total); **phase three adds `cookie_get` + `storage_get`** (15 total)
- Two security layers: allowlist + Toast
- content-script-style snapshot
- macOS/Windows/Linux + Chrome; Linux also supports Chromium; WSL supports both modes, Windows Chrome interop and WSLg Linux browsers

### 6.2 Not in v0.1, later phases
- **Phase two**:
  - `page_snapshot_precise`: debugger-fallback precise snapshot (flashes the infobar; the user must be told)
  - `page_eval`: high-risk confirmation channel (enlarged Toast + same-origin 60s grace window + configurable masking). **Done**; see [ADR-0008](./adr/0008-page-eval-confirmation-channel.md)
  - `page_snapshot_precise`: debugger precise snapshot (notification Toast + infobar flash + p-prefixed refs). **Done**; see [ADR-0009](./adr/0009-page-snapshot-precise-debugger.md)
- **Phase three**:
  - `cookie_get` / `storage_get` (read-only, limited to allowlisted domains, masked output). **Done**; see [ADR-0010](./adr/0010-cookie-storage-readonly.md)
  - Skill layer (distill the frequent playbooks, scraping list pages, form filling, cross-tab work, into skills)
  - Recording/replay, batch task orchestration

### 6.3 Explicitly excluded
- No browser history/bookmarks/downloads management
- No network request interception/modification
- No multi-browser sync support

## 7. Phase plan

| Phase | Scope | Status |
|------|------|------|
| **Phase one: v0.1 minimum viable** | FR-1 through FR-4 + NFR-1 through 6 | Done: code complete, protocol-layer e2e tests PASS, awaiting user acceptance with the extension loaded |
| **Phase two: precision** | debugger-fallback snapshot, page_eval high-risk channel | Done (page_eval + page_snapshot_precise) |
| **Phase three: extended capabilities** | cookie/storage, skill layer, orchestration | In progress: cookie/storage done; skill layer/orchestration not started |

## 8. Acceptance criteria (v0.1)

1. `install.sh` (macOS/Linux) or `install.ps1` (Windows) runs through, the extension loads, and the host manifest is registered
2. The MCP client shows `browser-bridge` as connected
3. The AI says "list my tabs" in a conversation -> sees the real tab list
4. The AI says "screenshot the current page" -> the AI can analyze the screenshot
5. The AI says "type XXX in the search box and click search" -> it really executes in the user's browser; the submit shows a confirmation Toast
6. Visiting an unauthorized domain -> the extension shows the authorization popup
7. Protocol-layer end-to-end tests PASS (NM frames, MCP JSON-RPC, TCP bridge)

## 9. Glossary

| Term | Meaning |
|------|------|
| **MCP** | Model Context Protocol, the standard protocol between AIs and tools, based on JSON-RPC 2.0 |
| **Native Messaging** | Chrome's official mechanism for extensions to talk to local processes; frame format = 4-byte little-endian length + JSON |
| **MV3** | Manifest V3, the current Chrome extension standard; the background moves to a Service Worker |
| **SW** | Service Worker, MV3's background script, force-restarted by Chrome every 5 minutes |
| **CDP** | Chrome DevTools Protocol, the protocol for controlling Chrome through the debug port |
| **ref** | The stable identifier the snapshot assigns to each interactive element (e.g. `e3`); the AI uses it to locate elements |
| **a11y** | accessibility; the a11y tree is the semantic structure of a page's elements |
