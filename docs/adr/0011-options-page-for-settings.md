# ADR-0011: Settings managed through a dedicated Options page

- **Status**: Accepted
- **Date**: 2026-07-09

## Context

As phases two and three landed, the design accumulated a scatter of configurable security policies and behavior switches:

- **ADR-0008**'s `page_eval` return-value masking switch (`evalMask`), stuffed into the popup in v0.2
- **ADR-0006**'s high-risk-click confirmation, the 60-second grace window, and the 30s Toast timeout, all hard-coded in content.js
- **ADR-0009**'s pre-precise-snapshot notification: shown every time, cannot be turned off
- **ADR-0004**'s allowlist: revocable only, no manual add (a popup.js comment states outright that v0.1 did not build manual add)
- Per-tool enablement: no master switch

These values were initially hard-coded as "safe defaults", on the grounds that v0.1/v0.2 should prove the base architecture first. But the accumulation left the user with **no way at all** to adjust these behaviors: no turning off a confirmation they find annoying, no adjusting timeouts per scenario, and no disabling page_eval, the largest attack surface. The security policy was welded shut.

Meanwhile the popup, only 320px wide, was getting crowded (connection status + pending-grant dialog + allowlist + evalMask switch); piling more switches into it was unsustainable.

A unified settings entry point was needed.

## Decision

**Register a dedicated full-page Options page via manifest `options_ui` (`options.html`, opened in a new tab) to centrally manage every configurable item; add a "settings" button at the top of the popup that jumps to it; migrate the `evalMask` switch out of the popup.**

All settings live in `chrome.storage.local`, following the existing flat-key convention (matching `evalMask` / `allowlist`), persisted immediately on `change` (no "save" button, consistent with popup behavior).

### Settings inventory

| key | type | default | related | effect |
|-----|------|------|------|------|
| `pageEvalEnabled` | bool | true | ADR-0008 | page_eval master switch; when off, arbitrary-JS execution is refused outright |
| `evalMask` | bool | true | ADR-0008 | page_eval return-value masking |
| `confirmHighRiskClick` | bool | true | ADR-0006 | high-risk click (submit/link) confirmation switch |
| `warnPreciseSnapshot` | bool | true | ADR-0009 | informational notice before a precise snapshot |
| `confirmGraceMs` | int | 60000 | ADR-0006 | grace window for same-origin same-kind repeats after a confirmation (0 = confirm every time) |
| `clickToastTimeoutMs` | int | 30000 | ADR-0006 | click-confirmation Toast auto-deny timeout |
| `evalToastTimeoutMs` | int | 45000 | ADR-0008 | eval-confirmation Toast auto-deny timeout |
| `disabledTools` | string[] | [] | (none) | set of disabled tool (op) names |
| `allowAllSites` | bool | false | ADR-0004 | skip per-site approval, allow all sites |

## Alternatives considered

### Option A: stuff everything into the popup
- **Pros**: simplest, no new files; the user sees all settings on clicking the extension icon
- **Cons**: the popup is 320px wide and cannot scroll much; many switches make it cramped; the popup's role is "connection status + grant shortcuts", and mixing in a pile of settings muddies it
- **Not chosen**: the extension was already near the popup's capacity ceiling

### Option B: dedicated Options page (the user's choice)
- **Pros**: ample space, groupable, extensible; matches Chrome extension convention (the details page has an "Extension options" entry); the popup stays light
- **Cons**: one extra hop (click icon -> click settings); options page and popup are two contexts, syncing state through storage
- **Implemented**

### Option C: full-page tab only, drop the popup settings entry
- **Pros**: cleanest
- **Cons**: every settings visit goes through "extension details -> options"; poor discoverability
- **Rejected**: a jump button in the popup costs almost nothing and is friendlier

## Key design decisions

### 1. Tool disabling intercepts at the extension dispatch layer, not by filtering Rust tools/list

`disabledTools` is checked at the entry of `dispatch()` in `background.js`: a hit throws `Error("tool disabled in settings: <op>")`.

**Why not change `tools/list` in `src/tools.rs`**: the single source of settings is the extension (`chrome.storage.local`), which the Rust host cannot read. Making the AI literally "not see" disabled tools would require the extension to sync settings to the host (an IPC protocol change), a large effort that introduces cross-process consistency to maintain.

**The cost**: the AI still sees disabled tools in `tools/list` and gets a clear error only on call. Accepted after weighing: a disabled tool at least cannot execute, the error message is explicit, and this follows the principle of "security by interception, not by hiding."

### 2. The allowAllSites switch must also request the <all_urls> permission

With "allow all sites" on, `ensureAllowed` passes everything through with no per-site approval. But the extension still needs the `<all_urls>` host permission to inject content scripts into arbitrary pages; otherwise, with the grant check skipped, injection fails silently.

`optional_host_permissions: ["<all_urls>"]` is already declared. When the switch is turned on, the options page's change handler (a legitimate user gesture) calls `chrome.permissions.request({ origins: ["<all_urls>"] })`; if the user declines, the checkbox rolls back. On load, `chrome.permissions.contains` reconciles the stored value with the actual permission to prevent drift.

### 3. Adding a site on the options page does not proactively request host permission

Manually adding an allowlist entry only writes `chrome.storage.local`. Rationale: under MV3, `chrome.permissions.request` must run in a user-gesture (popup/action) context; the options page is an extension page but its permission requests are restricted. On the first real visit to that site, `ensureAllowed` triggers the normal permission flow (the popup grant dialog).

### 4. The DEFAULTS constant is mirrored in three places

The defaults are defined as a `DEFAULTS` object in each of `options.js` / `background.js` / `content.js` (content.js holds the in-page-behavior subset), with KEEP IN SYNC comments. This follows the project's existing cross-file sync convention (like the `op` strings mirrored across background.js / content.js / tools.rs).

## Consequences

### Positive
- **The security policy is adjustable**: the user can turn off annoying confirmations, tune timeouts, and disable page_eval per scenario; nothing is welded shut anymore
- **Clear responsibilities**: the popup focuses on connection status and grant shortcuts; settings belong to the options page
- **Extensible**: a new setting needs only a storage key, a DEFAULTS entry, and a UI control, in one uniform pattern
- **Conventional**: `options_ui` is the standard way Chrome extensions manage settings

### Negative
- **DEFAULTS mirrored three ways**: adding a setting means updating DEFAULTS in three files, easy to miss. Constrained by extension scripts loading independently with no shared module in a lightweight setup (the project consistently uses comment-convention sync)
- **Tool disabling is not hiding**: the AI still sees disabled tools and is stopped by the call-time error, not "truly removed from the tool set"
- **allowAllSites risk**: once on, any site (banks/email/intranet included) can be operated without a grant; the UI carries a prominent warning but the final judgment is the user's

### Neutral
- Settings take effect immediately (a change is stored at once, the next action reads the new value), but in-memory caches in already-injected content.js (such as `_maskCache`) refresh only on the next eval

## Implementation details

- `extension/manifest.json`: add `options_ui: { page: "options.html", open_in_tab: true }`
- `extension/options.html`: full-page layout, grouped (security / confirmation timeouts and grace window / tool enablement / allowed sites), dangerous switches get a yellow warning card
- `extension/options.js`: storage read/write, immediate form persistence, allowlist add/remove, allowAllSites permission request/removal/reconciliation
- `extension/popup.html` / `popup.js`: add the settings button (`openOptionsPage`), remove the evalMask section
- `extension/background.js`: DEFAULTS + `getSetting`, disabledTools interception at the `dispatch` entry, the `add_allow` message, `snapshotPrecise` reads warnPreciseSnapshot, `ensureAllowed`/`ensureDomainAllowed` read allowAllSites
- `extension/content.js`: DEFAULTS + `getSetting`, runEval reads pageEvalEnabled, click reads confirmHighRiskClick, grace window/timeouts read from storage

## Relationship to other ADRs

- **[ADR-0004](./0004-allowlist-with-optional-host-permissions.md)**: allowAllSites is the allowlist's "master switch" variant; it skips per-site approval but still rests on the same optional-host-permissions mechanism underneath. Manual allowlist add fills the gap v0.1 left
- **[ADR-0006](./0006-toast-confirmation-for-high-risk.md)**: confirmHighRiskClick / confirmGraceMs / clickToastTimeoutMs make that ADR's hard-coded values (60s grace, 30s timeout, confirmation on/off) configurable, with defaults matching the original decision
- **[ADR-0008](./0008-page-eval-confirmation-channel.md)**: pageEvalEnabled (master switch), evalMask (migrated from the popup), and evalToastTimeoutMs make that ADR's policy configurable
- **[ADR-0009](./0009-page-snapshot-precise-debugger.md)**: warnPreciseSnapshot makes the pre-precise-snapshot notice dismissible
