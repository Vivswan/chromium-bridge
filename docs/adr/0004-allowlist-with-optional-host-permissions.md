# ADR-0004: Allowlist with on-demand optional host permissions

- **Status**: Accepted
- **Date**: 2026-07-07

## Context

When an AI operates the user's real browser, **the most dangerous thing** is that it can click/fill on arbitrary pages, above all banks, email, and logged-in admin consoles. Once the AI's instructions are subverted (prompt injection, model error), it could steal tokens, execute transfers, or leak private data.

A permission model is needed to control "which sites the AI can operate on."

## Decision

**Adopt a domain allowlist with on-demand grants, implemented with `optional_host_permissions` plus runtime `chrome.permissions.request`:**

1. **Manifest declaration**: `host_permissions: []` (no domain permissions initially) plus `optional_host_permissions: ["<all_urls>"]` (requestable at runtime)
2. **No manifest content_scripts**: everything is injected dynamically with `chrome.scripting.executeScript` (otherwise static matches simply never inject without host permission)
3. **First operation on a new domain**: the extension raises a popup; when the user clicks Allow it **simultaneously**:
   - calls `chrome.permissions.request({origins: [pattern]})` to request host permission for that domain
   - adds the domain to the allowlist in `chrome.storage.local`
4. **The allowlist is revocable**: the popup shows the granted domains, each individually revocable
5. **Persistence**: the allowlist lives in `chrome.storage.local` and survives SW restarts

## Alternatives considered

### Option A: static host_permissions: ["<all_urls>"] (grant everything once at install)
- **Pros**: simplest implementation; content scripts auto-inject on every page
- **Cons**:
  - Install shows the "read and change all your data on all websites" warning, scaring users away
  - Violates least privilege: the AI can instantly operate every site, including banks
  - No per-need control
- **Rejected**: the user explicitly chose the allowlist

### Option B: blocklist plus confirmation of critical actions
- **Mechanism**: all sites open by default, a blocklist for banks/payments, real-time confirmation of high-risk actions
- **Pros**: smooth experience, no permission step for each new site
- **Cons**: a blocklist has to be maintained (bank domains are many and changing); the default-open attack surface is large; relies on the user staying alert
- **Rejected**: the user chose the allowlist at decision time (safer)

### Option C: fully open (it is local anyway)
- **Mechanism**: no domain restrictions, no second confirmation, since it only runs on this machine
- **Cons**: security rests entirely on trusting every AI instruction; no protection against prompt injection
- **Rejected**: the user explicitly declined this

## Consequences

### Positive
- **Least privilege**: by default the AI can operate nothing; every new site needs an explicit user grant
- **Fine-grained revocation**: the user can revoke any domain in the popup at any time
- **Aligned with Chrome's permission model**: uses Chrome's native `optional_host_permissions` plus `permissions.request`, matching MV3 best practice
- **The allowlist persists**: storage.local survives SW restarts

### Negative
- **First-use friction**: each new site takes one popup click to authorize
- **A user gesture is required**: `permissions.request` can only be called in a popup/action-click context, not from the service worker in the background, so grants must go through the popup UI
- **Badge notification mechanism**: a pending grant sets the action badge to "!", and the user has to click the extension icon to open the popup (no response within 60 seconds auto-denies)
- **The cost of dropping manifest content_scripts**: `injectIfNeeded` is required (ping first, `executeScript` on failure), one extra round trip

### Neutral
- The allowlist's "domain" granularity is an origin glob (such as `https://example.com/*`), not an exact URL; this is enough for the vast majority of cases

## Implementation details

- `src/apps/extension/manifest.json`: `permissions: [tabs, scripting, storage, nativeMessaging]` (no activeTab, because injection happens from the background); `host_permissions: []`; `optional_host_permissions: ["<all_urls>"]`; **no content_scripts field**
- `src/apps/extension/background.js`:
  - `ensureAllowed(url)`: check whether the origin glob is on the allowlist; if not, `promptUserForAllow` (set badge + store `pendingAllow` + 60s timeout)
  - `injectIfNeeded(tabId)`: ping the content script, `chrome.scripting.executeScript` on failure
- `src/apps/extension/popup.js`: on `resolvePending`, call `chrome.permissions.request({origins: [pattern]})` and record the allowlist entry

## Design note

**Why not manifest content_scripts with static matches**: in MV3, even if the manifest declares content_scripts matches, the content script **will not inject** when the domain is not in host_permissions (or an already-granted optional permission). So static matches combined with initially empty host_permissions is completely dead. With dynamic injection the permissions follow the optional grants exactly: whichever domain is granted is the domain that gets injected, and the logic stays clear.

## Relationship to ADR-0006

The allowlist controls "which sites can be operated on"; Toast confirmation ([ADR-0006](./0006-toast-confirmation-for-high-risk.md)) controls "which actions inside a granted site need a second confirmation." The two defense layers complement each other: the allowlist guards against unknown sites, the Toast guards against dangerous actions on granted sites.
