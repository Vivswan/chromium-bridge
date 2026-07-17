# ADR-0010: Read-only Cookie/Storage access

- **Status**: Accepted
- **Date**: 2026-07-08
- **Implemented**: phase three, first batch

## Context

The user scenario: "let the AI read the session token of a site I am logged into, for use elsewhere (local scripts, cross-tool calls, API debugging)."

The core value of this is the **httpOnly Cookie**: many sites (production environments especially) keep the session/JWT/refresh token in an httpOnly Cookie, which **page JS cannot read via `document.cookie`** (that is exactly httpOnly's security design). Only the `chrome.cookies` API can read it.

At the same time, many frontend frameworks (Auth0/NextAuth/Firebase) keep tokens in `localStorage`/`sessionStorage`, which a content script can read.

## Decision

**Add two read-only tools, `cookie_get` and `storage_get`, with no writes of any kind:**

| Dimension | Implementation |
|------|------|
| Scope | **Read-only**: `cookie_get` + `storage_get`; **no** cookie_set/cookie_remove/storage_set |
| Confirmation | Silent execution (like page_snapshot/page_text), no Toast |
| Host constraint | Reuses the existing allowlist; cookies are naturally constrained by host_permissions, storage by same-origin |
| Output masking | Reuses `maskSensitive` from [ADR-0008](./0008-page-eval-confirmation-channel.md) (JWT/long hex/long numbers/sensitive keys) |
| httpOnly | Reads include httpOnly Cookies (the core value) |

## Key research conclusions (the facts that shaped the design)

1. **The `chrome.cookies` API is constrained by host_permissions**: `getAll({})` returns only the cookies of granted domains, **not** every browser cookie. The blast radius matches the existing tools and reuses the existing allowlist ([ADR-0004](./0004-allowlist-with-optional-host-permissions.md)).
2. **It can read httpOnly Cookies**: the API exposes the `httpOnly` field and returns httpOnly cookies normally; this is the core value over `document.cookie`.
3. **Page localStorage must be read from a content script** (same-origin restriction); `chrome.storage` belongs to the extension itself and has nothing to do with the page. The two are different things. So `storage_get` lives in content.js and `cookie_get` in background.js.
4. **The `cookies` permission adds no install warning** (we already have debugger triggering the maximum host warning, so adding `cookies` costs nothing).
5. **`cookie_set` can forge httpOnly+Secure cookies** (a session-fixation attack vector, something even page XSS cannot do) -> **not implemented**.

## Tool design

### `cookie_get(details)`, runs in background.js
- Parameters (all optional, at least one to narrow the query):
  - `url` (string): returns cookies that would be sent to that URL
  - `domain` (string): matches that domain and subdomains
  - `name` (string): exact cookie-name match
- Implementation: call `chrome.cookies.getAll({url, domain, name})` -> mask values (keep name/domain/httpOnly structure) -> return
- Returns: `[{name, value(masked), domain, path, httpOnly, secure, sameSite, session, expirationDate?}]`
- Friendly hint: on empty results, suggest checking "is the domain granted" (Chrome returns an empty array, not an error, when ungranted)

### `storage_get(details)`, runs in content.js
- Parameters:
  - `type` ("local" | "session", default "local")
  - `key` (string, optional): a specific key; omitted returns everything (masked)
- Implementation: read from `window.localStorage` / `window.sessionStorage` -> mask -> return
- Returns: single key `{key, value(masked)}`; everything `{type, entries: {k:v(masked)}, count}`

## Why no cookie_set (the risk, restated)

`chrome.cookies.set` can forge **httpOnly+Secure** cookies, something even page XSS cannot do (page JS cannot set httpOnly cookies).

Consequence: if the AI is subverted (prompt injection), it could plant an **attacker-controlled session ID** into a site the user is logged into (session fixation). Even with a confirmation UI, one mistaken approval plants it, and the user can hardly notice; cookies are not visible the way clicks and form fills are.

Reading covers 90% of the scenario (taking the login state elsewhere); writing is rarely necessary. **Not building it = minimal attack surface**, in line with the security-first principle.

## Why no cookie_remove
- Safer than set (can only log out/clear), but the practical use is narrow (clearing login state to retry)
- Adding remove means adding a confirmation (users would ask "why is it deleting my cookies"), which adds complexity
- Not in v0.1, left for the future (if real demand appears, remove is safer than set and can be added later)

## Alternatives considered

### Option A: both read and write (cookie_set behind high-risk confirmation)
- **Pros**: most complete capability
- **Cons**: cookie_set can forge httpOnly cookies (session fixation); even with a confirmation UI, one mistaken approval plants a malicious session
- **Rejected**: the user chose read-only, the minimal attack surface

### Option B: read plus cookie_remove (no set)
- **Pros**: safer than full read-write; remove can only clear, not forge
- **Cons**: narrow use; needs a confirmation UI
- **Not chosen**: the user chose pure read-only

### Option C: confirm every read
- **Pros**: safest
- **Cons**: reads are frequent (fetching tokens, checking state); confirming each one breaks the flow
- **Rejected**: the user chose silent (consistent with page_snapshot/page_text)

## Consequences

### Positive
- **Completes the core scenario**: reading httpOnly cookies / localStorage tokens for cross-tool use
- **Zero added attack surface**: read-only, masked, constrained by the existing allowlist; blast radius equivalent to page_text
- **No install-warning cost**: the cookies permission is silent; debugger already triggered the maximum warning
- **Reuses masking**: no new code, page_eval's maskSensitive is used directly

### Negative
- **Empty-result ambiguity**: ungranted versus genuinely no data; Chrome does not distinguish, only a hint is possible
- **Masking can mangle**: legitimate long values (base64 configs and the like) get masked (shares the evalMask switch; can be refined later)
- **No IndexedDB support**: some frameworks (Airbnb LiteSet and the like) store tokens in IndexedDB; this design does not cover it

### Neutral
- Tool count 13 -> 15

## Known limitations

1. **localStorage is same-origin bound**: the content script reads only the origin of the page it is injected into; cross-origin iframes are unreachable
2. **Empty-result ambiguity**: the Chrome cookies API returns an empty array, not an error, when ungranted
3. **Masking-switch granularity**: `evalMask` currently affects both page_eval and cookie/storage; it could be split into separate switches later

## Relationship to other ADRs

- **Reuses [ADR-0004](./0004-allowlist-with-optional-host-permissions.md)**: the allowlist is the site-level first defense layer; Cookie/Storage is automatically constrained by it
- **Reuses [ADR-0008](./0008-page-eval-confirmation-channel.md)**: the `maskSensitive` function and its JWT/hex/number/sensitive-key pattern library
- **Distinct from [ADR-0008](./0008-page-eval-confirmation-channel.md)**: eval is execution (needs high-risk confirmation), Cookie/Storage is read-only (silent). Both mask, but the confirmation strength differs
- **Supplements the capability boundary of [ADR-0003](./0003-content-script-snapshot-vs-chrome-debugger.md)**: the content script reads localStorage (same-origin); chrome.debugger could read it too but is too heavy; the content script suffices here
