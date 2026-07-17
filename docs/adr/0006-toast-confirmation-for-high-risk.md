# ADR-0006: In-page Toast for high-risk actions, with a short confirmation-free window

- **Status**: Superseded by [ADR-0027](./0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md)
  (the confirmation surface moves off the page-reachable DOM into an
  extension-owned window; the risk tiering and the click grace window it
  introduced stand and moved into `confirm/gate.ts`). Phase 8 completes the
  supersession for `page_eval`/`page_upload` when their approval becomes the
  Secure Enclave tap.
- **Date**: 2026-07-07

## Context

Even after the user has granted a site through the allowlist ([ADR-0004](./0004-allowlist-with-optional-host-permissions.md)), "high-risk actions" remain inside that site, actions that can cause irreversible side effects:

- **Form submission** (clicking a `type=submit` button): placing orders, transfers, publishing, deleting
- **Link navigation** (clicking `<a href>` / role=link): navigating to a new page, possibly triggering server-side operations (GET requests can mutate data too)
- **Closing a tab on a high-risk domain**: accidentally closing a bank or admin console

If the AI executes these silently, the user may never realize what happened. A second-confirmation mechanism is needed.

## Decision

**Use in-page Toast confirmation plus a 60-second same-origin, same-kind confirmation-free window:**

1. **Trigger point**: before executing a click, if the target is submit/link-like, the content script calls `confirmWithToast()`
2. **Toast UI**: a card injected at the top right of the page, showing "Browser Bridge / Click 'xxx'?" with Allow/Deny buttons
3. **Timeout**: no response within 30 seconds auto-denies (prevents the tool call from hanging forever)
4. **Confirmation-free window**: after the user clicks Allow, the same origin plus the same action kind does not prompt again for 60 seconds (avoids annoying back-to-back confirmations)
5. **Tab closing**: `tab_close` in the background first sends a confirmation Toast to the target page and closes only after the user allows it

## Alternatives considered

### Option A: dedicated confirmation window (separate popup window)
- **Mechanism**: every high-risk action opens a separate window listing the action details
- **Pros**: highest assurance; plenty of UI space for full details
- **Cons**: heavy experience; every high-risk action means switching away to confirm; interrupts the AI's workflow
- **Not chosen**: the user picked the Toast (lightweight). The dedicated window is reserved for the future high-risk confirmation of `page_eval` ([ADR-0005](./0005-page-eval-disabled-by-default.md))

### Option B: in-page Toast plus a short confirmation-free window (the user's choice)
- **Pros**: light experience; consecutive same-kind operations are not annoying
- **Cons**: easy to miss (the Toast sits in a corner); within the 60-second window consecutive high-risk actions by the AI are not re-confirmed
- **Implemented in v0.1**

### Option C: tiered by risk (low-risk silent / high-risk confirmed)
- **Mechanism**: within granted domains, low-risk actions (ordinary clicks, form filling) are silent; only high-risk actions (eval, submit, navigation) prompt
- **Pros**: the best balance point
- **Cons**: high implementation complexity (a risk-tier table has to be maintained)
- **Not chosen**: the user picked option B at the time, but option C is really option B's natural evolution (the v0.1 implementation already implies tiers: only submit/link prompts a Toast, ordinary clicks are silent)

## Consequences

### Positive
- **Lightweight experience**: the Toast does not steal focus; the user can keep working
- **No permanent hangs**: the 30-second timeout denies, so tool calls never wedge
- **Friendly to consecutive operations**: the 60-second window means clicking 5 links in a row does not prompt 5 times

### Negative
- **Can be missed**: the Toast is in a corner; a user looking elsewhere may miss it
- **60-second window risk**: if the AI is subverted into consecutive high-risk actions inside the window, only the first is confirmed; this is the experience/security trade-off
- **Click layer only**: currently only clicks are gated; Enter-key form submission and JS-triggered submit are not (phase-two addition)

## Implementation details

`src/apps/extension/content.js`:

```javascript
// High-risk detection
function isHighRiskClick(el) {
  const role = roleOf(el);
  if (role === "button" && (el.getAttribute("type") || "").toLowerCase() === "submit") return true;
  if (el.tagName === "A" && el.hasAttribute("href")) return true;
  if (role === "link") return true;
  return false;
}

// Confirmation-free window
let lastConfirmed = { key: null, until: 0 };
async function confirmWithToast(question, actionDesc) {
  const key = `${location.origin}:${actionDesc}`;
  if (lastConfirmed.key === key && Date.now() < lastConfirmed.until) return; // inside the window
  const approved = await showToast(question);
  if (!approved) throw new Error(`user denied: ${actionDesc}`);
  lastConfirmed = { key, until: Date.now() + 60_000 };
}
```

- `showToast()`: injects the DOM card; the Promise resolves true/false
- Card styling is in `toast.css`, with the critical styles also inlined in `ensureToastHost()` (in case toast.css did not load)
- An extremely high z-index (2147483647) keeps it on top

## Known limitations (phase-two improvements)

1. **Only clicks are gated**: Enter-key form submission and `form.submit()` JS calls are not intercepted
2. **No SPA-route awareness**: "soft navigations" via pushState/replaceState do not trigger it (the user perceives a navigation, but nothing is intercepted)
3. **Confirmation-free key granularity**: currently `origin:actionType`; a finer `origin:actionType:targetSelector` could be considered later
4. **The Toast can be affected by page CSS**: despite the high z-index and inlined critical styles, an extreme page could override with `!important`

## Relationship to other ADRs

- With [ADR-0004](./0004-allowlist-with-optional-host-permissions.md): the allowlist is the first layer (site level), the Toast is the second (action level)
- Distinct from [ADR-0005](./0005-page-eval-disabled-by-default.md): the Toast covers UI actions (click/fill); page_eval, if implemented, needs a stronger confirmation (a dedicated window)
- Relationship to [ADR-0008](./0008-page-eval-confirmation-channel.md): `page_eval`, implemented later, reuses this ADR's in-page Toast but not its 60s grace window. Since the ADR-0008 update 2026-07-16, `page_eval` reconfirms on every call; the grace window described here governs click/fill/submit/navigation only.
