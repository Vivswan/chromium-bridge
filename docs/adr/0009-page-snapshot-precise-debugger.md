# ADR-0009: page_snapshot_precise takes the authoritative a11y tree via chrome.debugger

- **Status**: Accepted
- **Date**: 2026-07-08
- **Supplements**: [ADR-0003](./0003-content-script-snapshot-vs-chrome-debugger.md) (the v0.1 decision to default to a content script)

## Context

[ADR-0003](./0003-content-script-snapshot-vs-chrome-debugger.md) decided that v0.1's `page_snapshot` defaults to a content-script approximation and does not call `chrome.debugger`, to avoid the infobar banner. The plan at the time was "add a `page_snapshot_precise` tool in phase two that attaches temporarily when targeting fails."

v0.1's content-script snapshot covers about 90% of scenarios, but it is inaccurate in these edge cases:
- **Closed shadow DOM**: completely unreachable from a content script
- **Complex ARIA**: the simplified accessible-name computation drifts (`aria-hidden` subtrees, presentational roles, `aria-describedby`)
- **computedRole/computedName**: Chrome's internal AOM results are not exposed to JS; the content script can only recompute
- **Cross-origin iframes**: unreadable due to same-origin restrictions

These cases need Chrome's **authoritative** a11y tree. The only way to get it is CDP's `Accessibility.getFullAXTree`.

## Decision

**Add a separate tool, `page_snapshot_precise`, that takes the authoritative a11y tree via `chrome.debugger` + CDP:**

| Dimension | Implementation |
|------|------|
| Trigger | Explicitly called by the AI (no automatic fallback on failure; failure detection is unreliable) |
| Infobar handling | Before attaching, show an informational Toast (blue scheme) via the content script: "Chrome will show a debugging banner; it disappears automatically." The user can cancel; a 30s timeout continues automatically |
| ref scheme | Reuses the `data-zcb-ref` attribute, with prefix `p` (precise) to distinguish from the content script's `e` |
| Execution location | background.js (SW): `chrome.debugger` can only be called from the extension context |

## Core technical chain (confirmed by protocol research)

```
chrome.debugger.attach({tabId}, "1.3")
  -> Accessibility.getFullAXTree()              // every AXNode carries backendDOMNodeId
  -> for each interactive node:
      DOM.resolveNode({backendNodeId})          // -> RemoteObjectId
      Runtime.callFunctionOn({                  // tag the element with data-zcb-ref
        objectId,
        functionDeclaration: "function(ref){this.setAttribute('data-zcb-ref',ref); return {role:..., name:...}; }",
        arguments: [{value: ref}]
      })
  -> chrome.debugger.detach({tabId})            // infobar disappears (must be in finally)
```

**Key facts (research-confirmed)**:
- Every AXNode carries a `backendDOMNodeId`, the bridge to the DOM
- `DOM.resolveNode({backendNodeId})` returns a `RemoteObjectId`
- `Runtime.callFunctionOn` can run JS on that node (set attributes, read info)
- `getFullAXTree` **does not need** `Accessibility.enable()` (enable only makes AXNodeIds stable across calls; backendDOMNodeId is already stable for us)
- An AXNode's `role`/`name` is Chrome's authoritative computation; use it directly, no recomputation

## Key advantage: the unified ref abstraction

The `data-zcb-ref` attribute set by the precise snapshot uses **exactly the same mechanism** as the content-script snapshot. content.js's `resolveTarget` already has the DOM-attribute fallback path:

```javascript
function resolveTarget(args) {
  if (args.ref) {
    let el = refMap.get(args.ref);                    // in-memory map (same-page content snapshot)
    if (!el) {
      el = document.querySelector(`[${REF_ATTR}="${args.ref}"]`);  // DOM attribute fallback (precise snapshot)
    }
    ...
  }
}
```

So `page_click`/`page_fill` can operate on nodes from the precise snapshot **with zero changes**. The unified ref abstraction fully decouples the two snapshot implementations.

## ref namespace isolation

Two counters would collide (the content script's `e3` and precise's `e3` pointing at different elements). Solution:
- content-script snapshot: `e1`/`e2`/`e3`...
- precise snapshot: `p1`/`p2`/`p3`...

Different prefixes; content.js looks up by attribute value, so no change is needed.

## Alternatives considered

### Option A: add a `precise: true` parameter to page_snapshot (no new tool)
- **Pros**: tool count does not grow
- **Cons**: the AI may forget the parameter; the return structure has to accommodate both sources
- **Not chosen**: the user picked a separate tool for the clearer boundary

### Option B: automatic fallback on failure (auto-attach after a content snapshot fails)
- **Pros**: invisible to the AI, self-healing
- **Cons**: failure detection is unreliable (a content snapshot can succeed while a click fails for other reasons, falsely triggering it); the debugger flash becomes unpredictable
- **Rejected**: the user explicitly declined it

### Option C: attach directly without the informational Toast
- **Pros**: fastest
- **Cons**: an unfamiliar "debugging" banner confuses or worries the user; no informed consent
- **Not chosen**: the user picked the pre-attach notification

## Infobar behavior (confirmed)

- **Shown for the whole attach duration**: the "Started debugging this browser" banner at the top of Chrome, on all tabs
- **Disappears after detach**
- **Cannot be dismissed**: except with the `--silent-debugger-extension-api` launch flag (violates project goal G2)
- attach -> take tree -> tag -> detach inside one handler, so the infobar only flashes (usually < 1 second)
- **The informational Toast warns in advance**, so the user is not alarmed

## Error-handling matrix

| Case | Handling |
|------|------|
| `chrome://`/`chrome-extension://`/webstore/`view-source:`/`about:` | Intercept up front, return an error (the debugger cannot attach) |
| "Another debugger already attached" | Return the error "please close DevTools for this tab" |
| User cancels (informational Toast) | Do not attach, return "cancelled" |
| onDetach mid-tree-fetch (user closes the tab/navigates) | Return an error, clean up state |
| Any error | **detach on the finally path**, so the infobar never sticks |

**Critical: `detach` must be on the finally path.** Every error must detach, otherwise the infobar shows forever, a UX disaster.

## Consequences

### Positive
- **Authoritative accuracy**: Chrome's internal a11y tree; shadow DOM and complex ARIA fully covered
- **No role/name recomputation**: read the AXNode fields directly
- **Unified refs**: page_click/fill need zero changes
- **Informed consent**: the informational Toast lets the user anticipate the infobar

### Negative
- **The infobar always appears**: even as a flash, every tab shows it
- **Conflicts with DevTools**: fails when the tab already has DevTools open
- **Unavailable on chrome:// and similar pages**: built-in restriction
- **A complex CDP chain**: multiple async steps, and every failure path must detach reliably
- **Somewhat slower**: multiple CDP commands; the content script's < 50ms versus perhaps 200-500ms for precise

### Neutral
- The precise snapshot uses `p`-prefixed refs, isolated from content's `e` prefix

## Implementation

- `extension/manifest.json`: add the `debugger` permission
- `extension/background.js`: the `snapshotPrecise(tabId)` function, the full CDP chain plus error handling
- `extension/content.js`: `showInfoToast` + the `page_snapshot_precise_info` case
- `extension/toast.css`: `.zcb-info-card` blue scheme
- `src/tools.rs`: tool definition + dispatch

## Relationship to other ADRs

- **Supplements [ADR-0003](./0003-content-script-snapshot-vs-chrome-debugger.md)**: ADR-0003 keeps the default on the content script (no infobar); this ADR provides the explicit precise fallback path. They coexist: use `page_snapshot` day to day (no infobar), and `page_snapshot_precise` when authority is needed (infobar flash plus notification)
- **Distinct from [ADR-0008](./0008-page-eval-confirmation-channel.md)**: the eval Toast is a high-risk confirmation (deny by default, requires an active Allow); precise's info Toast is informational (continue by default, requires an active cancel)
