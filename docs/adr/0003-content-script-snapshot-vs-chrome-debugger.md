# ADR-0003: Snapshot via content script, not chrome.debugger

- **Status**: Accepted
- **Date**: 2026-07-07

## Context

One of browser-bridge's core capabilities is `page_snapshot`: return the page's accessibility tree (a11y tree) so the AI can reference elements by stable `ref`s (like Playwright or chrome-devtools-mcp). The snapshot's accuracy directly determines how stable subsequent click/fill operations are; this is the lifeline of the whole system.

There are two implementation paths:

1. **chrome.debugger API**: attach to the tab and call `Accessibility.getFullAXTree` over CDP to get Chrome's internal, authoritative a11y tree
2. **Content script**: inject JS, walk the DOM with TreeWalker, and recompute role/accessible-name ourselves

Research (see the architecture research report) found one decisive constraint.

## The decisive constraint: chrome.debugger forces an infobar

**As soon as an extension calls `chrome.debugger.attach`, Chrome forcibly shows a "Started debugging this browser" banner at the top of every tab.**

- It cannot be dismissed from inside the extension (a hard-coded Chromium security feature)
- The only bypass is launching Chrome with the `--silent-debugger-extension-api` command-line flag, which is right back to "launch Chrome specially", violating the project's core goal G2 (zero special launches)
- The infobar shows on all tabs (not just the target tab) and pushes the viewport down about 30px, breaking coordinate-based targeting
- Enterprise force-install (ExtensionInstallForcelist) can also suppress it in some scenarios, but that requires enterprise policy and does not apply to individual users

This was confirmed through research during selection, and the user was explicit at the time that "the whole point of building an extension is to stop launching Chrome specially every time."

## Decision

**In v0.1, snapshot goes through a content script by default and does not call chrome.debugger:**

- Walk visible elements with `TreeWalker(SHOW_ELEMENT)`
- Recompute `role` (prefer `getAttribute('role')`, otherwise map by tag: `button->button`, `a[href]->link`, `input->textbox/checkbox/...`)
- Recompute the `accessible name` (simplified accname-1.2: `aria-label` -> `aria-labelledby` resolution -> `<label for>` -> `title` -> truncated innerText)
- Tag every meaningful node with `data-zcb-ref="eN"`; the map lives in the content script closure
- Return a slimmed tree: interactive nodes only, with a selector fallback

**Phase-two addition**: add a `page_snapshot_precise` tool. When targeting fails, the SW temporarily attaches -> takes `Accessibility.getFullAXTree` -> detaches immediately. The infobar flashes during that window, and **the tool description tells the user so explicitly**.

## Alternatives considered

### Option A: pure chrome.debugger (accept the infobar)
- **Pros**: authoritative, accurate a11y tree; shadow DOM included automatically; coverage close to 100%
- **Cons**: the infobar shows permanently; either tolerate it (bad UX, viewport shift breaks automation) or add the launch flag (violates G2)
- **Rejected**: conflicts with the project's core goal

### Option B: content script by default, temporary debugger attach when targeting fails (the user's final choice)
- **Pros**: no infobar day to day; edge cases have a fallback
- **Cons**:
  - Medium implementation complexity (attach/detach timing, error recovery)
  - The user will occasionally see the infobar flash (the design commits to disclosing this)
- **v0.1 status**: the content script part is implemented; the debugger fallback is deferred to phase two

### Option C: pure content script (the runner-up, not chosen)
- **Pros**: no infobar; invisible to the user; no special launch needed
- **Cons**: cannot read shadow DOM; complex ARIA recomputation drifts; roughly 10% of edge cases are inaccurate
- **Not chosen**: the user picked option B, wanting the debugger fallback

## Consequences

### Positive
- **Zero infobar day to day**: no debugger call, the user notices nothing
- **G2 intact**: no special Chrome launch needed
- **About 90% coverage**: sufficient for everyday interactions (button/input/link/menuitem)

### Negative
- **Shadow DOM unreadable**: closed shadow roots are completely unreachable; open shadow roots need dedicated traversal (not implemented in v0.1)
- **Complex ARIA is inaccurate**: `aria-hidden` subtrees, presentational roles, `aria-describedby`, and other edge cases drift under the simplified computation
- **Accessible-name computation is not authoritative**: Chrome's internal `element.computedRole`/`computedName` (AOM) is not exposed to JS, so the content script must recompute, and it will diverge from Chrome's actual tree
- **Cross-origin iframes**: unreadable due to same-origin restrictions on content scripts
- **Phase two owes the debugger fallback**: `page_snapshot_precise` plus attach/detach lifecycle handling still has to be built

## Implementation details (v0.1)

- The `snapshot()` function in `extension/content.js`
- `INTERACTIVE_TAGS` / `INTERACTIVE_ROLES` decide which nodes enter the tree
- `roleOf()` / `nameOf()` / `isVisible()` / `cssSelectorOf()` each hold their approximation logic
- refs are stored as a DOM attribute plus a content script Map, so they can be rebuilt from the DOM after an SW restart

## Known test gaps

- The DOM operations in content.js (snapshot/click/fill) **have not run on a real page yet**; the protocol-level e2e tests PASS, but the DOM layer awaits real testing once the user loads the extension
- Shadow DOM support and complex-ARIA accuracy need real-page verification before deciding the priority of the phase-two debugger fallback

## References

- Research: the Chrome infobar is hard-coded in Chromium (`chrome/app/generated_resources.grd`); `--silent-debugger-extension-api` is the only bypass
- Playwright aria snapshots and chrome-devtools-mcp both use CDP for exactly this reason
- AOM's `computedRole`/`computedName` is not exposed to content script JS; recomputation is the only option
