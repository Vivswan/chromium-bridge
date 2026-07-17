# ADR-0017: CDP mode (all page operations optionally via chrome.debugger)

- **Status**: Accepted
- **Date**: 2026-07-15
- **Related**: [ADR-0003](./0003-content-script-snapshot-vs-chrome-debugger.md) (content script by default), [ADR-0009](./0009-page-snapshot-precise-debugger.md) (CDP for the single precise tool), [ADR-0008](./0008-page-eval-confirmation-channel.md) (the page_eval confirmation channel)

## Context

On the default path, page-level operations (snapshot / click / fill / text / screenshot / scroll / wait_for / eval / storage_get) run through a content script injected by the background and driven via `chrome.tabs.sendMessage` (ADR-0003's decision: avoid chrome.debugger's "Started debugging this browser" infobar).

This path has one hard limit: **strict-CSP sites** (such as Bing and GitHub, which set `script-src` without `unsafe-eval`) block `new Function` / `eval` inside the content script, so `page_eval` fails outright. ADR-0009 already established that `chrome.debugger`'s `Runtime.evaluate` executes in the page's **MAIN world** and is not bound by the page's CSP (it is not the page eval'ing, it is the debugger evaluating). ADR-0009 used CDP for just one tool, `page_snapshot_precise` (attach -> take tree -> detach, so the infobar only flashes).

The requirement: provide a **global switch** that routes **all** page operations through CDP, so that:

- `page_eval` works on strict-CSP sites too;
- deep control comes with the consistent "Started debugging this browser" infobar behavior (uniformly in the MAIN world).

## Decision

**Add a user setting `cdpMode` (default `false`). When on, dispatch routes every page-level operation to the CDP backend; when off, behavior is byte-for-byte what it is today (still the content script).**

The implementation is organized around three patterns (`src/apps/extension/src/background/`):

| Role | Module | Responsibility |
|------|------|------|
| **Strategy** | `page-backend.ts` | The `PageBackend` interface + `selectBackend(cdpMode)`; two implementations: `ContentScriptBackend` (the existing path, extracted as-is) and `CdpBackend` |
| **Facade** | `cdp/session.ts` | `CdpSession` wraps one tab's `chrome.debugger`; `attach/detach/send/evaluate/screenshot`; also exports `dbgAttach/dbgDetach/dbgSend/isDebuggable` for precise.ts to reuse (DRY) |
| **Registry** | `cdp/registry.ts` | The `CdpSessionRegistry` singleton, `Map<tabId, CdpSession>`; lazily attaches and **keeps the attachment** (the infobar stays up for the duration of CDP mode, by design); teardown on tab close / onDetach / `cdpMode` turning off |
| **Portable page functions** | `cdp/page-fns.ts` | Self-contained functions (no imports, no closure over module scope) that are `toString()`ed and executed in the page via `Runtime.evaluate`, faithfully porting each content op's DOM logic one by one |

Key design points:

- **Unified refs**: CDP's `page_snapshot` runs **the same DOM traversal algorithm** as `content/snapshot.ts` (not the AX tree; that is `page_snapshot_precise`), setting **the same `data-zcb-ref="eN"`** attribute. The refs of the CDP and content paths are therefore fully interchangeable, and `page_click`/`page_fill` resolve through the DOM attribute lookup.
- **Confirmations without a content script**: the confirmation Toasts for high-risk clicks and `page_eval` are built, and the user's choice resolved, inside the page via `Runtime.evaluate` (`awaitPromise:true`); since CDP mode does not inject `toast.css`, the Toast styles are inlined. The settings gates (`confirmHighRiskClick`/`pageEvalEnabled`/`evalMask`), the 60s same-origin grace window (`confirmGraceMs`), and the `isHighRiskClick` logic all match the content path, with the grace-window state held in the SW.
  - Superseded in part by the ADR-0008 update 2026-07-16: `page_eval` no longer uses the `confirmGraceMs` grace window in either path and reconfirms on every call. `confirmGraceMs` now applies to high-risk clicks/submits only. The rest of this bullet (settings gates, inline Toast, `isHighRiskClick`, SW-held state) still holds, and the click grace window remains consistent between the CDP and content paths.
- **Serialization/masking**: `page_eval` takes the value back with CDP `returnByValue`, then reuses `shared/masking.ts` in the SW; `storage_get` reads raw values in the page and masks in the SW (always on, ADR-0010).
- **screenshot**: under CDP, prefer `Page.captureScreenshot` rather than a page function.
- **DRY**: `precise.ts` now imports `dbgAttach/dbgDetach/dbgSend/isDebuggable` from `cdp/session.ts` and deletes its private copies, with unchanged behavior.
- **contracts unchanged**: this is an execution-path switch, not a tool-contract change; `contracts/` and the tool definitions are untouched.

## Alternatives considered

### Option A: route only `page_eval` through CDP on CSP sites (everything else unchanged)
- **Pros**: smallest change; the infobar flashes only during eval
- **Cons**: snapshot/click/fill stay in the content world, so the ref scheme shuttles between two paths; "is this a CSP site" detection is unreliable (fail first, then fall back); the user cannot predict which path runs when
- **Not chosen**: the requirement is a **unified** deep-control switch, not a single-tool patch

### Option B: make CDP the default (remove the content script path)
- **Pros**: single implementation, no dual path
- **Cons**: the infobar becomes **permanent**, the exposure grows, and it violates ADR-0003's default trade-off; the vast majority of sites need no CSP bypass
- **Not chosen**: the default must remain content script, no infobar

### Option C: maintain the page logic as one big hand-written string
- **Cons**: high drift risk against the content sources
- **Not chosen**: instead "export real TS functions + `toString()`", validated by tsc/eslint/prettier, with self-containment verified at build time

## Consequences

### Positive
- **CSP bypass**: `page_eval` works even on strict-CSP sites (Bing and the like)
- **Unified deep control**: every page op runs in the MAIN world; refs interoperate with the content path
- **DRY**: the `chrome.debugger` primitives live in one place (`cdp/session.ts`), reused by precise
- **Zero regression by default**: with `cdpMode` off, dispatch takes the original `ContentScriptBackend`, byte-for-byte equivalent

### Negative (security trade-offs)
- **The infobar stays up**: during CDP mode the session stays attached and the "Started debugging this browser" banner shows the whole time (visible on every tab); this is a deliberate awareness signal
- **Larger exposure**: a debugger attached throughout has a larger theoretical attack surface than precise's attach-and-leave
- **CSP is bypassed**: page_eval runs even on strict-CSP sites (that is the goal, but it removes one layer of defense in depth)
- **Serialization differences**: CDP `returnByValue` serialization does not exactly match content's `serializeResult` (see "risks"), though both pass through the same `maskSensitive`
- **Performance**: multiple `Runtime.evaluate` round trips are slightly slower than content's single `sendMessage`

### Neutral
- Off by default; the user enables it explicitly on the Options page only when CSP bypass or unified deep control is needed
- A tab with DevTools open cannot be attached (the same limitation as precise)

## Implementation

- `src/apps/extension/src/background/page-backend.ts`, `backends/content-script.ts`, `backends/cdp.ts`
- `src/apps/extension/src/background/cdp/{session,registry,page-fns,click-risk}.ts`
- `src/apps/extension/src/background/dispatch.ts`: the page block becomes `selectBackend(cdpMode).run(op, args, tab)`
- `src/apps/extension/src/background/precise.ts`: reuses the `cdp/session.ts` primitives
- `src/apps/extension/src/background.ts`: `installCdpLifecycleListeners()` at startup
- `src/apps/extension/src/shared/{types,settings}.ts`: new `cdpMode` (default false)
- `src/apps/extension/options.html` + `options.ts`: new "execution mode" settings card
- Unit tests: `selectBackend`, `isHighRiskClick`/`describeAction`/`describeForToast`, `isDebuggable`, `buildEvaluateExpression`, page-fn self-containment
