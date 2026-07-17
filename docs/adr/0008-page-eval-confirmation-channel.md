# ADR-0008: page_eval high-risk confirmation channel

- **Status**: Amended by [ADR-0027](./0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md)
  (page_eval still confirms on every call, but the confirmation renders on the
  extension-owned window instead of an in-page toast). Phase 8 supersedes the
  channel entirely for page_eval by routing approval through the host Secure
  Enclave.
- **Date**: 2026-07-07
- **Supersedes**: [ADR-0005](./0005-page-eval-disabled-by-default.md) (the "do not implement in v0.1" decision)

## Context

[ADR-0005](./0005-page-eval-disabled-by-default.md) decided that v0.1 would not implement `page_eval` at all. The rationale was the attack surface: arbitrary JS execution can steal tokens and cookies and send requests as the user. v0.1 first proved the base architecture and security model.

v0.1 has shipped and been verified (protocol-level e2e PASS), and phase two has begun. `page_eval` is now due, but it must satisfy the preconditions ADR-0005 set at the time: **a high-risk confirmation channel plus return-value masking**.

## Decision

**Implement `page_eval` with an enlarged in-page confirmation Toast, a same-origin 60s confirmation-free window, and configurable return-value masking (on by default):**

| Dimension | Implementation |
|------|------|
| **Confirmation UI** | Enlarged in-page Toast (warning color scheme, distinct from the ordinary Toast) showing the full code (scrollable `<pre>`), the target domain, the tab title, and Allow/Deny; denies on a 30s timeout |
| **Confirmation-free window** | Reuses the existing `lastConfirmed` mechanism, key = `${origin}:eval`; after approval, same-origin evals do not prompt for 60 seconds |
| **Execution method** | `new Function('"use strict"; return (async () => { <code> })()')()`: global scope, supports await/return |
| **Return-value masking** | content.js masks the result **before** it leaves the page context (so raw tokens never travel the IPC chain). Regexes cover JWTs/long hex/long numbers/sensitive keys, applied recursively. The switch lives in `chrome.storage.local` (`evalMask`), default true, can be turned off in the popup |

## Alternatives considered

### Option A: dedicated extension window (chrome.windows.create)
- **Pros**: immune to page CSS; long code is fully visible
- **Cons**: complex to build (SW <-> window communication); an extra window interrupts the flow; the window can be occluded
- **Not chosen**: the user picked the in-page Toast; reusing the existing mechanism is lighter

### Option B: confirm every eval (no confirmation-free window)
- **Pros**: safest
- **Cons**: consecutive evals get annoying; eval should not be high-frequency, but debugging scenarios may run it repeatedly
- **Not chosen**: the user picked the same-origin 60s window, consistent with the existing Toast mechanism

### Option C: pre-authorization switch in the popup (once checked, all evals are silent)
- **Rejected**: the attack surface returns to "fully open", defeating the point of high-risk confirmation

### Alternatives for return-value masking
- **No masking**: simplest, but tokens/cookies/keys could enter the AI context and logs; high leak risk
- **Forced masking**: safest, but occasionally mangles legitimate data
- **Configurable (default on)**: the user chose this, balancing flexibility and safety

## The execution-method choice: the Function constructor

**Why not `eval(code)`**:
- eval is bound to the call-site scope (calling eval inside the content script closure cannot see the page's globals)
- In strict mode eval gets its own scope; assignments do not escape

**Why `new Function`**:
- Executes in the global scope, so it can reach the page's globals (variables on window, framework APIs)
- Supports `return` and `await` (wrapped as an async IIFE)
- Wrapping: `new Function('"use strict"; return (async () => { ' + code + ' })()')()`

**Known limitations**:
- A reliable execution timeout is hard (once the Function constructor is running, single-threaded JS cannot be interrupted from outside). Left for the future
- Syntax errors in the code throw `SyntaxError` at call time; try/catch is needed to return the error message

## Return-value serialization edge cases

eval can return any type; `serializeResult` must handle them safely:

| Type | Handling |
|------|------|
| Objects with circular references | Track with a WeakSet; already-visited nodes become `"[Circular]"` |
| DOM nodes | Replaced with `"<Element tag#id>"` |
| Error | Serialized as `{name, message, stack?}` |
| Symbol / BigInt / function | `.toString()` |
| Promise | Awaited automatically (already async-wrapped) |
| Oversized (>10KB) | Truncated with `"[truncated]"` |

## Risk note: the confirmation-free window is riskier for eval than for click

**The same-origin 60s window means**: after the user approves the first eval, a **completely different second eval within 60 seconds runs silently**.

Compare the click case: click's "same kind of action" (say, clicking 5 links in a row) is at least a similar operation; two eval calls are **entirely unrelated**. The first might be `document.title`, the second might be `fetch('/transfer', {...})`.

**Why this risk was accepted**:
1. eval should not be high-frequency (the tool description forces the AI to try page_click/page_fill first)
2. When the user approves the first call they are looking at the full code, so they are informed
3. Anyone genuinely worried can disable the whole eval capability in the popup (left as a future switch; not part of this design)

This risk is stated to the AI in the tool description and marked in the README's security-model table.

## Update (2026-07-15): new opt-out switch `confirmPageEval` (default on)

This ADR originally **rejected** "silent eval after pre-authorization" as option C. In practice, browser-bridge's core scenario is **letting the AI drive the browser fully automatically**, and requiring a human "Allow" click on every `page_eval` breaks the automation (`tab_close` likewise). Two settings were therefore added (both defaulting to **true**, preserving the original confirm-every-time behavior):

| Setting | When turned off | Default |
|------|--------|------|
| `confirmPageEval` | `page_eval` no longer prompts; arbitrary JS runs directly | on |
| `confirmTabClose` | `tab_close` no longer prompts "Close tab?" | on |

The differences from the originally rejected option C, and the reasons for accepting it:
1. **Default on**: no existing user's security posture changes; the user has to turn it off **deliberately**.
2. **Prominent warning on the Options page**: the card for turning off `confirmPageEval` states plainly "the AI will execute arbitrary JS with no prompt"; this is an **informed** choice.
3. **Consistency**: the three high-risk kinds (click / eval / tab close) now each have their own confirmation switch (`confirmHighRiskClick` / `confirmPageEval` / `confirmTabClose`), with uniform semantics, instead of the split state where clicks could be relaxed but eval could not.
4. The allowlist (site level) and `pageEvalEnabled` (master switch) remain in force as the other two gates.

Turning off `confirmPageEval` restores the "arbitrary JS with no prompt" attack surface; this is noted both in the switch's warning and here, and the trade-off is the user's to make.

## Update (2026-07-16): page_eval excluded from the same-origin grace window (fail-safe default)

(When this addendum was written the body above was still Chinese; the whole
file has since been translated to English.)

This update reverses the original grace-window choice for page_eval and turns
the rejected option into the shipped one. ADR-0008 first rejected option B
("confirm every eval", every eval reconfirms with no grace window) and instead
reused the same-origin 60s grace window keyed `origin:eval`, so that after one
approval any further eval on that origin within the window ran with no prompt.
The risk note above ("the confirmation-free window is riskier for eval than
for click") already recorded why that is dangerous: the two calls one approval
covers can be unrelated, `document.title` one time and
`fetch('/transfer', ...)` the next.

The zero-trust principle in AGENTS.md ("never weaken a check for convenience")
treats a silent same-origin window as exactly that kind of relaxation, so it
cannot stay the default. page_eval now behaves the way option B described: every
call reconfirms, and it is excluded from the grace window entirely. The one
exception is the explicit opt-out `confirmPageEval=false` (from the 2026-07-15
update above), which a user sets deliberately. The grace window
(`confirmGraceMs`, default 60000ms) stays in force for the lower-risk
click/submit confirmations, where the repeated action is similar and visible in
the UI. No new setting is added; `confirmGraceMs` no longer applies to eval.

What each remaining setting relaxes, and the residual the user accepts:

| Setting | Default | Relaxes | Residual if changed |
|---------|---------|---------|---------------------|
| `confirmPageEval` | `true` | Off = page_eval runs with no prompt at all | Arbitrary JS executes silently; user owns this by opting in (Options warning is explicit) |
| `confirmGraceMs` | `60000` | Applies to click/submit only; a same-origin re-click within the window does not re-prompt | A second same-origin click/submit within the window is silent. Does NOT affect eval |

Code: `extension/src/content/toast.ts` (`confirmWithEvalToast` no longer reads
or writes `lastConfirmed`), `extension/src/background/backends/cdp.ts`
(`pageEval` confirm block drops the grace check), and
`extension/src/content/eval.ts` / `extension/src/shared/settings.ts` comments.

This is the explicit, reviewed relaxation-of-a-default record the zero-trust
rule requires. Superseding only the eval portion of the grace-window decision;
the rest of ADR-0008 stands.

## Consequences

### Positive
- **Capability completed**: complex interactions (CustomEvent, SPA routing, reading JS variables, canvas) become possible
- **Masking prevents leaks**: return values are processed before leaving the page, so tokens never travel the IPC chain
- **Reuses existing mechanisms**: Toast + lastConfirmed + storage switches keep the code delta contained
  (see Update 2026-07-16: eval no longer uses lastConfirmed / the grace window)

### Negative
- **Larger attack surface**: arbitrary JS execution arrives; even with confirmation, one mistaken approval leaks
- **Confirmation-free window risk**: as described above, higher than the click case
  (superseded by Update 2026-07-16: eval is excluded from the grace window and always reconfirms; this risk no longer applies to eval)
- **Masking can mangle**: long numeric IDs and legitimate long hex (such as hashes) get masked; the user can turn the switch off
- **No execution timeout**: an infinite-loop eval hangs the tool call (the 120s session timeout backstops it, but the page stays stuck)

### Neutral
- page_eval is not ranked early in the default `tools/list` ordering, and its description forces the AI to use it sparingly

## Implementation

- `src/tools.rs`: add the Tool definition and the dispatch branch
- `extension/content.js`: `runEval()` + `confirmWithEvalToast()` + `serializeResult()` + `maskSensitive()` + `getMaskSetting()`
- `extension/toast.css`: `.zcb-eval-card` / `.zcb-eval-code` / `.zcb-eval-meta` warning color scheme
- `extension/popup.html/js`: the masking switch
- Docs: requirements FR-3 gains page_eval; architecture section 7 gains the Function-constructor choice

## Relationship to other ADRs

- **Supersedes [ADR-0005](./0005-page-eval-disabled-by-default.md)**: ADR-0005's "do not implement in v0.1" decision is overturned by this ADR; ADR-0005's status changes to Superseded by #0008
- **With [ADR-0006](./0006-toast-confirmation-for-high-risk.md)**: reuses the Toast mechanism, but eval's Toast is larger, shows the code, and uses the warning color scheme
- **With [ADR-0004](./0004-allowlist-with-optional-host-permissions.md)**: the allowlist remains the first layer (site level); the eval Toast is the action-level second layer
