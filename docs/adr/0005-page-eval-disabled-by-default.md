# ADR-0005: page_eval disabled by default

- **Status**: Superseded by [ADR-0008](./0008-page-eval-confirmation-channel.md)
- **Date**: 2026-07-07

> Note (current state): the title "page_eval disabled by default" is historical.
> page_eval is now implemented and enabled by default WITH a per-call
> confirmation (superseded by ADR-0008; every call reconfirms unless the user
> sets confirmPageEval=false). It is not disabled by default. This file is kept
> for the original v0.1 "do not implement" rationale and attack-surface analysis.

> **Superseded**: this ADR decided "do not implement page_eval in v0.1." After the
> v0.1 delivery, phase two began and [ADR-0008](./0008-page-eval-confirmation-channel.md)
> implemented page_eval's high-risk confirmation channel. This document is kept as a
> historical record of the trade-offs and the attack-surface analysis made at the
> time (still valid).

## Context

`page_eval`, executing arbitrary JavaScript in the page context, is **the most powerful and the most dangerous** capability in browser automation.

Why it is powerful: it can do almost anything (read JS variables, fire custom events, call page APIs, bypass the UI and operate directly).

Why it is dangerous: **as soon as the AI's instructions are subverted (prompt injection), it can, inside the user's logged-in pages**:
- Steal tokens from `localStorage` / `sessionStorage`
- Read `document.cookie` (reachable once the extension has host permission)
- Call the page's fetch/XHR to send requests as the user (transfers, data deletion)
- Read any sensitive information in the DOM (credit card numbers, private messages)

This is far more dangerous than `page_click`/`page_fill`; those two are at least observable at the UI level (the user can see the click/typing happen), while `eval` is silent.

## Decision

**v0.1 does not implement the `page_eval` tool at all.**

Add it in phase two, and only under these preconditions:
1. It goes through a **dedicated high-risk confirmation channel** (distinct from the in-page Toast of [ADR-0006](./0006-toast-confirmation-for-high-risk.md); possibly a stronger confirmation, such as a separate window showing the full JS code)
2. Return values are masked by default (mask suspected tokens/long strings)
3. The tool description forces the AI to explain why eval is needed (make the model explicitly acknowledge the risk)

## Alternatives considered

### Option A: implement eval with high-risk confirmation (the user's "disabled by default, requires high-risk confirmation" option at decision time)
- **Mechanism**: the tool exists but every call goes through a confirmation channel
- **Pros**: full capability, available when needed
- **Cons**: introduces the largest attack surface in v0.1 already
- **v0.1 handling**: the user chose this direction, but **v0.1 simply did not implement it**, deferring the design of the high-risk confirmation channel to phase two. The rationale: v0.1's 11 tools already cover 90% of scenarios, eval is not essential, and the base architecture and security model should be proven stable first

### Option B: fully disabled, never implement
- **Pros**: permanently removes the largest attack surface
- **Cons**: helpless against complex interactions (firing custom events, reading JS variables, SPA routing)
- **Not chosen**: the user picked "disabled by default + high-risk confirmation", which implies conditional availability

### Option C: open eval, no special confirmation
- **Pros**: most capable, simplest to build
- **Cons**: largest attack surface, violates the security-first principle
- **Rejected**: the user explicitly declined this

## Consequences

### Positive (v0.1)
- **Minimal attack surface**: v0.1's tools are all "observable UI actions"; there is no silent code execution
- **Simple to audit**: no eval masking/confirmation/sandboxing to design
- **Clear security model**: click/fill are gated by the Toast; snapshot/text are read-only and masked

### Negative
- **Complex interactions are out of reach**: scenarios that need `CustomEvent` firing, framework-state reads, or canvas/WebGL manipulation cannot be done
- **Phase two owes the work**: designing the high-risk confirmation channel is a real chunk of effort

### Neutral
- v0.1's `page_click`/`page_fill` use native setters plus dispatchEvent and already cover forms in React/Vue and other mainstream frameworks; most automation scenarios do not need eval

## Phase-two design draft (not implemented)

If `page_eval` is implemented, the design is roughly:
- New tool `page_eval(code)`, executing against the current tab by default
- On each call the content script raises a **separate confirmation window** (not a Toast) showing:
  - The full JS code (scrollable)
  - The target domain and tab title
  - "Run" / "Deny" buttons, denying on a 30-second timeout
- The return value is masked before going back to MCP (regex masks for suspected JWTs, long hex, long numbers)
- The tool description forces the AI to state "why eval instead of click/fill"

This design **is not a commitment**; the phase-two implementation may adjust it.

## Relationship to other ADRs

- With [ADR-0004](./0004-allowlist-with-optional-host-permissions.md) (allowlist): the allowlist guards against unknown sites, the eval ban guards against code execution on granted sites
- With [ADR-0006](./0006-toast-confirmation-for-high-risk.md) (Toast): the Toast covers UI actions; eval (if implemented) needs a stronger confirmation
