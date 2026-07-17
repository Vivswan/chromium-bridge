# ADR-0018: AI tabs go into a "Browser Bridge" tab group (workspace)

- **Status**: Accepted
- **Date**: 2026-07-16

## Context

browser-bridge drives the user's **real browser**, so tabs the AI opens with `tab_open` mix in with the user's own tabs: hard to tell apart, hard to reclaim in one motion, and operations can easily hit a page the user is actively using.

A common approach in other tools (such as Codex connecting to a local browser) is to put AI-opened tabs into a **named tab group (Chrome Tab Group)** and operate inside it. The benefits:

1. **Isolation without interference**: the AI's tabs are visually separated from the user's;
2. **Transparent and reclaimable**: the user sees at a glance "these are the AI's" and can collapse or close the whole group;
3. **Multi-agent friendly**: it is the lightest form of "one workspace per session" (still sharing the same browser profile and login state).

## Decision

Tabs opened by `tab_open` are **automatically placed into a tab group named "Browser Bridge"** (blue). Within the same window an existing group of that name is reused; otherwise one is created, named, and colored.

- Controlled by the `groupTabs` setting, **on by default**; can be turned off on the Options page.
- Needs the new **`tabGroups`** permission (for naming/coloring the group; `chrome.tabs.group()` itself belongs to `tabs`).
- Grouping is **best-effort UX**: a grouping failure (exception, restricted page) only gets a `console.warn` and **never** fails `tab_open`.
- `tab_list`'s return value gains a `groupId` field (`undefined` when ungrouped), so the AI/user can identify ownership.

## Alternatives considered

### Option A: hard isolation, allowing page operations only on tabs inside the group
- **Pros**: stronger "sandbox" semantics
- **Cons**: changes the existing targeting semantics (operations often target the active tab, which may not be in the group), inviting surprise failures
- **Not chosen**: this round does "organization + visibility" only, without changing operation targeting; hard isolation is left for later (it needs session isolation alongside)

### Option B: a separate `tab_group` tool (explicit create/move/focus)
- **Pros**: finer control
- **Cons**: it is a **contract change** (touching `contracts/tools.json`, the Rust catalogue, and code generation)
- **Not chosen**: start with zero-contract-change automatic grouping; an explicit tool can come later as an increment

### Option C: a separate browser context (incognito-like)
- **Rejected**: that isolates "a different set of cookies/login state", which contradicts the product goal of reusing the user's real login state, and it is not a visible tab group

## Consequences

### Positive
- AI tabs are grouped, visible, and reclaimable as a unit; they no longer scatter and disturb the user
- A single agent benefits immediately, and it lays the groundwork for future "one workspace per session" multi-agent isolation
- Zero contract change: a pure extension-side change, Rust/protocol untouched

### Negative / trade-offs
- The new `tabGroups` permission (low risk: it only organizes tabs and touches no page-content/cookie data plane); on the Chrome Web Store, a permission change triggers re-review and users re-granting
- **Does not solve the connection-layer multi-agent problem**: the single lock file, preemptive kill, and single native connection remain (that is the connection layer; this ADR is the in-browser organization layer, a different level)

## Relationship to other ADRs

- Orthogonal to [ADR-0004](./0004-allowlist-with-optional-host-permissions.md): grouping does not change the allowlist/grants
- Complements, not replaces, the "multi-client broker" (see the RFC example in [GOVERNANCE.md](../../GOVERNANCE.md))
