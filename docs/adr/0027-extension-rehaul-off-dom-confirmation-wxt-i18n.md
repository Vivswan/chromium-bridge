# ADR-0027: Extension rehaul: off-DOM confirmation surface, WXT, and runtime i18n

- **Status**: Accepted
- **Date**: 2026-07-17
- **Supersedes**: [ADR-0006](./0006-toast-confirmation-for-high-risk.md) (the
  in-page toast surface for high-risk confirmations; see the disposition note
  below). Phase 8 completes the supersession for `page_eval`/`page_upload`
  when their approval moves to the host Secure Enclave.
- **Amends**: [ADR-0008](./0008-page-eval-confirmation-channel.md) (the
  page_eval confirmation still runs on every call, but the surface it renders
  on moves off the page)
- **Superseded in part by** (build/tooling): [ADR-0012](./0012-typescript-esbuild-extension-build.md)
  was already retired by the Phase 3 toolchain record; this phase replaces the
  esbuild driver with WXT.

## Context

Phase 7 rebuilds the extension. Three problems drove it, and they are
independent enough that the rehaul addresses each on its own terms.

The first is the confirmation surface. Since ADR-0006 the high-risk
confirmations (a submit click, a keypress, a select, `page_eval`, a tab close,
`page_upload`) rendered as a toast injected into the page the AI was driving.
The page owns that DOM. A hostile or compromised page can watch for the toast
with a `MutationObserver` and click Allow itself, or overwrite the globals the
toast is built from, so consent is forged exactly where it matters most. The
threat model named this as a residual. The toast is the wrong surface for a
security decision because the party being guarded controls it.

The second is duplication. The DOM work existed twice: once in the
content-script modules (`content/{snapshot,refs,actions,wait,storage,toast}.ts`)
and again, hand-ported, in the CDP backend's page functions
(`cdp/page-fns.ts`), with a third copy of the risk classification and the toast
markup split across `content/toast.ts`, `content/actions.ts`,
`cdp/click-risk.ts`, and inline CDP styles. Every one of those pairs carried a
"MUST match" comment. A change to one that missed the other would silently
diverge the two backends, and the only thing catching it was reviewer memory.

The third is the UI and its language. The options page and popup were vanilla
TypeScript against a hand-written HTML document, the strings were hardcoded
Chinese, and the enrollment panel refreshed on a 2-second `setInterval`. The
house style (cloud-speech-for-chrome) is WXT plus React, event-driven storage,
and a runtime string bundle with a user-chosen display language.

## Decision

### One page-side implementation, consumed by both backends

`lib/dom/page-api.ts` exports a single self-contained factory,
`createPageApi(refAttr)`. It has no imports and no references to module scope;
every helper is declared inside it. The content-script backend calls it once
and keeps the instance. The CDP backend stringifies the same factory with
`Function.prototype.toString()` and evaluates `(factory)(refAttr).method(args)`
in the page's MAIN world through `Runtime.evaluate`. The two backends now run
byte-identical DOM logic, so they cannot drift. A test rebuilds the factory
from its own source text and drives it, which is what proves the
self-containment the CDP path depends on.

Policy no longer lives in a backend. `dispatch.ts` runs one pipeline for every
page op: resolve the tab, check the allowlist, run the preflight (risk
classification plus user confirmation), re-validate the tab, run the backend,
mask the result. Risk classification is one file (`confirm/risk.ts`), the
confirmation is one service (`confirm/service.ts`), and egress masking is one
module (`egress.ts`). Because a backend only probes and acts, the two can no
longer disagree about whether an op needed confirming or masking.

### Confirmations move to an extension-owned window

`confirm/service.ts` presents every confirmation through a
`ConfirmationProvider`. The default provider (`confirm/surface.ts`) opens a
dedicated `confirm.html` popup window. That window is a `chrome-extension://`
document in its own process. A guarded page cannot read it, focus it, overlay
it, or click it, and the runtime message router accepts the `confirm_ready`
and `confirm_resolve` messages only from that exact document (an origin plus
`pathname === "/confirm.html"` check, not a prefix). The page can neither see
what is pending nor answer it.

The service fails closed on every ambiguity: an unanswered request times out
to a denial, a closed window denies, a missing or throwing provider denies,
and a resolution is single-use and checked against the active request id.
Requests are serialized one at a time, first in first out; a queued request's
timeout clock starts when it is shown.

Moving consent off the page opened a window the old toast did not have: a
confirmation can hold the pipeline open for tens of seconds, during which the
tab can navigate. The bridge closes it in the page, atomically with the act.
The preflight records the origin it approved and, for a click, the target
descriptor it approved; both backends assert `location.origin` inside the same
`Runtime.evaluate` or content-script turn that performs the act, and the click
refuses if the resolved element no longer matches the approved descriptor. A
navigation that races the service-worker-side recheck therefore makes the act
throw rather than land on a page the user never approved. `page_upload`
verifies the origin of the exact document it attaches to; `page_screenshot`
captures only the resolved tab's window and only while that tab is active.

The provider seam is deliberate. Phase 8 registers a Secure Enclave
user-presence provider for the `eval` and `upload` kinds, so the host raises
the Touch ID prompt and the verdict comes from the host's signed answer, with
a display-only window showing what is being approved. The queue, the deadline,
and the fail-closed semantics stay; only the provider changes.

One in-page surface stays: the informational pre-warning for
`page_snapshot_precise` (`content/info-toast.ts`). It gates nothing, defaults
to proceed after its timeout, and lets the user only cancel. A page that
suppressed its own courtesy warning gains nothing, and a focus-stealing window
for a heads-up would be hostile, so it is not a security surface and does not
need to move.

### Trust state is confined to extension contexts (#32)

Chrome exposes `storage.local` to content scripts by default. Everything
security-relevant the extension persists lives there: the enrollment pin, the
pending pairing, the compromised marker, the `requireEnrollment` flag, the
allowlist, and every setting. A compromised renderer running with a content
script's privileges could read that trust state or, worse, write it.
`background/trusted-storage.ts` calls
`storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })` (and the
same for `storage.session`) so both areas are reachable only from extension
contexts. The rehaul already removed every content-side storage read, so
nothing legitimate loses access.

The enrollment gate and `onPortConnected` await the restriction first and fail
closed until it succeeds, blocking every bridge request even when
`requireEnrollment` reads false, because that read is itself untrusted until
storage is locked down. The result is memoized for the service worker's life;
a failure stays failed until the worker restarts, which errs toward blocked
rather than degraded.

Direct reads are not the only way a content script could reach the trust state:
the runtime message router is a mediated path. A content script that sent
`add_allow` could seed the per-origin allowlist, and `get_enrollment` would hand
back the pinned key id and fingerprint. So the router refuses every message
whose sender is not one of the extension's own pages (`fromExtensionPage`: our
extension id plus a `chrome-extension://<id>/` URL), and the confirmation
messages require the confirmation window specifically. The content script sends
the router nothing, so nothing legitimate is lost. Without this gate the
`setAccessLevel` restriction would be true for direct reads but bypassable
through the router; with it, the allowlist and the enrollment status are
writable and readable only from extension pages.

`setAccessLevel` is asynchronous and applied after the worker starts, so it
cannot lock storage at t=0. A sub-millisecond window exists at cold start in
which a content script from a prior worker life, in a compromised renderer,
could write a tampered value that the restriction then locks in. No user-space
API closes it; the enclave ceremony's cryptographic checks bound, but do not
erase, what a planted pin achieves. With the router gated, this cold-start
window is the only remaining content-script path to the trust state. The threat
model records this residual
honestly.

### WXT, React, and runtime i18n

The build moves to WXT. `wxt.config.ts` generates the manifest per browser,
injects the pinned `key` from `contracts/identity.json` (so the derived
extension ID `mkjjlmjbcljpcfkfadfmhblmmddkdihf` is unchanged), and keeps the
exact permission set, the empty `host_permissions`, the optional `<all_urls>`,
and the runtime-registered (not manifest-declared) content script.
`scripts/check-extension-id.ts` re-asserts that security surface on the built
artifact, and a config-level test asserts it at the source.

The options page, popup, and confirmation window are React 19 with Radix
primitives and Tailwind v4. Every surface is event-driven through
`storage.onChanged`; the 2-second enrollment poll is gone. `useSettings`
carries a monotonic read guard so an out-of-order storage read cannot roll
back a security toggle. Settings gained a versioned migration ladder run once
at startup under a Web Lock.

Strings move into a runtime bundle in English, Simplified Chinese, and
Traditional Chinese (`src/locales/*.yml`, compiled by `@wxt-dev/i18n`). A
`uiLanguage` setting chooses the display language and defaults to `en`:
English is the canonical language on every surface, and a Chinese UI is an
explicit user choice, never inherited from the environment. The opt-in `auto`
value resolves from the browser (`zh` to `zh_CN`, `zh-Hant`/`TW`/`HK`/`MO` to
`zh_TW`, anything else to `en`). The language picker renders each option in
its own language (the native names in `src/lib/native-language-names.ts`),
never translated into the active locale, so a user facing a UI they cannot
read can always find the way back. The swap
is sequence-guarded, and each key falls back to English if a locale lacks it.
A CI test fails if any key is missing from one of the three locales or if a
`$n` placeholder drifts between them, and the `check-cjk` gate
(`scripts/check-cjk.ts`) fails CI on any CJK text outside the zh locale
files, translated docs, and the native-name constants.

## Alternatives considered

### Keep the toast, harden it in place

Shadow DOM with a closed root, or a nonce the page cannot read, was considered
for the toast. None of it survives a page that runs before the content script
or that patches the DOM APIs the toast is built from. The page owns its event
loop; any surface rendered into it is reachable by it. The only fix is a
surface the page does not own, which is a separate window.

### A `chrome.notifications` confirmation instead of a window

Notifications are off-page and unspoofable, but they carry little text and no
scrollable code view, and `page_eval` must show the full code the user is
approving. A popup window shows the code and gives Phase 8 a place to display
what the Touch ID tap authorizes. The window is the surface that fits both.

### Generate the CDP page functions from the content-script source

An earlier idea kept two files but generated one from the other at build time.
That still ships two artifacts and adds a generator to trust. Shipping one
self-contained function, stringified for the CDP path, removes the second
artifact entirely; the only thing to verify is that the function closes over
nothing, which a test does directly.

## Consequences

### Positive

- The high-risk confirmation is on a surface the guarded page cannot reach,
  read, or auto-click, which closes the toast-autoclick residual for every
  confirmed op and structures the surface for the Phase 8 Touch ID gate.
- The DOM logic, the risk classification, the confirmation, and the egress
  masking each exist once. The "MUST match" mirrors are gone, and a backend
  cannot silently diverge from the other.
- Trust state is unreadable and unwritable from a content script, up to the
  named cold-start residual.
- The UI is React, event-driven, trilingual, and matches the house style, with
  a CI check that keeps the three locales in lockstep.

### Negative

- The confirmation is a separate window rather than an inline toast, so it
  costs a focus change. That is the intended tradeoff: a security decision
  should interrupt.
- WXT and React are new dependencies. They carry no security weight
  (enforcement stays in the service worker and the Rust host), so relying on
  heavily-adopted, community-audited libraries there is the right trust
  boundary per ADR-0023.
- The cold-start storage residual (#32) cannot be closed in user space and is
  named in the threat model rather than implied to be covered.

### Verification gap

The service-worker-side logic, the fail-closed confirmation service, the
single page API, the masking audit, and the i18n coverage are covered by the
Vitest suite against `fakeBrowser`. Three things need an isolated browser and
are flagged as such: that Chrome actually blocks a content script from reading
`storage.local` after `setAccessLevel`, that the guarded page genuinely cannot
reach or auto-click the confirmation window, and that the UI renders correctly
across all three locales. Those are the isolated-browser (`CHROME_BIN`)
suite's job and are not part of the required gate.

## Disposition of ADR-0006

ADR-0006 is marked superseded by this record. The tiering it introduced (only
submit buttons and navigating links prompt; ordinary clicks are silent) and
the same-origin grace window for clicks both stand, and both moved into
`confirm/gate.ts`. What changed is the surface: the confirmation renders in the
extension window, not the page. Phase 8 completes the supersession for
`page_eval` and `page_upload` when their approval becomes the Enclave tap.
