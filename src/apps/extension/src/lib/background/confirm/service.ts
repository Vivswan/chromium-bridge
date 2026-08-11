// The user-confirmation service (ADR-0027): every confirmation the bridge
// asks for goes through confirmWithUser(), which presents the request on an
// EXTENSION-OWNED surface the guarded page cannot reach, script, or
// auto-click. This replaces the in-page toasts of ADR-0006/0008: a page
// script could observe and click a toast rendered in its own DOM, so consent
// could be forged exactly where it mattered most. The extension window is a
// separate chrome-extension:// document in a separate process; the router
// additionally refuses confirm_* messages from anything but extension pages.
//
// Fail-closed properties:
// - unanswered within the timeout -> denied (and the surface is dismissed);
// - surface closed by the user -> denied;
// - the surface failing to open -> denied;
// - a second resolution for the same id -> ignored (single-use);
// - no provider installed -> denied;
// - SW death loses the in-flight request -> the op fails; nothing dangles.
//
// Requests are serialized: one confirmation surface at a time, FIFO. A queued
// request's timeout clock starts when it is SHOWN, not when queued.
//
// Phase 8 (ADR-0031): providers implement ConfirmationProvider. The default
// is the extension popup window (surface.ts). The "eval" and "upload" kinds
// route to the Enclave user-presence provider (presence.ts) when the
// request's decision-time routing verdict says so (presenceRouting below,
// computed by the caller from its per-request policy snapshot, ADR-0032
// decision 4) - the host raises the Touch ID prompt and the provider
// resolves its verdict from the host's SIGNED answer, with a display-only
// window showing WHAT is being approved. Such payloads carry
// `hardware: true`, and resolveConfirm refuses a window-side approval for
// them: the tap is the only approval. The queue, deadline, and fail-closed
// semantics here stay unchanged.

import type { ConfirmKind, ConfirmPayload } from "@chromium-bridge/shared";
import { auditEvent } from "../audit-log";

export interface ConfirmRequest {
  kind: ConfirmKind;
  origin: string;
  tabTitle: string;
  detail: string;
  timeoutMs: number;
  /** Route this confirmation to the Enclave user-presence provider
   * (ADR-0031)? Decided by the CALLER at decision time - for the gated ops,
   * from the SAME per-request policy snapshot as the rest of the decision
   * (ADR-0032 decision 4), so a policy push landing while the confirmation
   * waits in the queue cannot re-route it. Kinds the presence provider never
   * serves pass false. Honored only for the "eval"/"upload" kinds while a
   * presence provider is installed; false (or no provider) falls back to the
   * off-DOM window confirmation - still confirmed, not hardware-gated. */
  presenceRouting: boolean;
  /** The panic epoch captured at DECISION START (currentPanicEpoch below) -
   * in dispatch, SYNCHRONOUSLY beside the policy snapshot and BEFORE the
   * decision's first await, then threaded through the confirmation path as a
   * required parameter. Every await the decision performs - the policy read,
   * the tab resolve, the presence routing probe, a click probe - follows the
   * capture, so a deny-kill that lands AND lifts inside any of them still
   * denies on the epoch mismatch (SFX-2). */
  panicEpoch: number;
}

/** A live presentation of one confirmation. */
export interface Presentation {
  /** The provider-observed outcome. The window provider only ever reports
   * denials here (surface closed / failed to open) - approvals arrive
   * through resolveConfirm(), from the extension page, via the router. The
   * Enclave provider (ADR-0031) resolves true here from the host's signed
   * user-presence answer instead. */
  verdict: Promise<boolean>;
  /** Tear the surface down (deadline hit, or resolved through the router). */
  dismiss(): void;
}

export interface ConfirmationProvider {
  present(payload: ConfirmPayload): Presentation;
}

interface Active {
  payload: ConfirmPayload;
  settle: (approved: boolean) => void;
}

// One live confirmation at a time, FIFO: each request appends itself to
// this promise chain (the audit-log idiom) and runs when its predecessor
// has fully settled. Occupancy IS the chain - there is no separate flag to
// desynchronize from it, and the chain's own catch keeps it alive, so a
// presentation step that throws can deny its own request but never wedge
// every confirmation behind a stuck boolean.
let tail: Promise<void> = Promise.resolve();
let active: Active | null = null;

// Installed by the background entrypoint at SW startup. No provider
// installed = every confirmation denies (fail closed).
let defaultProvider: ConfirmationProvider | null = null;

export function installConfirmationProvider(p: ConfirmationProvider): void {
  defaultProvider = p;
}

// The Enclave user-presence provider (ADR-0031). Whether a confirmation
// routes to it travels IN the request (presenceRouting above), decided from
// the caller's per-request policy snapshot: providerFor never re-reads live
// policy, so a push landing between decision and presentation cannot
// re-route an in-flight confirmation (ADR-0032 decision 4). A missing
// provider routes to the window (still a real confirmation), never to
// "no confirmation".
let presence: ConfirmationProvider | null = null;

export function installPresenceProvider(p: ConfirmationProvider): void {
  presence = p;
}

/** The provider for one request. "eval" and "upload" go to the Enclave
 * user-presence gate when the request's decision-time routing verdict says
 * so and a provider is installed; everything else (and every fallback)
 * keeps the window. `hardware` marks the payload so the window renders
 * display-only and resolveConfirm refuses a window approval. Synchronous on
 * purpose: no await sits between the front-of-queue latch check and the
 * `active` registration below, so a panic can never land "mid-selection"
 * INSIDE the service; the awaits that remain in a decision (the caller-side
 * routing probe, the queue wait) are covered by the decision-start epoch the
 * request carries (ConfirmRequest.panicEpoch). */
function providerFor(req: ConfirmRequest): {
  provider: ConfirmationProvider | null;
  hardware: boolean;
} {
  if ((req.kind === "eval" || req.kind === "upload") && presence && req.presenceRouting) {
    return { provider: presence, hardware: true };
  }
  return { provider: defaultProvider, hardware: false };
}

// The panic latch (ADR-0030): set by the confirm window's deny-and-kill,
// lifted by the router only when the kill state authoritatively reads alive
// again after the engage applied, or when the engage frame never reached
// the pipe (send failure). While it is on, EVERY confirmation - the active
// one, the whole queue, and anything newly requested - denies without
// presenting. This closes the window the queue would otherwise open: a
// request that passed the kill gate while the mirror still read alive would
// pop a fresh surface (which the user could approve) while the brake is
// still in flight to the host. Module state, deliberately: if the engage is
// lost with a dying host (posted, never answered, host restarts alive) the
// latch stays on - denying consent is the fail-closed reading of "kill
// everything" - until the SW's own restart clears it.
let panicDeny = false;
// Edge marker beside the level latch: bumped on every panic, and LOAD-BEARING
// (SFX-2): every request carries the epoch its DECISION captured at its start
// (currentPanicEpoch below, threaded through ConfirmRequest.panicEpoch). The
// decision's own awaits - the presence routing probe, a click probe - and the
// FIFO queue wait all sit between that capture and presentation, so a panic
// that lands AND lifts anywhere inside that span is invisible to the level
// check alone. Any mismatch denies: "a panic crossed this decision's
// lifetime" survives the lift.
let panicEpoch = 0;

/** Capture the panic epoch at the START of a decision, before its first
 * await (SFX-2). Every confirmation the decision raises carries this value,
 * so the service denies it if a deny-kill crossed the decision - even one
 * that lifted again before the confirmation was created. */
export function currentPanicEpoch(): number {
  return panicEpoch;
}

/** The confirm window hit the brake: deny the active confirmation and latch
 * everything behind it to auto-deny. Settling the active entry lets the
 * chain advance, and every request already queued on it sees the latch and
 * denies without presenting. Returns the panic's epoch, which is the ONLY
 * token that can later lift this latch (releasePanicDeny). */
export function denyAllConfirmations(): number {
  panicDeny = true;
  panicEpoch += 1;
  active?.settle(false);
  return panicEpoch;
}

/** Router-only: lift the panic latch, scoped to the panic that armed it.
 * Fail closed on every ambiguity:
 * - `epoch` must be the value denyAllConfirmations returned; a stale
 *   release (an earlier panic's kill settling late) is a no-op, so it can
 *   never lift a NEWER panic's latch;
 * - the router calls this only on the two proofs that the brake either
 *   fully settled or never left the station: the kill state authoritatively
 *   reading alive again AFTER the engage applied (an explicit, presence-
 *   gated release), or the engage frame never reaching the pipe at all
 *   (send failure - nothing is in flight, and the mirror tells the user the
 *   truth). A timeout is neither: the posted frame may still apply, so the
 *   latch stays down and confirmations keep denying. */
export function releasePanicDeny(epoch: number): void {
  if (epoch === panicEpoch) panicDeny = false;
}

/** Tests only: clear the latch level. The epoch stays monotonic, exactly
 * like the real thing across panics. */
export function resetPanicForTests(): void {
  panicDeny = false;
}

/** Ask the user. Resolves true only on an explicit, in-time approval from
 * the extension-owned surface; every other outcome is false. */
export function confirmWithUser(req: ConfirmRequest): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    // The DECISION-START epoch the caller captured before its first await
    // (SFX-2): a panic bumps the epoch, so any request whose decision
    // predates the panic - active, queued, or still awaiting its caller-side
    // routing probe when the panic hit - denies on the mismatch even after
    // the latch lifts.
    const epoch = req.panicEpoch;
    // One collision-resistant id per confirmation ATTEMPT, minted once here so
    // EVERY audit event this attempt emits carries the same `cid` (ADR-0030) -
    // whether it is shown and gets a verdict, or denied before any surface
    // exists. It doubles as the surface routing handle (payload.id below;
    // getPendingConfirm/resolveConfirm match on it). A random 128-bit UUID, not
    // a monotonic counter: the host merges audit records from every browser, so
    // per-worker counters would collide across browsers, and a random id cannot
    // be steered to match another attempt's row. The audit panel joins a
    // verdict to its shown row by this exact id; a pre-surface denial's id
    // simply matches no shown row (it resolves nothing), which is what makes a
    // panic-latch denial closing an unrelated confirmation impossible.
    const cid = crypto.randomUUID();
    if (panicDeny) {
      // Created while the latch is on: denied at the door. Waiting in the
      // queue instead would let it present if the latch lifts before it
      // reaches the front (its own epoch is the post-panic one). No surface was
      // shown, so this cid matches no confirm_shown row - it resolves nothing.
      auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
      resolve(false);
      return;
    }
    tail = tail
      .then(() => presentOne(req, epoch, cid, resolve))
      .catch((e: unknown) => {
        // presentOne settles every path it knows about; this is the chain's
        // backstop for anything it did not - deny THIS request and keep the
        // serializer alive for the ones queued behind it. Audit the denial
        // like every other deny path (ADR-0030): a shown attempt already
        // emitted its own verdict via settle, so at worst this is a second
        // confirm_denied under the same cid - never a missing trail.
        console.error("[bb] confirmation step failed; denying", e);
        auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
        resolve(false);
      });
  });
}

/** Run one confirmation at the front of the queue. The returned promise is
 * what holds the next queued request back: it settles when this
 * confirmation does. Every known failure path resolves the verdict false
 * and returns; the chain's catch backstops the rest. */
async function presentOne(
  req: ConfirmRequest,
  epoch: number,
  cid: string,
  resolve: (approved: boolean) => void,
): Promise<void> {
  if (panicDeny || panicEpoch !== epoch) {
    // Denied unseen: the user already chose "kill everything" - showing
    // more consent surfaces after that choice would invert it. Same
    // attempt cid, but no surface was shown, so it resolves no row.
    auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
    resolve(false);
    return;
  }
  const { provider, hardware } = providerFor(req);
  const payload: ConfirmPayload = {
    // The attempt's id doubles as the surface routing handle
    // (getPendingConfirm/resolveConfirm match on it). Same value the
    // audit events above and below carry, so the shown row and its
    // verdict join exactly.
    id: cid,
    kind: req.kind,
    origin: req.origin,
    tabTitle: req.tabTitle,
    detail: req.detail,
    deadline: Date.now() + req.timeoutMs,
    ...(hardware ? { hardware: true } : {}),
  };
  if (!provider) {
    console.error("[bb] no confirmation provider installed; denying", req.kind);
    resolve(false);
    return;
  }

  let presentation: Presentation;
  try {
    presentation = provider.present(payload);
  } catch (e) {
    console.error("[bb] confirmation provider threw; denying", e);
    resolve(false);
    return;
  }

  await new Promise<void>((advance) => {
    let done = false;
    const settle = (approved: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      active = null;
      try {
        presentation.dismiss();
      } catch (e) {
        // A provider that cannot tear down must not block the verdict or
        // stall the queue.
        console.warn("[bb] confirmation dismiss failed", e);
      }
      // Log-after-decide (ADR-0030): the verdict is already settled; the
      // audit ring and the host's audit file record it, never gate it.
      // `cid` ties this verdict to THIS attempt's confirm_shown row. Only a
      // shown attempt reaches settle(), so this resolves exactly its own
      // row; the pre-surface denials above carry the same-shaped cid but no
      // shown row exists for them, so they resolve nothing.
      auditEvent(approved ? "confirm_allowed" : "confirm_denied", {
        tool: req.kind,
        name: req.origin,
        cid,
      });
      resolve(approved);
      advance();
    };
    const timer = setTimeout(() => settle(false), req.timeoutMs);
    active = { payload, settle };
    // The surface is up in front of the user from here (ADR-0030 audit).
    // Same cid as the verdict above, so the panel joins the pair exactly.
    auditEvent("confirm_shown", { tool: req.kind, name: req.origin, cid });
    try {
      presentation.verdict.then(settle, (e: unknown) => {
        console.error("[bb] confirmation presentation failed; denying", e);
        settle(false);
      });
    } catch (e) {
      // A presentation whose verdict cannot even be observed: deny THROUGH
      // settle, so the timer, the active slot, and the queue all unwind.
      console.error("[bb] confirmation verdict unobservable; denying", e);
      settle(false);
    }
  });
}

/** The payload the confirmation window asks for on load. Only the ACTIVE
 * request is ever handed out, and only by id: a stale or foreign window gets
 * nothing. */
export function getPendingConfirm(id: string): ConfirmPayload | null {
  return active && active.payload.id === id ? active.payload : null;
}

/** Resolve the active confirmation. Single-use; unknown ids are refused.
 * The router routes this ONLY from extension pages - that restriction is the
 * mechanism that makes page-side auto-approval impossible.
 *
 * A hardware-gated payload (ADR-0031) refuses a window-side APPROVAL: the
 * only approval is the verified Enclave user-presence answer, so even the
 * trusted window cannot substitute for the tap. Denial stays accepted -
 * removing capability is always friction-free. */
export function resolveConfirm(id: string, approved: boolean): { ok: boolean; error?: string } {
  if (!active || active.payload.id !== id) {
    return { ok: false, error: "no such pending confirmation" };
  }
  if (approved && active.payload.hardware) {
    return {
      ok: false,
      error: "hardware-gated confirmation: approval requires the Touch ID prompt",
    };
  }
  active.settle(approved);
  return { ok: true };
}
