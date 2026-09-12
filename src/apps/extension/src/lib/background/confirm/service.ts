// The user-confirmation service (ADR-0027): every confirmation the bridge asks for goes through
// confirmWithUser(), which presents it on an EXTENSION-OWNED surface the guarded page cannot reach,
// script, or auto-click (an in-page toast could be observed and clicked by the page's own script,
// forging consent exactly where it mattered most). The router (messages.ts) accepts confirm_*
// messages only from the confirmation window itself; that gate is what makes the window's verdict count.
//   service worker dies mid-request -> the in-flight request is lost, the op fails, nothing dangles

import { type ConfirmKind, type ConfirmPayload, isHardwareGated } from "@chromium-bridge/shared";
import { auditEvent } from "../audit-log";

/** The fields every confirmation request carries. */
interface ConfirmRequestBase {
  timeoutMs: number;
  /** Route this confirmation to the Enclave user-presence provider (ADR-0031)? Decided by the CALLER
   * from the SAME per-request policy snapshot as the rest of the decision (ADR-0032 decision 4), so a
   * policy push landing while the confirmation waits in the queue cannot re-route it. Only the
   * "eval"/"upload" kinds honor it (providerFor); false, or no presence provider, is the off-DOM window
   * confirmation: still confirmed, not hardware-gated. */
  presenceRouting: boolean;
  /** The panic epoch captured at DECISION START (currentPanicEpoch), synchronously beside the policy
   * snapshot and BEFORE the decision's first await. Every await the decision performs (the policy read,
   * the tab resolve, the routing probe, a click probe) follows the capture, so a deny-kill that lands
   * AND lifts inside any of them still denies on the epoch mismatch. */
  panicEpoch: number;
}

/** Discriminated on `kind`, mirroring the payload union it feeds
 * (ConfirmPayload): the page-op kinds carry their page context, while a
 * `policy_relax` request - no page is involved - pins origin/tabTitle to
 * "", so a request claiming a page for a policy approval cannot be built. */
export type ConfirmRequest = ConfirmRequestBase &
  (
    | {
        kind: Exclude<ConfirmKind, "policy_relax">;
        origin: string;
        tabTitle: string;
        detail: string;
      }
    | { kind: "policy_relax"; origin: ""; tabTitle: ""; detail: string }
  );

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

// The panic latch (ADR-0030): while it is on, EVERY confirmation (active, queued, or newly requested)
// denies without presenting. It closes the window the queue would otherwise open: a request that
// passed the kill gate while the mirror still read alive would pop a fresh surface the user could
// approve while the brake is still in flight to the host.
//   engaged  -> denyAllConfirmations, from the confirm window's deny-and-kill
//   lifted   -> releasePanicDeny, router-only, on the proofs its doc names; a lost engage (posted, never
//               answered, host restarts alive) keeps it on until the SW's own restart clears it
let panicDeny = false;
// Edge marker beside the level latch, bumped on every panic. Every request carries the epoch its
// decision captured at its start (ConfirmRequest.panicEpoch), so a panic that lands AND lifts between
// that capture and presentation, invisible to the level check alone, still denies on the mismatch.
let panicEpoch = 0;

/** Capture the panic epoch at the START of a decision, before its first await. Every confirmation the
 * decision raises carries this value, so the service denies it if a deny-kill crossed the decision,
 * even one that lifted again before the confirmation was created. */
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

/** Router-only: lift the panic latch, scoped to the panic that armed it. `epoch` must be the value
 * denyAllConfirmations returned, so an earlier panic's kill settling late can never lift a NEWER panic's latch.
 *
 * The router calls this only on proof that the brake fully settled or never left the station:
 *   kill state authoritatively reads alive again AFTER the engage applied            -> lift (an explicit, presence-gated release)
 *   send failed AND no posted engage is still unconfirmed (kill.ts engageOutstanding) -> lift (nothing is in flight)
 *   send failed while an earlier engage is unconfirmed, or timeout                    -> no lift: a posted frame may still apply
 */
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
    // The decision-start epoch: a panic bumps it, so any request whose decision predates the panic
    // denies on the mismatch even after the latch lifts.
    const epoch = req.panicEpoch;
    // One id per confirmation ATTEMPT, minted before any surface exists, so every audit event of the
    // attempt carries the same `cid` (ADR-0030) and the audit panel joins a verdict to its shown row by
    // it; it doubles as the surface routing handle (payload.id). Random, not a counter: the host merges
    // audit records from every browser, so per-worker counters would collide, and a random id cannot be
    // steered onto another attempt's row.
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
  // Built per arm of the request union, so each payload carries exactly its
  // kind's fields: `hardware` can only ride the two presence-gated kinds
  // (providerFor only raises it there, and the payload union would refuse it
  // anywhere else), and a policy_relax payload is structurally page-less.
  const common = {
    // The attempt's id doubles as the surface routing handle
    // (getPendingConfirm/resolveConfirm match on it). Same value the
    // audit events above and below carry, so the shown row and its
    // verdict join exactly.
    id: cid,
    deadline: Date.now() + req.timeoutMs,
  };
  const payload: ConfirmPayload =
    req.kind === "policy_relax"
      ? { ...common, kind: "policy_relax", origin: "", tabTitle: "", detail: req.detail }
      : req.kind === "eval" || req.kind === "upload"
        ? {
            ...common,
            kind: req.kind,
            origin: req.origin,
            tabTitle: req.tabTitle,
            detail: req.detail,
            ...(hardware ? { hardware: true } : {}),
          }
        : {
            ...common,
            kind: req.kind,
            origin: req.origin,
            tabTitle: req.tabTitle,
            detail: req.detail,
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
      // Log-after-decide (ADR-0030): the verdict is already settled; the audit ring and the host's
      // audit file record it, never gate it. Only a shown attempt reaches settle(), so this cid
      // resolves exactly its own confirm_shown row.
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

/** messages.ts routes this ONLY from the confirmation window; that sender check is what makes page-side
 * auto-approval impossible. A hardware-gated payload (ADR-0031) is approved only by the verified Enclave
 * user-presence answer, so even the trusted window cannot stand in for the tap.
 *   hardware-gated + approve  -> refused; only the Touch ID prompt approves
 *   any payload + deny        -> accepted; removing capability is always friction-free */
export function resolveConfirm(id: string, approved: boolean): { ok: boolean; error?: string } {
  if (!active || active.payload.id !== id) {
    return { ok: false, error: "no such pending confirmation" };
  }
  if (approved && isHardwareGated(active.payload)) {
    return {
      ok: false,
      error: "hardware-gated confirmation: approval requires the Touch ID prompt",
    };
  }
  active.settle(approved);
  return { ok: true };
}
