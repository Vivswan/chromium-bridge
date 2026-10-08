// The user-confirmation service: every confirmation the bridge asks for goes through
// confirmWithUser(), which presents it on an EXTENSION-OWNED surface the guarded page cannot reach,
// script, or auto-click (an in-page toast could be observed and clicked by the page's own script,
// forging consent exactly where it mattered most). The router (messages.ts) accepts confirm_*
// messages only from the confirmation window itself; that gate is what makes the window's verdict count.
//   service worker dies mid-request -> the in-flight request is lost, the op fails, nothing dangles

import { type ConfirmKind, type ConfirmPayload, isPresenceGated } from "@genkan/shared/confirm";
import type { RuntimeResponse } from "@genkan/shared/runtime-msg";
import pLimit from "p-limit";
import { inLife } from "../../shared/in-life";
import { auditEvent } from "../audit-log";
import { confirmationsLatched, currentPanicEpoch } from "../brake";

/** The fields every confirmation request carries. */
interface ConfirmRequestBase {
  timeoutMs: number;
  /** Route this confirmation to the presence provider, if one is installed? Decided by the CALLER from the
   * SAME per-request policy snapshot as the rest of the decision, so a policy push landing while
   * the confirmation waits in the queue cannot re-route it. Only the "eval"/"upload" kinds honor it
   * (routeFor); false is the off-DOM window confirmation: still confirmed, not presence-gated.
   * True with no presence provider installed denies: the route never falls back to the window. */
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
   * presence provider resolves true here from the host's verdict on the
   * window's answer to its presence request instead. */
  verdict: Promise<boolean>;
  /** Whether a surface reached the user: true once one is up, false when the
   * presentation ends without one. Absent means the surface is up from
   * present() on (the window provider). The confirm_shown audit record waits
   * on it, so a confirmation denied before any surface opened leaves no shown
   * row. */
  shown?: Promise<boolean>;
  /** Tear the surface down (deadline hit, or resolved through the router). */
  dismiss(): void;
}

export interface ConfirmationProvider {
  present(payload: ConfirmPayload): Presentation;
}

/** The two payload kinds the presence route carries; the type is what keeps every other kind out of it. */
export type PresencePayload = Extract<ConfirmPayload, { kind: "eval" | "upload" }>;

export interface PresenceProvider {
  present(payload: PresencePayload): Presentation;
}

interface Active {
  payload: ConfirmPayload;
  settle: (approved: boolean) => void;
}

// One live confirmation at a time, FIFO: each request runs on this lane once its predecessor has fully settled.
// Occupancy IS the lane, so no separate flag can desynchronize from it, and a presentation step that throws denies
// its own request without wedging the ones queued behind it.
const queue = inLife(() => pLimit(1));
const active = inLife<Active | null>(() => null);

// Installed by the background entrypoint at SW startup. No provider
// installed = every confirmation denies (fail closed).
const defaultProvider = inLife<ConfirmationProvider | null>(() => null);

export function installConfirmationProvider(p: ConfirmationProvider): void {
  defaultProvider.value = p;
}

// The presence provider slot. Whether a confirmation routes to it is the request's own
// presenceRouting field (ConfirmRequestBase); the route is chosen without re-reading live policy.
const presence = inLife<PresenceProvider | null>(() => null);

export function installPresenceProvider(p: PresenceProvider): void {
  presence.value = p;
}

/** The payload and the provider that shows it, for one request. "eval" and
 * "upload" go to the presence provider when the request's decision-time
 * routing verdict says so, their payload marked `presence` so the window
 * answers the host's request instead of offering Allow and resolveConfirm
 * refuses a window approval; with no presence provider installed they deny.
 * Everything else keeps the window. Built per arm of the request union, so
 * each payload carries exactly its kind's fields: `presence` exists only on
 * the two presence-gated kinds, and a policy_relax payload is structurally
 * page-less. Synchronous on purpose: no await sits between the front-of-queue
 * latch check and the `active` registration below, so a panic can never land
 * "mid-selection" INSIDE the service; the awaits that remain in a decision
 * (the caller-side routing probe, the queue wait) are covered by the
 * decision-start epoch the request carries (ConfirmRequest.panicEpoch). */
function routeFor(
  req: ConfirmRequest,
  common: { id: string; deadline: number },
): { payload: ConfirmPayload; present: (() => Presentation) | null } {
  if (req.kind === "policy_relax") {
    const payload: ConfirmPayload = {
      ...common,
      kind: "policy_relax",
      origin: "",
      tabTitle: "",
      detail: req.detail,
    };
    const window = defaultProvider.value;
    return { payload, present: window && (() => window.present(payload)) };
  }
  const page = { origin: req.origin, tabTitle: req.tabTitle, detail: req.detail };
  if ((req.kind === "eval" || req.kind === "upload") && req.presenceRouting) {
    // No presence provider is a denial, never the window: the route has no fallback.
    const provider = presence.value;
    const payload: PresencePayload = { ...common, ...page, kind: req.kind, presence: true };
    return { payload, present: provider && (() => provider.present(payload)) };
  }
  const payload: ConfirmPayload = { ...common, ...page, kind: req.kind };
  const window = defaultProvider.value;
  return { payload, present: window && (() => window.present(payload)) };
}

/** The confirm window hit the brake. Settling the active entry lets the lane advance; the router follows this with
 * the panic engage in the same synchronous turn (messages.ts denyAndKill), which bumps the brake's panic epoch and
 * arms its latch before any queued request can reach the front, so every request behind this one denies without
 * presenting. */
export function denyActiveConfirmation(): void {
  active.value?.settle(false);
}

/** Ask the user. Resolves true only on an explicit, in-time approval from
 * the extension-owned surface; every other outcome is false. */
export function confirmWithUser(req: ConfirmRequest): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    // The decision-start epoch: a panic bumps it, so any request whose decision predates the panic
    // denies on the mismatch even after the latch lifts.
    const epoch = req.panicEpoch;
    // One id per confirmation ATTEMPT, minted before any surface exists, so every audit event of
    // the attempt carries the same `cid` and the audit panel joins a verdict to its shown row by
    // it; it doubles as the surface routing handle (payload.id). Random, not a counter: the host
    // merges audit records from every browser, so per-worker counters would collide, and a random
    // id cannot be steered onto another attempt's row.
    const cid = crypto.randomUUID();
    if (confirmationsLatched()) {
      // Created while the latch is on: denied at the door. Waiting in the
      // queue instead would let it present if the latch lifts before it
      // reaches the front (its own epoch is the post-panic one). No surface was
      // shown, so this cid matches no confirm_shown row - it resolves nothing.
      auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
      resolve(false);
      return;
    }
    void queue
      .value(() => presentOne(req, epoch, cid, resolve))
      .catch((e: unknown) => {
        // presentOne settles every path it knows about; this is the backstop for anything it did not: deny THIS
        // request (the lane advances on its own, settled or rejected). Audit the denial like every other deny path:
        // a shown attempt already emitted its own verdict via settle, so at worst this is a second confirm_denied
        // under the same cid, never a missing trail.
        console.error("[genkan] confirmation step failed; denying", e);
        auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
        resolve(false);
      });
  });
}

/** Run one confirmation at the front of the lane. The returned promise holds the next queued request back: it
 * settles when this confirmation does. Every known failure path resolves the verdict false and returns; the
 * caller's catch backstops the rest. */
async function presentOne(
  req: ConfirmRequest,
  epoch: number,
  cid: string,
  resolve: (approved: boolean) => void,
): Promise<void> {
  if (confirmationsLatched() || currentPanicEpoch() !== epoch) {
    // Denied unseen: the user already chose "kill everything" - showing
    // more consent surfaces after that choice would invert it. Same
    // attempt cid, but no surface was shown, so it resolves no row.
    auditEvent("confirm_denied", { tool: req.kind, name: req.origin, cid });
    resolve(false);
    return;
  }
  const { payload, present } = routeFor(req, {
    // The attempt's id doubles as the surface routing handle
    // (getPendingConfirm/resolveConfirm match on it). Same value the
    // audit events above and below carry, so the shown row and its
    // verdict join exactly.
    id: cid,
    deadline: Date.now() + req.timeoutMs,
  });
  if (!present) {
    console.error("[genkan] no provider for this confirmation; denying", req.kind);
    resolve(false);
    return;
  }

  let presentation: Presentation;
  try {
    presentation = present();
  } catch (e) {
    console.error("[genkan] confirmation provider threw; denying", e);
    resolve(false);
    return;
  }

  await new Promise<void>((advance) => {
    let done = false;
    const settle = (approved: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      active.value = null;
      try {
        presentation.dismiss();
      } catch (e) {
        // A provider that cannot tear down must not block the verdict or
        // stall the queue.
        console.warn("[genkan] confirmation dismiss failed", e);
      }
      // Log-after-decide: the verdict is already settled; the audit ring and the host's audit file
      // record it, never gate it.
      auditEvent(approved ? "confirm_allowed" : "confirm_denied", {
        tool: req.kind,
        name: req.origin,
        cid,
      });
      resolve(approved);
      advance();
    };
    const timer = setTimeout(() => settle(false), req.timeoutMs);
    active.value = { payload, settle };
    // Audited once a surface is in front of the user (at once for the window;
    // when the host's request lands for the presence route). Same cid as the
    // verdict above, so the panel joins the pair exactly; a presentation that
    // ends before any surface opened leaves no shown row, like a denial at the
    // door.
    void (presentation.shown ?? Promise.resolve(true)).then((up) => {
      if (up) auditEvent("confirm_shown", { tool: req.kind, name: req.origin, cid });
    });
    try {
      presentation.verdict.then(settle, (e: unknown) => {
        console.error("[genkan] confirmation presentation failed; denying", e);
        settle(false);
      });
    } catch (e) {
      // A presentation whose verdict cannot even be observed: deny THROUGH
      // settle, so the timer, the active slot, and the queue all unwind.
      console.error("[genkan] confirmation verdict unobservable; denying", e);
      settle(false);
    }
  });
}

/** The payload the confirmation window asks for on load. Only the ACTIVE
 * request is ever handed out, and only by id: a stale or foreign window gets
 * nothing. */
export function getPendingConfirm(id: string): ConfirmPayload | null {
  const current = active.value;
  return current && current.payload.id === id ? current.payload : null;
}

/** messages.ts routes this ONLY from the confirmation window; that sender check is what makes
 * page-side auto-approval impossible. A presence-gated payload is approved only by the host's verdict
 * on the window's answer to its presence request, so even the trusted window cannot stand in for it.
 *   presence-gated + approve  -> refused; only the host's verdict approves
 *   any payload + deny        -> accepted; removing capability is always friction-free */
export function resolveConfirm(id: string, approved: boolean): RuntimeResponse<"confirm_resolve"> {
  const current = active.value;
  if (!current || current.payload.id !== id) {
    return { ok: false, error: "no such pending confirmation" };
  }
  if (approved && isPresenceGated(current.payload)) {
    return {
      ok: false,
      error: "presence-gated confirmation: approval is the host's verdict on the presence request",
    };
  }
  current.settle(approved);
  return { ok: true };
}
