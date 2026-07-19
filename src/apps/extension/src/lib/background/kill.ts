// The extension half of the ADR-0030 kill switch: a SW-only mirror of the
// host's kill state, and the control-frame plumbing that reads and toggles it.
//
// The AUTHORITY for the kill state is the host's revocation record; every
// host-side enforcement point reads it fail-closed. This module keeps a
// durable mirror in the #32 trusted storage so that (a) the extension's own
// gate refuses ops locally while killed (defense in depth, and correct UI
// even while the SW was asleep during the transition), and (b) the options
// page can render the state. The mirror is written ONLY from the host's
// kill_status_result frames - never from a runtime message - so a page (or a
// compromised renderer) can neither read it (TRUSTED_CONTEXTS storage) nor
// plant a value the gate would trust: the router requires an extension-page
// sender for get_kill/set_kill, and even those only RELAY to the host, which
// makes the actual decision and answers with the resulting state.
//
// Mirror semantics, fail closed on everything but a positive "alive":
//   absent          -> allowed locally (never heard from a host: a fresh
//                      install must not be bricked; the host side enforces).
//   {state:alive}   -> allowed.
//   {state:killed}  -> refused.
//   {state:unknown} -> refused (the host said it cannot read its own state).
//   malformed value -> refused (tampering evidence, never mapped to absent).
//
// Same shape as clients.ts: port.ts hands this module the port (attachPort)
// and every kill_status_result frame; messages.ts routes the options-page
// actions here. Unsolicited results (the host's startup/transition pushes)
// update the mirror; solicited ones additionally resolve the pending request.

import { type KillMirror, KillMirrorSchema, type KillStatusResult } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { auditEvent } from "./audit-log";

export { isKillStatusFrame } from "@chromium-bridge/shared";

const KILL_MIRROR_KEY = "bridgeKillMirror";

/** How long the host has to answer a kill control frame before the request
 * fails closed (same posture as the client-admin exchange, #61). */
const KILL_REQUEST_TIMEOUT_MS = 10_000;

/** kill_release alone gets a longer window (ADR-0031): on macOS the host
 * answers only after the user completes the Touch ID prompt, and a 10s
 * budget would time the request out mid-tap. Timing out still fails closed
 * (the switch stays engaged; a late release is pushed to the mirror). */
const KILL_RELEASE_TIMEOUT_MS = 120_000;

export type KillGate = { allowed: true } | { allowed: false; reason: string };

/** The mirror's verdict for the request gate. Pure over the stored value so
 * the fail-closed matrix is unit-testable. */
export function killGateFromStored(value: unknown): KillGate {
  if (value === undefined) return { allowed: true };
  const parsed = KillMirrorSchema.safeParse(value);
  if (!parsed.success) {
    return {
      allowed: false,
      reason:
        "the stored kill-switch mirror is malformed; refusing all bridge activity " +
        "(possible tampering). Toggle the kill switch from the options page or run " +
        "`chromium-bridge unkill` to rewrite it.",
    };
  }
  switch (parsed.data.state) {
    case "alive":
      return { allowed: true };
    case "killed":
      return {
        allowed: false,
        reason:
          "the bridge kill switch is engaged; all bridge activity is refused until " +
          "it is explicitly released (options page, or `chromium-bridge unkill`)",
      };
    case "unknown":
      return {
        allowed: false,
        reason:
          "the host cannot read its kill-switch state; failing closed until it can " +
          "(see `chromium-bridge doctor`)",
      };
  }
}

/** Read the mirror and gate on it. Consulted by the enrollment gate before
 * every dispatched bridge request. */
export async function killGate(): Promise<KillGate> {
  const { [KILL_MIRROR_KEY]: value } = await browser.storage.local.get(KILL_MIRROR_KEY);
  return killGateFromStored(value);
}

/** The mirror for the UI (null = never heard from a host). */
export async function getKillMirror(): Promise<KillMirror | null> {
  const { [KILL_MIRROR_KEY]: value } = await browser.storage.local.get(KILL_MIRROR_KEY);
  const parsed = KillMirrorSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

async function setMirror(state: KillMirror["state"]): Promise<void> {
  const previous = await getKillMirror();
  // Unchanged state writes nothing: `at` means "when the mirror last
  // CHANGED", and an idempotent rewrite would retrigger every
  // storage.onChanged consumer (the options panel refreshes on the mirror
  // and queries the host, whose reply lands here - rewriting unchanged
  // state would close that loop into an infinite query cycle).
  if (previous?.state === state) return;
  await browser.storage.local.set({
    [KILL_MIRROR_KEY]: { state, at: Date.now() } satisfies KillMirror,
  });
  // Local ring only: the host already audits its own transitions.
  auditEvent("kill_status_changed", { outcome: state }, { forward: false });
}

// ---- port plumbing (mirrors clients.ts) --------------------------------------

let postFrame: ((frame: object) => boolean) | null = null;

export function attachPort(post: (frame: object) => boolean): void {
  postFrame = post;
  // At-least-once for the panic brake (ADR-0030): an engage that was handed
  // to a port that then died UNCONFIRMED (no refusing frame ever arrived) is
  // re-asserted on the fresh host - a dying host must not be able to drop
  // the brake silently. Idempotent host-side (engaging a killed bridge just
  // re-bumps the epoch) and audited there; if the user explicitly released
  // in the gap, the re-assert re-kills, which is the honest at-least-once
  // reading of an unconfirmed "kill everything" - releasing again is
  // friction the user can see, unlike a lost kill.
  if (unconfirmedEngageSeq !== null) {
    auditEvent("kill_engaged", { outcome: "requested" }, { forward: false });
    if (post({ type: "kill_engage" })) {
      unconfirmedEngageSeq = frameArrivals;
    }
    // A failed re-post keeps the flag armed: the next attach retries.
  }
}

export function detachPort(): void {
  postFrame = null;
  failPending("native host disconnected");
}

export interface KillView {
  ok: boolean;
  /** Whether the request frame was handed to the host's port. false means
   * nothing was ever put on the pipe; ABSENT or true means the frame may
   * still be applied by the host even when `ok` is false (a timeout, a
   * disconnect after the post, a failed mirror write), so consumers
   * deciding "is the exchange dead?" must treat only an explicit false as
   * dead (fail closed). */
  sent?: boolean;
  /** The resulting/last-known state ("alive" | "killed" | "unknown"), plus
   * when the mirror last changed. */
  state?: KillMirror["state"];
  at?: number;
  error?: string;
}

interface Pending {
  resolve: (v: KillView) => void;
  timer: ReturnType<typeof setTimeout>;
}

let pending: Pending | null = null;

function failPending(reason: string): void {
  if (pending) {
    clearTimeout(pending.timer);
    // sent:true - a pending exchange only exists once its frame was handed
    // to the port (a failed post clears the slot synchronously), so a
    // disconnect here is AMBIGUOUS: the host may have applied the frame
    // before dying. Reporting sent:false would let the panic path treat a
    // maybe-applied engage as never-sent and lift the latch.
    pending.resolve({ ok: false, sent: true, error: reason });
    pending = null;
  }
}

async function mirrorView(ok: boolean, sent: boolean, error?: string): Promise<KillView> {
  const mirror = await getKillMirror();
  return { ok, sent, state: mirror?.state, at: mirror?.at, error };
}

/** One kill request (status query or transition) over the port. One request
 * outstanding at a time; the host replies in order on a single pipe. */
function request(frame: object, timeoutMs: number = KILL_REQUEST_TIMEOUT_MS): Promise<KillView> {
  if (!postFrame) {
    return mirrorView(false, false, "native host not connected");
  }
  if (pending) {
    return Promise.resolve({
      ok: false,
      sent: false,
      error: "a kill-switch request is already in flight",
    });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending = null;
      // sent:true - the frame is on the pipe and the host may still apply
      // it; a timeout is silence, not proof of death.
      void mirrorView(false, true, "no reply from the native host (timed out)").then(resolve);
    }, timeoutMs);
    pending = { resolve, timer };
    if (!postFrame?.(frame)) {
      clearTimeout(timer);
      pending = null;
      void mirrorView(false, false, "failed to send the request to the native host").then(resolve);
    } else if ((frame as { type?: string }).type === "kill_engage") {
      // Arm the at-least-once re-post (see attachPort) for EVERY engage that
      // actually reached the pipe, whichever surface posted it. Armed only
      // on success, in the same synchronous turn as the post, so the flag
      // being set always means "a real engage is outstanding".
      unconfirmedEngageSeq = frameArrivals;
    }
  });
}

/** The options page's status read: last-known mirror plus a live host query
 * when the port is up (which also refreshes the mirror). */
export function requestKillStatus(): Promise<KillView> {
  return request({ type: "kill_status" });
}

// ---- panic-latch support (ADR-0030 confirm-window engage) --------------------

// Arrival counter for inbound kill_status_result frames, stamped in
// handleKillFrame BEFORE the serialized processing chain: SW storage writes
// interleave at awaits, so "processed after the panic subscribed" is NOT the
// same as "arrived after the panic subscribed" - a pre-panic frame whose
// mirror write was still in flight when the panic landed would otherwise
// masquerade as post-panic evidence.
let frameArrivals = 0;

// The single panic waiter. One per panic: a newer panic REPLACES the older
// waiter (whose promise then never settles - its epoch-scoped release in
// the router would be a no-op anyway), which is also what keeps waiters
// from accumulating across repeated panics in one SW lifetime.
//
// Two-phase and frame-driven ONLY - the stored mirror is deliberately never
// consulted, because at panic time it can read a stale "killed" while a
// pending release is about to write "alive" with the panic's own engage
// still queued behind it on the pipe. Only frames that ARRIVED after the
// subscribe (afterSeq) count; the subscribe and the engage post share one
// synchronous turn, so counting from the subscribe is counting from the
// post:
//   phase 1: an authoritative refusing frame (killed/unknown) lands - the
//            engage (or an equivalent cross-surface kill) has applied;
//   phase 2: a LATER authoritative alive frame lands. After the engage has
//            applied, only an explicit user-presence-gated release produces
//            an alive state, so that is exactly the moment confirmations may
//            legitimately resume.
// Residual, named: a cross-surface kill push already in flight when the
// panic lands (written by the host before it processed this engage, arriving
// after the subscribe) can satisfy phase 1 one frame early, letting a
// pre-panic release's alive reply lift while the engage is still queued;
// similarly, a repeat panic anchored at an EARLIER outstanding engage can
// lift on a release that lands before the repeat's own (failed or queued)
// engage settles. Both windows open only on an explicit presence-gated
// release racing the brake, and no web page, content script, or MCP client
// can mint either frame (the router's sender gate and the server-leg
// control-frame drop); the conceded same-user-process boundary (a replaced
// host binary) can forge frames, but that boundary already owns the bridge -
// see docs/security/trust-boundaries.md.
let panicWaiter: { afterSeq: number; sawRefusal: boolean; resolve: () => void } | null = null;

// The watermark of a panic engage that was handed to a port but has not yet
// been CONFIRMED by a refusing frame that arrived after it. attachPort
// re-posts while this is armed (at-least-once, see there); a refusing
// arrival after the watermark disarms it.
let unconfirmedEngageSeq: number | null = null;

/** Resolves once the kill state - via host frames alone - has authoritatively
 * refused (the engage applied) and then read alive again (an explicit,
 * presence-gated release). May never resolve in a session where the engage
 * never lands or the switch is never released - the caller pairs it with the
 * exchange's send-failure path, and an unresolved waiter just leaves the
 * panic latch denying confirmations, which is the fail-closed posture. */
export function whenKillRevivesAfterRefusal(): Promise<void> {
  return new Promise<void>((resolve) => {
    // Anchor at the OUTSTANDING engage's post when one is in flight: that
    // engage IS the brake this panic wants (its own post may even fail),
    // so frames postdating ITS post are valid settlement evidence. Without
    // this, a refusing frame that arrived before this subscribe (but whose
    // settlement is exactly what the panic is waiting on) would be ignored
    // and a send-failure panic could deny confirmations forever, past even
    // the explicit release. With nothing outstanding, anchor here - the
    // subscribe and this panic's own engage post share one synchronous
    // turn, so this counts from the post.
    const afterSeq = unconfirmedEngageSeq ?? frameArrivals;
    panicWaiter = { afterSeq, sawRefusal: false, resolve };
  });
}

/** Advance the panic waiter on one authoritative, mirror-committed state.
 * `seq` is the frame's ARRIVAL stamp; frames that predate the waiter's
 * subscription are ignored (they prove nothing about the panic's engage). */
function advancePanicWaiter(state: KillMirror["state"], seq: number): void {
  if (state !== "alive" && unconfirmedEngageSeq !== null && seq > unconfirmedEngageSeq) {
    // The brake (or an equivalent kill) demonstrably applied after the
    // engage was posted: nothing left to re-assert on reconnect.
    unconfirmedEngageSeq = null;
  }
  if (!panicWaiter || seq <= panicWaiter.afterSeq) return;
  if (state !== "alive") {
    panicWaiter.sawRefusal = true;
    return;
  }
  if (panicWaiter.sawRefusal) {
    const waiter = panicWaiter;
    panicWaiter = null;
    waiter.resolve();
  }
}

/** Engage or release the switch. The host performs the transition (and
 * audits it, surface=extension); the mirror adopts the host's answer. The
 * caller was already gated: the router accepts set_kill only from extension
 * pages, so a page can NEVER reach this. */
export function setKillSwitch(on: boolean): Promise<KillView> {
  // Local ring only: the host records the authoritative kill_engage/release.
  auditEvent(on ? "kill_engaged" : "kill_released", { outcome: "requested" }, { forward: false });
  return on
    ? request({ type: "kill_engage" })
    : request({ type: "kill_release" }, KILL_RELEASE_TIMEOUT_MS);
}

/** The panic engage (the confirm window's deny-and-kill, ADR-0030): never
 * refused because some OTHER kill exchange holds the single request slot
 * (the startup status query, an options-page read, or - worst case - an
 * in-flight release). With the slot free this is setKillSwitch(true); with
 * it occupied the engage frame is posted anyway, uncorrelated: the control
 * frames carry no ids, the host applies them in arrival order on one pipe,
 * and the mirror adopts every kill_status_result in order, so the pending
 * exchange settles with equally authoritative state and an engage racing a
 * release still lands AFTER it (final state: killed). The returned view
 * reports only the SEND outcome plus the last-known mirror, never the
 * engage's result - the result is whatever the mirror adopts, which is what
 * whenKillRevivesAfterRefusal watches. A successfully posted engage also
 * arms the at-least-once re-post (see attachPort): only a refusing frame
 * that arrives after the post disarms it, so a host dying mid-exchange
 * cannot swallow the brake. Residual, named honestly: with the port down
 * the engage cannot reach the host at all (ok: false); nothing can drive the
 * browser through a dead port either, and the popup renders that state
 * severed, never live. */
export function engageKillSwitch(): Promise<KillView> {
  if (!pending) return setKillSwitch(true);
  auditEvent("kill_engaged", { outcome: "requested" }, { forward: false });
  if (!postFrame) return mirrorView(false, false, "native host not connected");
  if (!postFrame({ type: "kill_engage" })) {
    return mirrorView(false, false, "failed to send the request to the native host");
  }
  // Armed only AFTER the successful post (same synchronous turn, so no
  // frame can interleave): a set flag always means a real engage is on the
  // pipe, which is what engageOutstanding's callers rely on.
  unconfirmedEngageSeq = frameArrivals;
  return mirrorView(true, true);
}

/** Whether a successfully posted engage is still unconfirmed - no refusing
 * frame has arrived since it went out (on this port or a reconnect's
 * re-post). While true, one exchange's "my send failed" proves nothing
 * globally: some engage may still apply, so the panic latch must not lift
 * on that failure alone. */
export function engageOutstanding(): boolean {
  return unconfirmedEngageSeq !== null;
}

// Frames are processed strictly in arrival order: SW event handlers
// interleave at awaits, so two overlapping handleKillFrame calls could
// otherwise finish their storage writes in the wrong order and leave the
// mirror on the OLDER state (e.g. "alive" surviving a later "killed").
let frameChain: Promise<void> = Promise.resolve();

/** Route one inbound kill_status_result: update the mirror (every result is
 * authoritative, solicited or pushed), then resolve a pending request if one
 * was outstanding when the frame arrived. Serialized via the chain above;
 * the arrival stamp is taken HERE, before the chain, so the panic waiter
 * can tell pre-panic frames (stamped low, however late their storage write
 * completes) from genuinely post-panic evidence. */
export function handleKillFrame(msg: KillStatusResult): Promise<void> {
  frameArrivals += 1;
  const seq = frameArrivals;
  frameChain = frameChain
    .then(() => handleOneKillFrame(msg, seq))
    .catch((e) => {
      console.warn("[bb] kill frame handling failed", e);
    });
  return frameChain;
}

async function handleOneKillFrame(msg: KillStatusResult, seq: number): Promise<void> {
  // Claim the pending request BEFORE any await: the host answers on one
  // ordered pipe, so a frame arriving while a request is outstanding is its
  // answer, or a push carrying equally authoritative state. Not claiming it
  // up front would let the request's timeout fire mid-await and a NEXT
  // request take the slot, which this frame would then wrongly resolve.
  //
  // Pushes and replies are deliberately not correlated (the control frames
  // have no ids): if a cross-surface transition pushes mid-request, the
  // request settles one frame early with that push's state. That is safe by
  // construction - nothing enforcing reads the returned view (the gate reads
  // only the mirror, which applies every frame in order), and the panel
  // re-renders from the mirror on storage.onChanged - so the view is
  // transiently early, never wrong about what the host last said.
  const current = pending;
  pending = null;
  if (current) clearTimeout(current.timer);

  // ok:false = the host cannot read its own state: unknown, which the gate
  // refuses.
  const state: KillMirror["state"] =
    msg.ok && typeof msg.killed === "boolean" ? (msg.killed ? "killed" : "alive") : "unknown";
  let stored = false;
  try {
    await setMirror(state);
    stored = true;
    // Only after a successful write: the waiter's contract is "the STORED
    // state now reads this" (what killGate enforces on), not "a frame
    // claiming it was seen".
    advancePanicWaiter(state, seq);
  } finally {
    // The pending exchange must always settle, even when the mirror write
    // throws - stranding the caller would leave its consumer (the panic
    // path, the options page) hanging instead of failing closed. A failed
    // write settles ok:false: reporting ok:true over the STALE mirror would
    // hand the caller a state the gate is not actually enforcing.
    if (current) {
      if (!stored) {
        current.resolve({
          ok: false,
          sent: true,
          error: "the kill-switch mirror could not be written; state unknown",
        });
      } else {
        // mirrorView is itself a storage read, so its failure must not
        // strand the caller either.
        try {
          current.resolve(await mirrorView(msg.ok, true, msg.error));
        } catch {
          current.resolve({ ok: false, sent: true, error: "kill state storage is unreadable" });
        }
      }
    }
  }
}

/** Tests only: forget port + pending so suites can drive both paths. */
export function resetKillForTests(): void {
  postFrame = null;
  failPending("test reset");
  pending = null;
  frameChain = Promise.resolve();
  panicWaiter = null;
  unconfirmedEngageSeq = null;
  // frameArrivals is deliberately NOT reset: it stays monotonic across
  // resets so a stale still-running handler from a previous test (its seq
  // stamped before the reset) can never outrank a new waiter's afterSeq.
}
