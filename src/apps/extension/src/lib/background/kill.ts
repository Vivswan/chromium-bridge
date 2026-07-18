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
}

export function detachPort(): void {
  postFrame = null;
  failPending("native host disconnected");
}

export interface KillView {
  ok: boolean;
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
    pending.resolve({ ok: false, error: reason });
    pending = null;
  }
}

async function mirrorView(ok: boolean, error?: string): Promise<KillView> {
  const mirror = await getKillMirror();
  return { ok, state: mirror?.state, at: mirror?.at, error };
}

/** One kill request (status query or transition) over the port. One request
 * outstanding at a time; the host replies in order on a single pipe. */
function request(frame: object, timeoutMs: number = KILL_REQUEST_TIMEOUT_MS): Promise<KillView> {
  if (!postFrame) {
    return mirrorView(false, "native host not connected");
  }
  if (pending) {
    return Promise.resolve({ ok: false, error: "a kill-switch request is already in flight" });
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending = null;
      void mirrorView(false, "no reply from the native host (timed out)").then(resolve);
    }, timeoutMs);
    pending = { resolve, timer };
    if (!postFrame?.(frame)) {
      clearTimeout(timer);
      pending = null;
      void mirrorView(false, "failed to send the request to the native host").then(resolve);
    }
  });
}

/** The options page's status read: last-known mirror plus a live host query
 * when the port is up (which also refreshes the mirror). */
export function requestKillStatus(): Promise<KillView> {
  return request({ type: "kill_status" });
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

// Frames are processed strictly in arrival order: SW event handlers
// interleave at awaits, so two overlapping handleKillFrame calls could
// otherwise finish their storage writes in the wrong order and leave the
// mirror on the OLDER state (e.g. "alive" surviving a later "killed").
let frameChain: Promise<void> = Promise.resolve();

/** Route one inbound kill_status_result: update the mirror (every result is
 * authoritative, solicited or pushed), then resolve a pending request if one
 * was outstanding when the frame arrived. Serialized via the chain above. */
export function handleKillFrame(msg: KillStatusResult): Promise<void> {
  frameChain = frameChain
    .then(() => handleOneKillFrame(msg))
    .catch((e) => {
      console.warn("[bb] kill frame handling failed", e);
    });
  return frameChain;
}

async function handleOneKillFrame(msg: KillStatusResult): Promise<void> {
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

  if (msg.ok && typeof msg.killed === "boolean") {
    await setMirror(msg.killed ? "killed" : "alive");
  } else {
    // The host cannot read its own state: unknown, which the gate refuses.
    await setMirror("unknown");
  }
  if (current) current.resolve(await mirrorView(msg.ok, msg.error));
}

/** Tests only: forget port + pending so suites can drive both paths. */
export function resetKillForTests(): void {
  postFrame = null;
  failPending("test reset");
  pending = null;
  frameChain = Promise.resolve();
}
