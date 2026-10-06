// The extension half of the kill switch: a service-worker-only mirror of the host's kill state, and the
// control-frame plumbing that reads and toggles it.
//
// The host's trust record is the AUTHORITY; the mirror lets the extension's own gate refuse locally while killed and
// the options page render the state. It is written ONLY from kill_status_result frames, never from a runtime message
// (the router relays get_kill/set_kill to the host, which answers with the resulting state), and it lives in trusted
// storage (trusted-storage.ts), so a page can neither read nor plant it.
//
// Gate verdict per stored value; fail closed on everything but a positive "alive":
//   absent           -> allowed (never heard from a host; a fresh install must not be bricked, the host enforces)
//   {state: alive}   -> allowed
//   {state: killed}  -> refused
//   {state: unknown} -> refused (the host cannot read its own state)
//   malformed        -> refused (tampering evidence, never mapped to absent)
//
// port.ts drives `collaborator`; messages.ts routes the options-page actions here. Every result updates the mirror;
// a solicited one also resolves the pending request. The panic brake, its latch, and the re-post watermark are brake.ts.

import {
  isKillStatusFrame,
  type KillMirror,
  KillMirrorSchema,
} from "@chromium-bridge/shared/enclave";
import type {
  KillEngageWire,
  KillStatusResult,
  KillStatusWire,
} from "@chromium-bridge/shared/envelope.gen";
import pLimit from "p-limit";
import { browser } from "wxt/browser";
import { inLife } from "../shared/in-life";
import { readKey, readKeyOr, type Stored } from "../shared/storage";
import { claimKillRelease, type PresenceAssertView } from "../webauthn/exchange";
import { auditEvent } from "./audit-log";
import { advance, engageOutstanding, resetBrakeForTests, stampArrival } from "./brake";
import type { PortCollaborator } from "./connection";
import { exchange, type Failure } from "./exchange";

const KILL_MIRROR_KEY = "bridgeKillMirror";

export type KillGate = { allowed: true } | { allowed: false; reason: string };

/** The mirror's verdict for the request gate. */
function killGateFromStored(stored: Stored<KillMirror>): KillGate {
  if (stored.state === "absent") return { allowed: true };
  if (stored.state === "corrupt") {
    return {
      allowed: false,
      reason:
        "the stored kill-switch mirror is malformed; refusing all bridge activity " +
        "(possible tampering). Engage the kill switch from the options page, or run " +
        "`chromium-bridge kill` / `unkill`, to rewrite it.",
    };
  }
  switch (stored.value.state) {
    case "alive":
      return { allowed: true };
    case "killed":
      return {
        allowed: false,
        reason:
          "the bridge kill switch is engaged; all bridge activity is refused until " +
          "it is explicitly released (`chromium-bridge unkill`)",
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

/** Read the mirror and gate on it. Consulted by the enrollment gate before every dispatched bridge request. */
export async function killGate(): Promise<KillGate> {
  return killGateFromStored(await readKey(KILL_MIRROR_KEY, KillMirrorSchema));
}

/** The mirror for the UI (null = never heard from a host). */
export function getKillMirror(): Promise<KillMirror | null> {
  return readKeyOr(KILL_MIRROR_KEY, KillMirrorSchema, null);
}

async function setMirror(state: KillMirror["state"]): Promise<void> {
  const previous = await getKillMirror();
  // An unchanged state writes nothing: `at` means "when the mirror last CHANGED", and the options panel refreshes on
  // every storage.onChanged and queries the host, whose reply lands here, so an idempotent rewrite would close that
  // loop into an infinite query cycle.
  if (previous?.state === state) return;
  await browser.storage.local.set({
    [KILL_MIRROR_KEY]: { state, at: Date.now() } satisfies KillMirror,
  });
  // Local ring only: the host already audits its own transitions.
  auditEvent("kill_status_changed", { outcome: state });
}

// ---- port plumbing ----------------------------------------------------------

/** Closed over the GENERATED wire types (envelope.gen.ts <- protocol/control.rs), so a typo'd frame type is a compile
 * error rather than a frame the host drops. kill_release is not here: its reply is a presence request, so the
 * WebAuthn exchange (../webauthn/exchange.ts) posts it. */
export type KillControlFrame = KillStatusWire | KillEngageWire;

const ENGAGE = { type: "kill_engage" } satisfies KillControlFrame;

// Status and engage share the one exchange: the host answers both with kill_status_result.
const status = exchange<KillStatusResult>("a kill-switch request is already in flight");

export const collaborator: PortCollaborator = {
  onAttach(c) {
    status.attach(c);
    // At-least-once for the brake: an engage the previous host never confirmed is re-asserted on the fresh one, so a
    // dying host cannot drop it silently (host-side it is idempotent and audited). A failed re-post leaves it
    // outstanding, so the next attach retries; the SW's own death loses it, since nothing durable re-arms.
    if (engageOutstanding()) {
      auditEvent("kill_engaged", { outcome: "requested" });
      if (c.post(ENGAGE)) advance({ type: "engage-posted" });
    }
  },
  onDetach() {
    status.detach();
  },
  onFrame(msg) {
    if (!isKillStatusFrame(msg)) return false;
    void handleKillFrame(msg);
    return true;
  },
};

export interface KillView {
  ok: boolean;
  /** Whether the request frame was handed to the host's port. false means nothing was ever put on the pipe; ABSENT
   * or true means the frame may still be applied by the host even when `ok` is false (a timeout, a disconnect after
   * the post, a failed mirror write). */
  sent?: boolean;
  /** The resulting/last-known state ("alive" | "killed" | "unknown"), plus when the mirror last changed. */
  state?: KillMirror["state"];
  at?: number;
  error?: string;
}

/** The send outcome plus the last-known mirror. Never rejects: a view that could not read storage still settles,
 * as ok:false, so no caller (the options page, the panic path) is stranded on a failed read. */
async function mirrorView(ok: boolean, sent: boolean, error?: string): Promise<KillView> {
  try {
    const mirror = await getKillMirror();
    return { ok, sent, state: mirror?.state, at: mirror?.at, error };
  } catch {
    return { ok: false, sent, error: "kill state storage is unreadable" };
  }
}

/** A refusal the host never answered carries the last-known mirror; a busy slot, a detach and an unwritten mirror
 * settle bare, and KillSwitchPanel paints a bare refusal as severed. */
function refusedView(failure: Failure): KillView | Promise<KillView> {
  switch (failure.why) {
    case "not-connected":
    case "post-failed":
    case "timed-out":
      return mirrorView(false, failure.posted, failure.error);
    case "busy":
    case "detached":
    case "failed":
      return { ok: false, sent: failure.posted, error: failure.error };
  }
}

/** One kill request (status query or engage) over the port. `posted` is known in the same synchronous turn so the
 * caller can anchor the brake at it. */
function request(frame: KillControlFrame): { posted: boolean; view: Promise<KillView> } {
  return status.request(frame, {
    read: (msg) => mirrorView(msg.ok, true, msg.error),
    refused: refusedView,
  });
}

/** The options page's status read: last-known mirror plus a live host query when the port is up (which also
 * refreshes the mirror). */
export function requestKillStatus(): Promise<KillView> {
  return request({ type: "kill_status" }).view;
}

/** Engage. The router accepts set_kill from extension pages only, with `on` pinned to true, so a page can neither
 * reach this nor express a release here: release is the WebAuthn exchange's kill_release, behind the host's presence
 * request. The host performs and audits the transition; the mirror adopts its answer. */
export function engageKill(): Promise<KillView> {
  // Local ring only: the host records the authoritative kill_engage.
  auditEvent("kill_engaged", { outcome: "requested" });
  const { posted, view } = request(ENGAGE);
  if (posted) advance({ type: "engage-posted" });
  return view;
}

/** The confirm window's panic engage: never refused because another exchange holds the single request slot.
 *   slot free      -> engageKill's exchange under the brake's panic event; the view carries the host's answer
 *   slot occupied  -> the engage is posted uncorrelated; the view is the SEND outcome plus the last-known mirror
 * Uncorrelated is safe: control frames carry no ids and the host applies them in arrival order on one pipe, so the
 * pending exchange settles with equally authoritative state and an engage racing a release still lands after it. */
export function panicEngage(): Promise<KillView> {
  auditEvent("kill_engaged", { outcome: "requested" });
  if (!status.isOpen()) {
    const { posted, view } = request(ENGAGE);
    advance({ type: "panic", posted });
    return view;
  }
  const posted = status.post(ENGAGE);
  advance({ type: "panic", posted });
  if (posted) return mirrorView(true, true);
  return mirrorView(false, false, "failed to send the request to the native host");
}

// Frames apply strictly in arrival order: SW event handlers interleave at awaits, and two overlapping handlers could
// otherwise finish their storage writes in the wrong order and leave the mirror on the OLDER state.
const frames = inLife(() => pLimit(1));

/** Route one inbound kill_status_result: update the mirror (every result is authoritative, solicited or pushed), then
 * resolve a pending request if one was outstanding when the frame arrived. Stamped before the lane (brake.ts says
 * why). */
export function handleKillFrame(msg: KillStatusResult): Promise<void> {
  const seq = stampArrival();
  // Claimed at arrival, like the stamp (exchange.ts claimKillRelease says why).
  const settleRelease = claimKillRelease(msg);
  return frames
    .value(() => handleOneKillFrame(msg, seq, settleRelease))
    .catch((e) => {
      console.warn("[bb] kill frame handling failed", e);
    });
}

async function handleOneKillFrame(
  msg: KillStatusResult,
  seq: number,
  settleRelease: ((view: PresenceAssertView) => void) | null,
): Promise<void> {
  // Claim the pending request BEFORE any await: the host answers in order on one pipe, so a frame arriving while a
  // request is outstanding is its answer or an equally authoritative push. Claiming late would let the timeout fire
  // mid-await and a NEXT request take the slot, which this frame would then wrongly resolve. A cross-surface push
  // mid-request settles the request one frame early; nothing enforcing reads the view (the gate reads the mirror).
  const claimed = status.claim();

  // ok:false = the host cannot read its own state: unknown, which the gate refuses.
  const state: KillMirror["state"] =
    msg.ok && typeof msg.killed === "boolean" ? (msg.killed ? "killed" : "alive") : "unknown";
  let stored = false;
  try {
    await setMirror(state);
    stored = true;
    // Committed frames only (brake.ts, the frame event).
    advance({ type: "frame", state, seq });
  } finally {
    // The pending exchange must always settle, even when the mirror write throws: stranding the caller would leave
    // its consumer (the options page) hanging instead of failing closed. A failed write settles ok:false, since
    // ok:true over the STALE mirror would hand the caller a state the gate is not actually enforcing. The lane
    // holds until the view has read the mirror, or the next frame's write could land first and the view would
    // report that push's state instead of this reply's.
    if (stored) await claimed?.settle(msg);
    else await claimed?.fail("the kill-switch mirror could not be written; state unknown");
    settleRelease?.(releaseOutcome(msg, stored));
  }
}

function releaseOutcome(msg: KillStatusResult, stored: boolean): PresenceAssertView {
  if (!msg.ok) {
    return { ok: false, error: msg.error ?? "the host could not read its kill-switch state" };
  }
  if (!stored) {
    return { ok: false, error: "the kill-switch mirror could not be written; state unknown" };
  }
  return msg.killed === false
    ? { ok: true }
    : { ok: false, error: "the kill switch is still engaged" };
}

/** Tests only: forget the port, the pending exchange, the frame lane, and the brake. */
export function resetKillForTests(): void {
  status.detach();
  frames.reset();
  resetBrakeForTests();
}
