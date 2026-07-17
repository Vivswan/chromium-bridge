// The enrollment ceremony state machine: the extension half of ADR-0021.
//
// port.ts hands this module the native-messaging port (attachPort) and every
// enclave control frame; messages.ts routes the options/popup actions here.
// This module never imports port.ts, so there is no import cycle.
//
// States, derived from storage on every read (nothing cached across the MV3
// service-worker restarts):
//
//   unpaired    no pin. Bridge traffic is refused while requireEnrollment is
//               on. Each connect issues a pairing challenge (unless paused);
//               on an unenrolled machine that costs one enclave_error round
//               trip and no prompt, and once `chromium-bridge pair` has minted
//               a key it raises the single ceremony Touch ID prompt.
//   pending     a pairing proof verified; the fingerprint awaits the user's
//               approval in the options page. Still refused.
//   pinned      the user approved; bridge traffic flows. Session granularity
//               (ADR-0021): reconnects are NOT re-challenged, because every
//               host signature raises a presence prompt and MV3 respawns the
//               host every few minutes. "Verify now" in the options page
//               challenges on demand, and the opt-in hostReverifyMs setting
//               re-verifies lazily on connect once the last success is older
//               than that interval (default 0 = off).
//   compromised a pinned-key verification failed. Refused until the user
//               revokes and re-pairs.
//
// Platform scoping: on platforms without a Secure Enclave (decided by the
// browser's own getPlatformInfo probe, never by the host's claim) enrollment
// is unavailable, so the gate does not block and no challenge is issued; the
// bridge runs on the base transport authentication.
//
// The challenge-on-connect policy lives entirely in onPortConnected below.

import {
  type EnclaveInboundFrame,
  EnclaveInboundFrameSchema,
  EnclaveProofFrameSchema,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { getSetting } from "../shared/settings";
import * as pinStore from "./enclave-pin";
import {
  fingerprintDisplay,
  generateNonce,
  verifyPairingProof,
  verifyProofAgainstPin,
} from "./enclave-verify";
import { hardenStorageAccess } from "./trusted-storage";

// ---- frame plumbing ---------------------------------------------------------

export type { EnclaveInboundFrame };

/** True for the three ADR-0021 control frame tags. Bridge requests carry `op`
 * and never a top-level `type`, so nothing legitimate collides. */
export function isEnclaveFrame(msg: unknown): msg is EnclaveInboundFrame {
  return EnclaveInboundFrameSchema.safeParse(msg).success;
}

// The port sender, registered by port.ts while a port is up. Null = not
// connected.
let postFrame: ((frame: object) => boolean) | null = null;

export function attachPort(post: (frame: object) => boolean): void {
  postFrame = post;
}

export function detachPort(): void {
  postFrame = null;
  // The host process died with the port; its proof can never arrive, and the
  // nonce must not outlive the challenge it was issued for.
  clearOutstanding();
}

// ---- transition serialization -------------------------------------------------

// Every state transition (inbound proof/error, user action, connect hook)
// runs through this queue. Several options tabs, the popup, and the port all
// call in concurrently, and an interleaved revoke/approve must not resurrect
// a pin, so each transition re-checks its preconditions inside the queue.
let transitionChain: Promise<unknown> = Promise.resolve();

function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const next = transitionChain.then(fn, fn);
  transitionChain = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
}

// ---- outstanding challenge --------------------------------------------------

// In-memory only, on purpose: single-use nonce freshness is what makes a
// proof non-replayable, and persisting a nonce would let a proof be accepted
// by a later service-worker incarnation that never issued it. If the SW dies
// mid-ceremony the challenge is simply lost and reissued.
interface Outstanding {
  nonce: string;
  context: string;
  mode: "pair" | "verify";
  timer: ReturnType<typeof setTimeout>;
}

let outstanding: Outstanding | null = null;

// Generous because answering a challenge blocks on the macOS presence prompt.
const CHALLENGE_TIMEOUT_MS = 120_000;

function clearOutstanding(): void {
  if (outstanding) {
    clearTimeout(outstanding.timer);
    outstanding = null;
  }
}

async function issueChallenge(mode: "pair" | "verify"): Promise<{ ok: boolean; error?: string }> {
  if (!postFrame) return { ok: false, error: "native host not connected" };
  if (outstanding) return { ok: false, error: "a challenge is already outstanding" };
  const nonce = generateNonce();
  const context = `ext:${browser.runtime.id}:${mode}`;
  const timer = setTimeout(() => {
    outstanding = null;
    void pinStore
      .setLastError(
        `no answer to the ${mode} challenge within ${CHALLENGE_TIMEOUT_MS / 1000}s ` +
          "(presence prompt unanswered, or the host hung)",
      )
      .then(updateBadge);
  }, CHALLENGE_TIMEOUT_MS);
  outstanding = { nonce, context, mode, timer };
  if (!postFrame({ type: "enclave_challenge", nonce, context })) {
    clearOutstanding();
    return { ok: false, error: "failed to send the challenge to the native host" };
  }
  console.log(`[bb] enclave ${mode} challenge issued`);
  return { ok: true };
}

// ---- platform capability ------------------------------------------------------

/** Whether this platform can enroll at all, decided by the BROWSER's own
 * platform probe (browser.runtime.getPlatformInfo), never by the host's
 * unsupported_platform claim. The host is the party being authenticated, so
 * its self-reported platform must not be able to open the gate: a
 * substituted host on macOS could otherwise dodge enrollment by claiming
 * "unsupported". Where the Secure Enclave does not exist (non-mac),
 * enrollment is unavailable rather than unsatisfied: the bridge runs on the
 * base transport authentication and the ceremony is skipped entirely. That
 * is a platform fact, not a disabled security control. If the probe itself
 * fails, ambiguity fails closed: the platform is treated as capable and the
 * gate enforces. */
async function platformCanEnroll(): Promise<boolean> {
  try {
    const info = await browser.runtime.getPlatformInfo();
    return info.os === "mac";
  } catch (e) {
    console.warn("[bb] getPlatformInfo failed; enforcing enrollment", e);
    return true;
  }
}

// ---- the fail-closed gate ----------------------------------------------------

export type Gate = { allowed: true } | { allowed: false; reason: string };

/** Consulted by port.ts before every dispatched bridge request. "Blocked"
 * means exactly this: the request is answered with {ok:false, error:reason}
 * and never reaches dispatch(), so no tab, cookie, or page op runs. The
 * block-until-pinned enforcement applies only where the platform can enroll
 * (macOS); elsewhere enrollment is unavailable and requests proceed on the
 * base authentication.
 *
 * Fail closed against concurrent transitions: the state reads are
 * individually async and this gate runs on the hot request path, so a
 * transition (a revoke, a compromised mark) can land while a read pass is in
 * flight. A first, unserialized pass answers the cheap refusals; an
 * "allowed" answer must then be confirmed by a second read INSIDE the
 * serialized transition queue, and `onAllowed` (the dispatch kickoff) runs
 * synchronously in that same critical section. That gives every op a strict
 * order against every transition: a transition queued or in flight before
 * the confirming read is fully applied first and honored (the op is
 * blocked); a transition queued after it runs strictly after the op has
 * already begun dispatching, i.e. the op is ordered before the transition by
 * mechanism, not by luck. */
export async function enrollmentGate(onAllowed?: () => void): Promise<Gate> {
  const first = await readGateState();
  if (!first.allowed) return first;
  return serialized(async () => {
    const gate = await readGateState();
    if (gate.allowed) onAllowed?.();
    return gate;
  });
}

/** One unserialized read of the gate state. Callers other than the two-pass
 * enrollmentGate must not use this to grant access. */
async function readGateState(): Promise<Gate> {
  // #32 FIRST, unconditionally: every check below reads trust state from
  // browser.storage, which must be confined to extension contexts before we
  // can believe any of it. If the restriction is not verifiably applied this
  // SW life, a content script could have written the very values we are about
  // to trust (planted a pin, flipped requireEnrollment off), so refuse - even
  // when requireEnrollment reads false, since that read is itself untrusted
  // until storage is locked down.
  const hardened = await hardenStorageAccess();
  if (!hardened.ok) {
    return {
      allowed: false,
      reason:
        `storage access could not be restricted to the extension (${hardened.reason}); ` +
        "refusing so a page context cannot tamper with the trust state. Update Chrome " +
        "and reload the extension.",
    };
  }
  if ((await getSetting("requireEnrollment")) !== true) return { allowed: true };
  const compromised = await pinStore.getCompromised();
  if (compromised) {
    return {
      allowed: false,
      reason:
        `enrollment failed closed: ${compromised.reason}. ` +
        "Bridge disabled until you revoke the pin in the extension options and re-pair " +
        "(`chromium-bridge pair`).",
    };
  }
  if (!(await platformCanEnroll())) return { allowed: true };
  if (await pinStore.getPin()) return { allowed: true };
  if (await pinStore.getPending()) {
    return {
      allowed: false,
      reason:
        "enrollment pending: open the extension options page and approve the host key " +
        "fingerprint (compare it with the `chromium-bridge pair` output)",
    };
  }
  return {
    allowed: false,
    reason:
      "enrollment required: run `chromium-bridge pair` on this machine, then approve the " +
      "fingerprint in the extension options page",
  };
}

// ---- connect hook -------------------------------------------------------------

/** Called by port.ts after each successful connectNative(). Once pinned this
 * refreshes the badge and, only when the opt-in hostReverifyMs interval has
 * lapsed, issues a re-verify challenge; per ADR-0021 the default steady
 * state is never challenged (a challenge is a Touch ID prompt, and MV3
 * reconnects every few minutes). While unpaired it drives the ceremony
 * forward. */
export function onPortConnected(): Promise<void> {
  return serialized(async () => {
    // Do not read or act on trust state until it is confined to the extension
    // (#32): the same reasoning as the gate. If hardening failed, do nothing -
    // the gate is already blocking every request, so there is no ceremony to
    // drive.
    if (!(await hardenStorageAccess()).ok) return;
    // ADR-0025: an unpair that could not reach the host yet (port was down,
    // SW died) is retried on every connect until the host acknowledges the
    // key deletion. Independent of the gate/ceremony state below.
    await maybeSendPendingHostRevoke();
    await updateBadge();
    if ((await getSetting("requireEnrollment")) !== true) return;
    if (!(await platformCanEnroll())) return; // no Enclave here; no ceremony
    if (await pinStore.getCompromised()) return;
    const pin = await pinStore.getPin();
    if (pin) {
      await maybePeriodicReverify(pin);
      return;
    }
    if (await pinStore.getPending()) return; // proof already in hand; awaiting approval
    if (await pinStore.getPaused()) return; // user halted pairing; manual restart only
    await issueChallenge("pair");
  });
}

/** Resend the not-yet-acknowledged host key-deletion request (ADR-0025). The
 * durable flag is cleared only by the host's `enclave_revoked` ack, so a lost
 * frame or a dead SW just means another send here; deletion is idempotent on
 * the host side. */
async function maybeSendPendingHostRevoke(): Promise<void> {
  if (!postFrame) return;
  if (!(await pinStore.getHostRevokePending())) return;
  if (postFrame({ type: "enclave_revoke" })) {
    console.log("[bb] requested host enrollment-key deletion (pending ack)");
  }
}

/** Optional lazy re-verification (hostReverifyMs > 0): on connect, when the
 * last successful verification (pairing counts as one) is older than the
 * interval, challenge the host against the pin. The default (0) keeps the
 * ADR-0021 session behavior: verify at pairing and on demand only. This is
 * detection, not gating - like a manual verify, an unanswered or declined
 * prompt leaves the pinned state and the gate unchanged, and only a
 * cryptographic mismatch (or a host that can no longer prove the key) fails
 * closed. Each re-verify raises a Touch ID prompt, which is why it is
 * opt-in. */
async function maybePeriodicReverify(pin: pinStore.EnclavePin): Promise<void> {
  const interval = await getSetting("hostReverifyMs");
  if (typeof interval !== "number" || interval <= 0) return;
  const lastVerified = Math.max(pin.pinnedAt, (await pinStore.getLastVerifiedAt()) ?? 0);
  if (Date.now() - lastVerified < interval) return;
  console.log("[bb] periodic host re-verification due");
  await issueChallenge("verify");
}

// ---- inbound control frames ----------------------------------------------------

/** Stable reason codes from the host (src/enclave.rs reason_code). */
const KNOWN_REASONS = new Set([
  "unsupported_platform",
  "not_enrolled",
  "invalid_challenge",
  "key_invalid",
  "keychain_error",
  "signing_failed",
]);

export function handleEnclaveFrame(msg: EnclaveInboundFrame): Promise<void> {
  return serialized(async () => {
    if (msg.type === "enclave_proof") return handleProof(msg);
    if (msg.type === "enclave_error") return handleError(msg);
    if (msg.type === "enclave_revoked") return handleRevoked();
    // The host never sends a challenge (or a revoke request) toward the
    // browser; drop it.
    console.warn("[bb] dropping unexpected", msg.type, "frame from native host");
  });
}

/** The host says the enrollment key is gone (ADR-0025): the acknowledgement
 * of our own `enclave_revoke`, or a host-originated push after an
 * out-of-band `chromium-bridge revoke` / `pair --reset`. Pure capability
 * reduction, so the (unauthenticated) frame is safe to honor: with a pin it
 * fails the bridge closed until the user re-pairs; without one it only
 * settles the pending-unpair bookkeeping. */
async function handleRevoked(): Promise<void> {
  if (await pinStore.getHostRevokePending()) {
    await pinStore.setHostRevokePending(false);
    console.log("[bb] host acknowledged the enrollment-key deletion");
  }
  const pin = await pinStore.getPin();
  if (!pin) return; // nothing pinned: nothing to fail closed
  await pinStore.setCompromised({
    reason: "the host's enrollment key was revoked (host-originated notice)",
    at: Date.now(),
  });
  console.error("[bb] host enrollment key revoked; bridge disabled until re-pair");
  await updateBadge();
}

async function handleProof(frame: EnclaveInboundFrame): Promise<void> {
  const current = outstanding;
  // Single use: the challenge is consumed even by a proof that fails to
  // verify. A retry needs a fresh nonce.
  clearOutstanding();
  if (!current) {
    // Unsolicited (a replay, or a frame injected on the server leg, which
    // never sees our nonces). Never verify, never touch state.
    console.warn("[bb] dropping unsolicited enclave_proof");
    return;
  }
  const proofFrame = EnclaveProofFrameSchema.safeParse(frame);
  if (!proofFrame.success) {
    await pinStore.setLastError("malformed enclave_proof frame from host");
    await updateBadge();
    return;
  }
  const { sig, key_id, pubkey } = proofFrame.data;
  const proof = { sig, key_id, pubkey };

  if (current.mode === "pair") {
    const res = await verifyPairingProof(proof, current.nonce, current.context);
    if (!res.ok) {
      await pinStore.setLastError(`pairing proof rejected: ${res.reason}`);
      await updateBadge();
      return;
    }
    // Re-check inside the transition queue: a pin or fail-closed mark that
    // appeared since the challenge went out wins over this proof.
    if ((await pinStore.getPin()) || (await pinStore.getCompromised())) {
      console.warn("[bb] dropping pairing proof; state changed while it was in flight");
      return;
    }
    await pinStore.setPending({ keyId: res.keyId, pubkeyB64: res.pubkeyB64, at: Date.now() });
    await pinStore.clearLastError();
    await updateBadge();
    console.log("[bb] pairing proof verified; awaiting fingerprint approval:", res.keyId);
    return;
  }

  // verify mode: only the PINNED key decides; the proof's own pubkey field is
  // ignored for trust purposes.
  const pin = await pinStore.getPin();
  if (!pin) {
    await pinStore.setLastError("verify proof arrived but no key is pinned");
    await updateBadge();
    return;
  }
  const res = await verifyProofAgainstPin(
    proof,
    current.nonce,
    current.context,
    pin.pubkeyB64,
    pin.keyId,
  );
  if (res.ok) {
    await pinStore.setLastVerifiedAt(Date.now());
    await pinStore.clearLastError();
    console.log("[bb] pinned key verified");
  } else {
    // Positive cryptographic evidence that whatever answered does not hold
    // the pinned key. Fail closed until the user re-pairs.
    await pinStore.setCompromised({
      reason: `host failed pinned-key verification: ${res.reason}`,
      at: Date.now(),
    });
    console.error("[bb] pinned-key verification FAILED; bridge disabled:", res.reason);
  }
  await updateBadge();
}

async function handleError(frame: EnclaveInboundFrame): Promise<void> {
  const current = outstanding;
  clearOutstanding();
  const reason =
    typeof frame.reason === "string" && KNOWN_REASONS.has(frame.reason)
      ? frame.reason
      : "unknown_error";
  if (!current) {
    console.warn("[bb] dropping unsolicited enclave_error:", reason);
    return;
  }
  if (
    current.mode === "verify" &&
    (reason === "not_enrolled" || reason === "key_invalid" || reason === "unsupported_platform")
  ) {
    // A key is pinned but the answering host can no longer prove it: the
    // enrollment key was revoked or replaced, or the host now denies Enclave
    // capability on a machine that demonstrably enrolled one (a downgrade
    // claim from a suspect binary). Fail closed.
    await pinStore.setCompromised({
      reason: `host cannot prove the pinned key (${reason})`,
      at: Date.now(),
    });
  } else {
    await pinStore.setLastError(errorHelp(reason, current.mode));
  }
  await updateBadge();
}

function errorHelp(reason: string, mode: "pair" | "verify"): string {
  switch (reason) {
    case "not_enrolled":
      return (
        "not_enrolled: no enrollment key exists on this machine. " +
        "Run `chromium-bridge pair` in a terminal, then return here."
      );
    case "unsupported_platform":
      return (
        "unsupported_platform: the host reports no Secure Enclave, but this browser is " +
        "running on macOS. If this Mac genuinely lacks one (pre-T2 Intel), pairing is " +
        'impossible and turning off "Require host pairing" is an explicit decision to run ' +
        "without host verification. Otherwise treat the host binary as suspect (outdated " +
        "or substituted) and leave the bridge blocked."
      );
    case "invalid_challenge":
      return "invalid_challenge: the host rejected our challenge frame (version mismatch?).";
    case "key_invalid":
      return (
        "key_invalid: the key under the enrollment label is not a single Secure Enclave key. " +
        "Run `chromium-bridge pair --reset` to delete it and mint a fresh one."
      );
    case "keychain_error":
      return "keychain_error: the host could not reach the keychain. Try again.";
    case "signing_failed":
      return (
        "signing_failed: no signature was produced (presence prompt declined or failed). " +
        `The ${mode} attempt did not complete; try again. If this repeats without any ` +
        "Touch ID prompt appearing, treat it as host substitution and re-pair."
      );
    default:
      return `unrecognized enclave_error reason from host: ${reason}`;
  }
}

// ---- user actions (routed from messages.ts) -------------------------------------

export function startPairing(): Promise<{ ok: boolean; error?: string }> {
  return serialized(async () => {
    if (!(await platformCanEnroll())) {
      return { ok: false, error: "Secure Enclave pairing is unavailable on this platform" };
    }
    if (await pinStore.getPin()) {
      return { ok: false, error: "a key is already pinned; revoke it first to re-pair" };
    }
    if (await pinStore.getCompromised()) {
      return {
        ok: false,
        error: "enrollment failed closed; revoke the pin first, then pair again",
      };
    }
    await pinStore.setPaused(false);
    await pinStore.clearPending();
    await pinStore.clearLastError();
    return issueChallenge("pair");
  });
}

export function verifyPinnedNow(): Promise<{ ok: boolean; error?: string }> {
  return serialized(async () => {
    if (!(await platformCanEnroll())) {
      return { ok: false, error: "Secure Enclave pairing is unavailable on this platform" };
    }
    if (!(await pinStore.getPin())) return { ok: false, error: "no pinned key to verify" };
    if (await pinStore.getCompromised()) {
      return { ok: false, error: "enrollment already failed closed; revoke and re-pair" };
    }
    return issueChallenge("verify");
  });
}

export function approvePending(): Promise<{ ok: boolean; error?: string }> {
  return serialized(async () => {
    const pending = await pinStore.getPending();
    if (!pending) return { ok: false, error: "no pairing awaiting approval" };
    // A pin or fail-closed mark that landed since this approval was clicked
    // (another tab, a revoke) wins; never overwrite it.
    if (await pinStore.getPin()) return { ok: false, error: "a key is already pinned" };
    if (await pinStore.getCompromised()) {
      return { ok: false, error: "enrollment failed closed; revoke and re-pair" };
    }
    await pinStore.setPin({
      keyId: pending.keyId,
      pubkeyB64: pending.pubkeyB64,
      pinnedAt: Date.now(),
    });
    await pinStore.clearPending();
    await pinStore.clearLastError();
    await updateBadge();
    console.log("[bb] enrollment pinned:", pending.keyId);
    return { ok: true };
  });
}

export function rejectPending(): Promise<{ ok: boolean; error?: string }> {
  return serialized(async () => {
    // A stale reject (the pending record is gone, e.g. already approved in
    // another tab) must not pretend it revoked anything.
    if (!(await pinStore.getPending())) return { ok: false, error: "no pairing awaiting approval" };
    await pinStore.clearPending();
    await pinStore.setPaused(true);
    await pinStore.setLastError(
      "fingerprint rejected; pairing halted. If the fingerprints really differed, " +
        "something other than your `chromium-bridge pair` key answered the challenge; " +
        "investigate before pairing again.",
    );
    await updateBadge();
    return { ok: true };
  });
}

/** Forget the pin and all ceremony records, and ask the host to delete its
 * enclave key too (ADR-0025: unpairing from either side leaves NO usable
 * credential behind - previously an extension-side revoke left the host's
 * keychain key alive). The deletion request is durable: if the port is down
 * it is stored and resent on every connect until the host acknowledges.
 * Pairing does not auto-restart afterwards (paused), so revoking never
 * triggers a surprise Touch ID prompt; the user starts the next ceremony
 * from the options page. */
export function revokePin(): Promise<{ ok: boolean }> {
  return serialized(async () => {
    clearOutstanding();
    await pinStore.clearAll();
    await pinStore.setPaused(true);
    // Only where an enclave key can exist: on other platforms there is no
    // host key to delete, and queueing the request would just resend a
    // frame the host answers with unsupported_platform forever.
    if (await platformCanEnroll()) {
      await pinStore.setHostRevokePending(true);
      await maybeSendPendingHostRevoke();
    }
    await updateBadge();
    console.log("[bb] enrollment pin revoked; host key deletion requested");
    return { ok: true };
  });
}

// ---- status for the popup/options UI ----------------------------------------------

export interface EnrollmentStatus {
  required: boolean;
  /** False on platforms without a Secure Enclave (non-mac): enrollment is
   * unavailable there and the gate never blocks, per the browser's own
   * platform probe (not the host's claim). */
  platformSupported: boolean;
  state: "unpaired" | "pending" | "pinned" | "compromised";
  /** Bridge requests are currently refused by the gate. */
  blocked: boolean;
  keyId?: string;
  fingerprint?: string; // 4-char grouped display of keyId
  pinnedAt?: number;
  lastVerifiedAt?: number;
  compromisedReason?: string;
  lastError?: string;
  paused?: boolean;
  /** ADR-0025: an unpair's host-key deletion has not been acknowledged yet
   * (it completes on the next host connection). */
  hostRevokePending?: boolean;
}

export async function getEnrollmentStatus(): Promise<EnrollmentStatus> {
  const required = (await getSetting("requireEnrollment")) === true;
  const platformSupported = await platformCanEnroll();
  const compromised = await pinStore.getCompromised();
  const pin = await pinStore.getPin();
  const pending = await pinStore.getPending();
  const lastError = await pinStore.getLastError();
  const base = {
    required,
    platformSupported,
    lastError: lastError ?? undefined,
    paused: await pinStore.getPaused(),
    hostRevokePending: (await pinStore.getHostRevokePending()) || undefined,
  };
  if (compromised) {
    return {
      ...base,
      state: "compromised",
      blocked: required,
      compromisedReason: compromised.reason,
      keyId: pin?.keyId,
      fingerprint: pin ? fingerprintDisplay(pin.keyId) : undefined,
    };
  }
  if (pin) {
    return {
      ...base,
      state: "pinned",
      blocked: false,
      keyId: pin.keyId,
      fingerprint: fingerprintDisplay(pin.keyId),
      pinnedAt: pin.pinnedAt,
      lastVerifiedAt: (await pinStore.getLastVerifiedAt()) ?? undefined,
    };
  }
  if (pending) {
    return {
      ...base,
      state: "pending",
      blocked: required && platformSupported,
      keyId: pending.keyId,
      fingerprint: fingerprintDisplay(pending.keyId),
    };
  }
  return { ...base, state: "unpaired", blocked: required && platformSupported };
}

// ---- badge ----------------------------------------------------------------------

// Only clear the badge when we set it, so a pending allowlist "!" badge is
// not stomped. (While enrollment blocks the bridge no allowlist prompt can
// arise, since nothing reaches dispatch.)
let badgeShown = false;

async function updateBadge(): Promise<void> {
  if (!browser.action) return;
  const st = await getEnrollmentStatus();
  try {
    if (st.blocked) {
      badgeShown = true;
      await browser.action.setBadgeText({ text: st.state === "pending" ? "PAIR" : "!" });
      await browser.action.setBadgeBackgroundColor({
        color: st.state === "pending" ? "#f59e0b" : "#d9534f",
      });
    } else if (badgeShown) {
      badgeShown = false;
      await browser.action.setBadgeText({ text: "" });
    }
  } catch (e) {
    console.warn("[bb] enrollment badge update failed", e);
  }
}
