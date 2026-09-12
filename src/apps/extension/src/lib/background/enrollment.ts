// The enrollment ceremony state machine, the extension half of ADR-0021. port.ts hands it the port (attachPort)
// and every enclave control frame, messages.ts routes the options/popup actions; this module never imports
// port.ts, so there is no cycle. State is derived from storage on every read: nothing survives an MV3
// service-worker restart in memory.
//
//   unpaired     no pin; traffic refused. Each connect issues a pairing challenge unless paused: one enclave_error
//                round trip on an unenrolled machine, the single ceremony Touch ID prompt once a key is minted
//   pending      a pairing proof verified; the fingerprint awaits approval in the options page. Still refused
//   pinned       traffic flows. Reconnects are NOT re-challenged (every host signature is a presence prompt and
//                MV3 respawns the host every few minutes); "Verify now" and the opt-in hostReverifyMs re-verify
//   compromised  a pinned-key verification failed; refused until the user revokes and re-pairs
//
// Enrollment is required wherever the platform can enroll (ADR-0032 retired requireEnrollment; a stored value is
// never consulted). Where the browser's own probe says no Secure Enclave, the gate does not block and no
// challenge is issued.

import {
  type EnclaveChallengeWire,
  EnclaveErrorFrameSchema,
  type EnclaveInboundFrame,
  EnclaveInboundFrameSchema,
  EnclaveProofFrameSchema,
  type EnclaveReasonCode,
  type EnclaveRevokeWire,
  isEnclaveReasonCode,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import type { EnrollmentStatus } from "../enrollment-status";
import { BADGE_DANGER_COLOR, BADGE_PENDING_COLOR } from "../shared/theme-colors";
import { auditEvent } from "./audit-log";
import { getEffectivePolicy } from "./effective-policy";
import * as pinStore from "./enclave-pin";
import {
  fingerprintDisplay,
  generateNonce,
  verifyPairingProof,
  verifyProofAgainstPin,
} from "./enclave-verify";
import { killGate } from "./kill";
import {
  currentConnectionToken,
  currentPinGeneration,
  notePinProvenOnConnection,
  onPinPinned,
  onPinRevoked,
  policyDispatchGate,
} from "./policy-sync";
import { hardenStorageAccess } from "./trusted-storage";

// ---- frame plumbing ---------------------------------------------------------

export type { EnclaveInboundFrame };

/** True for the five enclave control frame tags (ENCLAVE_FRAME_TYPES: the
 * ADR-0021 ceremony trio - challenge/proof/error - plus the ADR-0025
 * revoke/revoked pair). Bridge requests carry `op` and never a top-level
 * `type`, so nothing legitimate collides. */
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
  /** The policy-sync connection the challenge went out on: a verify success
   * is per-connection identity evidence (ADR-0032 decision 8 send-once), and
   * the token is what stops a proof verified after a reconnect from
   * crediting the NEW connection. */
  connection: object | null;
  /** The pin epoch at challenge-send time, stamped into the evidence with
   * the token: a re-pair during the challenge window (even same-key) moves
   * the epoch, and the stale proof then credits nothing. */
  generation: number;
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
  outstanding = {
    nonce,
    context,
    mode,
    timer,
    connection: currentConnectionToken(),
    generation: currentPinGeneration(),
  };
  if (!postFrame({ type: "enclave_challenge", nonce, context } satisfies EnclaveChallengeWire)) {
    clearOutstanding();
    return { ok: false, error: "failed to send the challenge to the native host" };
  }
  console.log(`[bb] enclave ${mode} challenge issued`);
  return { ok: true };
}

// ---- platform capability ------------------------------------------------------

/** Decided by the browser's own probe, never the host's unsupported_platform claim: the host is the party being
 * authenticated, and a substituted host on macOS could otherwise dodge enrollment by claiming "unsupported".
 * Off macOS enrollment is unavailable rather than unsatisfied (the bridge runs on the base transport
 * authentication); a Mac without a Secure Enclave stays blocked (REASON_HELP.unsupported_platform), and a failed
 * probe fails closed as capable. Shared with confirm/presence.ts (ADR-0031). */
export async function platformCanEnroll(): Promise<boolean> {
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

/** Consulted by port.ts before every dispatched bridge request; "blocked" means the request is answered
 * {ok:false, error: reason} and never reaches dispatch(). The state reads are individually async on the hot
 * path, so an "allowed" first pass is confirmed by a second read INSIDE the serialized transition queue, with
 * `onAllowed` (the dispatch kickoff) run synchronously in that same critical section. The queue orders, it does
 * not refuse: the verdict is whatever state the confirming read sees.
 *
 *   transition queued or in flight before the confirming read  -> fully applied first; the confirming read sees its result
 *   transition queued after it                                 -> runs after the op has begun dispatching */
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
  // Storage hardening FIRST, unconditionally (trusted-storage.ts): every check below reads trust state from
  // browser.storage, which must be confined to extension contexts before any of it is believed. If the restriction
  // is not verifiably applied this SW life, a content script could have written the very values about to be
  // trusted (planted a pin, cleared the compromised mark), so refuse.
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
  // The kill switch next (ADR-0030), before any enrollment reasoning: while
  // the mirror says killed (or unknown, or is malformed) every bridge request
  // is refused here, whatever the enrollment state. The mirror lives in the
  // storage the line above just confined, which is why the order matters.
  const kill = await killGate();
  if (!kill.allowed) return kill;
  // The policy dispatch barrier next (ADR-0032 decision 4). Post-cutover,
  // every bridge request is refused until a policy push has verified and
  // applied on the CURRENT host connection, whatever the enrollment state -
  // an op must not race ahead of the connect push and run under a cached
  // policy the host has since tightened. Pre-cutover (the flag, in the
  // storage confined above, was never set) the barrier is inert and the
  // legacy local settings govern.
  const policy = await policyDispatchGate();
  if (!policy.allowed) return policy;
  // Enrollment is unconditionally required where the platform can enroll
  // (ADR-0032: requireEnrollment is retired; a stored value - however it got
  // there - is never consulted, so a planted `false` cannot open this gate).
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
    // Do not read or act on trust state until it is confined to the extension (trusted-storage.ts): the same
    // reasoning as the gate. If hardening failed, do nothing - the gate is already blocking every request, so
    // there is no ceremony to drive.
    if (!(await hardenStorageAccess()).ok) return;
    // ADR-0025: an unpair that could not reach the host yet (port was down,
    // SW died) is retried on every connect until the host acknowledges the
    // key deletion. Independent of the gate/ceremony state below.
    await maybeSendPendingHostRevoke();
    await updateBadge();
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
 * durable flag is cleared by the host's `enclave_revoked` ack (a lost frame
 * or a dead SW just means another send here), or superseded when a fresh
 * pairing is PINNED (approvePending): `enclave_revoke` names no key, so past
 * a re-pair it would delete the newly minted key, not the one the revoke
 * meant. Merely starting a ceremony does not supersede it - an abandoned
 * ceremony must leave the deletion pending, or the old key would outlive the
 * revoke with nothing left to request its removal. */
async function maybeSendPendingHostRevoke(): Promise<void> {
  if (!postFrame) return;
  if (!(await pinStore.getHostRevokePending())) return;
  if (postFrame({ type: "enclave_revoke" } satisfies EnclaveRevokeWire)) {
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
  // A policy field (ADR-0032), read once: its own decision moment.
  const effective = await getEffectivePolicy();
  if (effective.state === "blocked") {
    // The connect path is NOT behind the dispatch barrier: resolving a blocked posture to the deny-baseline
    // defaults here would read hostReverifyMs 0 = never-re-verify and silently skip the user's opt-in check.
    // Skip LOUDLY instead; the barrier is refusing requests anyway.
    console.warn("[bb] periodic host re-verification skipped:", effective.reason);
    return;
  }
  const interval = effective.values.hostReverifyMs;
  if (interval <= 0) return;
  const lastVerified = Math.max(pin.pinnedAt, (await pinStore.getLastVerifiedAt()) ?? 0);
  if (Date.now() - lastVerified < interval) return;
  console.log("[bb] periodic host re-verification due");
  await issueChallenge("verify");
}

// ---- inbound control frames ----------------------------------------------------

// The reason vocabulary is the GENERATED EnclaveReasonCode union
// (enclave.gen.ts, from the host's reason_code in
// src/packages/core/src/enclave/mod.rs). Both tables below are Records over
// the full union, so a code added on the Rust side cannot compile here
// without an explicit latch classification AND help text.

type CeremonyMode = "pair" | "verify";

/** "compromise" answering a VERIFY challenge is evidence of host substitution, not a transient failure: a key is
 * pinned but the answering host cannot prove it (a revoked or replaced key, or a downgrade claim of no Enclave on
 * a machine that demonstrably enrolled one), so it latches the compromised mark. "transient" only surfaces as
 * lastError.
 *
 * Residual, named: a newer host adding a compromise-worthy code reaches the unknown-reason path below, which
 * does not latch. Host and extension ship in one archive, so the skew window is one un-updated install. */
const REASON_CLASS: Record<EnclaveReasonCode, "compromise" | "transient"> = {
  unsupported_platform: "compromise",
  not_enrolled: "compromise",
  invalid_challenge: "transient",
  key_invalid: "compromise",
  keychain_error: "transient",
  signing_failed: "transient",
};

const REASON_HELP: Record<EnclaveReasonCode, (mode: CeremonyMode) => string> = {
  not_enrolled: () =>
    "not_enrolled: no enrollment key exists on this machine. " +
    "Run `chromium-bridge pair` in a terminal, then return here.",
  unsupported_platform: () =>
    "unsupported_platform: the host reports no Secure Enclave, but this browser is " +
    "running on macOS. If this Mac genuinely lacks one (pre-T2 Intel), pairing is " +
    "impossible and the bridge stays blocked - enrollment is required on macOS " +
    "(ADR-0032) and this configuration is unsupported. Otherwise treat the host " +
    "binary as suspect (outdated or substituted) and leave the bridge blocked.",
  invalid_challenge: () =>
    "invalid_challenge: the host rejected our challenge frame (version mismatch?).",
  key_invalid: () =>
    "key_invalid: the key under the enrollment label is not a single Secure Enclave key. " +
    "Run `chromium-bridge pair --reset` to delete it and mint a fresh one.",
  keychain_error: () => "keychain_error: the host could not reach the keychain. Try again.",
  signing_failed: (mode) =>
    "signing_failed: no signature was produced (presence prompt declined or failed). " +
    `The ${mode} attempt did not complete; try again. If this repeats without any ` +
    "Touch ID prompt appearing, treat it as host substitution and re-pair.",
};

/** Help text for a reason outside the generated union (or a frame that
 * failed the wire schema, raw = null). The raw value is attacker-influenced,
 * so it is BOUNDED and JSON-escaped before it can reach the options UI. */
function unknownReasonHelp(raw: string | null): string {
  const display = raw === null ? "a malformed frame" : JSON.stringify(raw.slice(0, 64));
  return `unknown_error: the host sent an unrecognized enclave_error reason (${display}). Update the extension and the host to matching versions.`;
}

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
    // A fresh-nonce proof of the PINNED key just verified: per-connection identity evidence for the
    // legacy-settings send-once (ADR-0032 decision 8). The token pins it to the connection the challenge went
    // out on, the generation to the pin epoch at challenge time; if either has moved, this credits nobody.
    notePinProvenOnConnection(current.connection, pin.keyId, current.generation);
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
  // Parse with the wire schema the envelope-parity gate declares for
  // enclave_error (`reason` is required). A frame that fails it (raw = null)
  // degrades exactly like a reason code outside the generated union
  // (reason = null), keeping the fail direction unchanged: an error frame
  // only clears the outstanding challenge, it never grants anything.
  const parsed = EnclaveErrorFrameSchema.safeParse(frame);
  const raw = parsed.success ? parsed.data.reason : null;
  const reason: EnclaveReasonCode | null = raw !== null && isEnclaveReasonCode(raw) ? raw : null;
  if (!current) {
    console.warn("[bb] dropping unsolicited enclave_error:", reason ?? "unknown_error");
    return;
  }
  if (current.mode === "verify" && reason && REASON_CLASS[reason] === "compromise") {
    // A key is pinned but the answering host can no longer prove it
    // (REASON_CLASS above). Fail closed.
    await pinStore.setCompromised({
      reason: `host cannot prove the pinned key (${reason})`,
      at: Date.now(),
    });
  } else {
    await pinStore.setLastError(
      reason ? REASON_HELP[reason](current.mode) : unknownReasonHelp(raw),
    );
  }
  await updateBadge();
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
    // The pin IS the fresh pairing: a deletion request still pending from
    // before it is stale, and resending it would revoke the key just pinned.
    await pinStore.setHostRevokePending(false);
    // A (re-)pin decides the policy ratchet scope (ADR-0032 decision 3): onPinPinned resets the ratchet for a
    // DIFFERENT key but RETAINS it for a same-key re-pair (so an old permissive baseline cannot replay), drops
    // this connection's verified mark, and keeps the cutover flag.
    await onPinPinned(pending.keyId);
    await updateBadge();
    console.log("[bb] enrollment pinned:", pending.keyId);
    auditEvent("enroll_approved", { name: fingerprintDisplay(pending.keyId) });
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
    auditEvent("enroll_rejected", {});
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
    // Read the pin BEFORE clearing the store: its keyId is the prior identity
    // onPinRevoked persists durably, and the next re-pair decides key-novelty
    // against it (ADR-0032 decision 3). Read after clearAll it would always be
    // null, and every re-pair would read as "prior unknown" - which is
    // fail-closed but strands the revoke-and-re-pair recovery the latched-state
    // messages promise. `null` here means nothing was pinned.
    const revokedKeyId = (await pinStore.getPin())?.keyId ?? null;
    // Hand the identity over BEFORE clearAll, so no SW death can land in a gap where both copies are gone.
    // Revoke RETAINS the policy ratchet record (ADR-0032 decision 3): a same-key re-pair must still refuse an
    // old-baseline replay, and the record stays inert (deny baseline + closed barrier) while unpinned. The
    // cutover flag survives too: post-reset means the deny baseline plus the barrier, never legacy policy.
    await onPinRevoked(revokedKeyId);
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
    auditEvent("enroll_revoked", {});
    return { ok: true };
  });
}

// ---- status for the popup/options UI ----------------------------------------------

/** The SHARED status union (lib/enrollment-status.ts): one definition for
 * this producer and the popup/options consumers, discriminated on `state`
 * with the keyId/fingerprint coupling structural. Re-exported here so the
 * background world keeps its historical import path. */
export type { EnrollmentStatus };

export async function getEnrollmentStatus(): Promise<EnrollmentStatus> {
  const platformSupported = await platformCanEnroll();
  const compromised = await pinStore.getCompromised();
  const pin = await pinStore.getPin();
  const pending = await pinStore.getPending();
  const lastError = await pinStore.getLastError();
  const base = {
    platformSupported,
    lastError: lastError ?? undefined,
    paused: await pinStore.getPaused(),
    hostRevokePending: (await pinStore.getHostRevokePending()) || undefined,
  };
  if (compromised) {
    const common = {
      ...base,
      state: "compromised" as const,
      blocked: true as const,
      compromisedReason: compromised.reason,
    };
    // The pin the failure was measured against, when one survives: keyId and
    // fingerprint travel together or not at all (the structural coupling).
    return pin
      ? { ...common, keyId: pin.keyId, fingerprint: fingerprintDisplay(pin.keyId) }
      : common;
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
      blocked: platformSupported,
      keyId: pending.keyId,
      fingerprint: fingerprintDisplay(pending.keyId),
    };
  }
  return { ...base, state: "unpaired", blocked: platformSupported };
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
        color: st.state === "pending" ? BADGE_PENDING_COLOR : BADGE_DANGER_COLOR,
      });
    } else if (badgeShown) {
      badgeShown = false;
      await browser.action.setBadgeText({ text: "" });
    }
  } catch (e) {
    console.warn("[bb] enrollment badge update failed", e);
  }
}
