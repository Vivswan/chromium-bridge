// The Enclave user-presence confirmation provider: the approval mechanism
// behind the "eval" and "upload" confirmation kinds on a capable, enrolled
// device. The window surface stays - it SHOWS what is being approved - but
// approval itself is the host-side Secure Enclave signature, whose
// user-presence ACL raises the Touch ID prompt. What makes this unforgeable end
// to end:
//
// - the approval the service accepts is a P-256 signature over
//   PRESENCE_DOMAIN || 0x00 || nonce || 0x00 || context, verified against
//   the PINNED host key - a substituted host binary cannot produce it;
// - the nonce is fresh CSPRNG, single-use, held only in SW memory - a
//   captured proof cannot be replayed;
// - the context binds the digest of exactly this confirmation's
//   kind/origin/detail - a proof for one eval cannot approve another;
// - the payload is marked `hardware`, and the service refuses a window-side
//   approval for it - no page or UI path can substitute for the tap.
//
// Fail closed, never downgrade: a presence_error, a bad signature, a missing
// pin, a detached port, or a timeout all DENY the confirmation. The provider
// never falls back to the window's Allow button - provider selection
// happened up front (setting + capability), and a refused hardware check
// must not demote the gate (the same rule as src/packages/core/src/presence
// on the host side). A signature that fails verification additionally marks
// the bridge compromised: only a substituted host or a corrupted channel can
// produce one.

import type { ConfirmPayload } from "@chromium-bridge/shared/confirm";
import {
  type PresenceInboundFrame,
  PresenceInboundFrameSchema,
} from "@chromium-bridge/shared/enclave";
import {
  type PresenceChallengeWire,
  PresenceErrorFrameSchema,
  PresenceProofFrameSchema,
} from "@chromium-bridge/shared/envelope.gen";
import type { PolicyValues } from "@chromium-bridge/shared/policy.gen";
import { browser } from "wxt/browser";
import type { Connection, PortCollaborator } from "../connection";
import { getCompromised, getPin, setCompromised } from "../enclave-pin";
import { generateNonce, hexEncode, verifyPresenceProofAgainstPin } from "../enclave-verify";
import { platformCanEnroll } from "../enrollment";
import type { ConfirmationProvider, Presentation } from "./service";

/** The live connection, or null while the link is down; compared by identity per Connection in ../connection.ts. */
let conn: Connection | null = null;

/** One outstanding presence round. Single-flight by construction: the slot
 * is claimed SYNCHRONOUSLY (before any await), so a second same-tick round
 * finds it occupied and is refused rather than overwriting the first -
 * which would orphan its settle and risk a false compromise mark. The
 * stages carry exactly the data that exists at each point: a round that has
 * not sent its challenge yet has no context to verify against. */
type PendingRound =
  | {
      stage: "preparing";
      nonce: string;
      /** The connection this round will send on (identity-checked later). */
      conn: Connection;
      settle: (approved: boolean) => void;
    }
  | {
      stage: "challenged";
      nonce: string;
      context: string;
      /** The connection the challenge went out on. If the live connection is
       * no longer this exact object at verdict time, the port dropped (or was
       * replaced) and the round fails closed. */
      conn: Connection;
      settle: (approved: boolean) => void;
    };
let pending: PendingRound | null = null;

export const collaborator: PortCollaborator = {
  onAttach(c) {
    conn = c;
  },
  /** Port gone: the outstanding round can never complete - deny it. */
  onDetach() {
    conn = null;
    cancelPending("native port disconnected");
  },
  onFrame(msg) {
    if (!isPresenceFrame(msg)) return false;
    handlePresenceFrame(msg);
    return true;
  },
};

function cancelPending(why: string): void {
  const round = pending;
  pending = null;
  if (round) {
    console.warn("[bb] presence round cancelled:", why);
    round.settle(false);
  }
}

/** Classification for the port demux: is this frame a presence answer? */
export function isPresenceFrame(msg: unknown): msg is PresenceInboundFrame {
  return PresenceInboundFrameSchema.safeParse(msg).success;
}

/** Route one inbound presence frame to the outstanding round. A frame with
 * no round outstanding is dropped (a late answer to a cancelled round, or a
 * confused host); the nonce it would have answered is already burned. */
export function handlePresenceFrame(msg: unknown): void {
  const round = pending;
  if (!round) {
    console.warn("[bb] dropping presence frame with no round outstanding");
    return;
  }
  // Claim the round before any await: exactly one answer per round.
  pending = null;
  if (round.stage === "preparing") {
    // An answer arrived before this round's challenge was even sent: nothing
    // can validly answer it, so deny. The setup still in flight notices its
    // claim is gone and aborts without sending.
    console.warn("[bb] presence frame preceded the challenge; denying");
    round.settle(false);
    return;
  }

  const proof = PresenceProofFrameSchema.safeParse(msg);
  if (!proof.success) {
    const err = PresenceErrorFrameSchema.safeParse(msg);
    console.warn(
      "[bb] presence round refused by the host:",
      err.success ? (err.data.reason ?? "unknown") : "unparsable frame",
    );
    round.settle(false);
    return;
  }
  void (async () => {
    const pin = await getPin();
    if (!pin) {
      round.settle(false);
      return;
    }
    const verdict = await verifyPresenceProofAgainstPin(
      { sig: proof.data.sig, key_id: proof.data.key_id, pubkey: proof.data.pubkey },
      round.nonce,
      round.context,
      pin.pubkeyB64,
      pin.keyId,
    );
    if (!verdict.ok) {
      // A presence proof that fails against the pin is not a user "no" - it
      // is evidence the signer is not the pinned host. Deny AND fail the
      // bridge closed until the user re-pairs (same posture as a failed
      // pinned-key verification in the enrollment machine).
      console.error("[bb] presence proof failed verification:", verdict.reason);
      await setCompromised({
        reason: `presence proof failed verification: ${verdict.reason}`,
        at: Date.now(),
      }).catch((e) => console.error("[bb] could not persist compromised mark", e));
      round.settle(false);
      return;
    }
    // Fail closed on a mid-verification disconnect OR reconnect: the pin
    // lookup and the crypto above are async, and the port can drop (or drop
    // and be replaced by a fresh one) while they run. onDetach cancels the
    // OUTSTANDING round, but this round was already claimed off `pending`, so
    // the cancel could not reach it. The connection identity is what closes
    // both holes: if the live connection is no longer the exact object this
    // challenge was sent on, the op can no longer proceed on it, so a
    // stale-but-valid approval must not stand.
    if (conn !== round.conn) {
      console.warn("[bb] native port changed before the presence verdict; denying");
      round.settle(false);
      return;
    }
    round.settle(true);
  })().catch((e) => {
    console.error("[bb] presence verification errored; denying", e);
    round.settle(false);
  });
}

/** The context string a presence signature binds: the digest of exactly this
 * confirmation's kind/origin/detail, under this extension's id. NUL-free and
 * far under the host's MAX_CONTEXT_BYTES bound by construction. */
async function presenceContext(payload: ConfirmPayload): Promise<string> {
  const utf8 = new TextEncoder();
  // Length-prefixed fields make the encoding injective before hashing.
  const material = [payload.kind, payload.origin, payload.detail]
    .map((f) => `${utf8.encode(f).length}:${f}`)
    .join("\n");
  const digest = await crypto.subtle.digest("SHA-256", utf8.encode(material));
  return `ext:${browser.runtime.id}:presence:${payload.kind}:${hexEncode(new Uint8Array(digest))}`;
}

/** Whether this device can hardware-gate confirmations right now: macOS (the
 * browser's own probe, never the host's claim), a pinned host key, and no
 * compromise mark. The setting is checked separately (presenceRoutingEnabled). */
export async function presenceCapable(): Promise<boolean> {
  if (!(await platformCanEnroll())) return false;
  if (await getCompromised()) return false;
  return (await getPin()) !== null;
}

/** The routing verdict for the "eval"/"upload" kinds: the policy field (default
 * ON) AND device capability. Computed at DECISION time from the caller's
 * per-request policy snapshot and carried in the ConfirmRequest: presentation
 * never re-reads live policy, so a push landing while the confirmation waits in
 * the queue cannot re-route it. Opting out falls back to the off-DOM window
 * confirmation - still confirmed, not hardware-gated. */
export async function presenceRoutingEnabled(policy: PolicyValues): Promise<boolean> {
  if (policy.touchIdConfirm === false) return false;
  // A THROWN probe fails the op closed (the throw propagates and the caller
  // refuses): the legacy window-fallback is deliberately NOT restored here,
  // because demoting a hardware-required approval to an ordinary window on an
  // anomalous storage error would downgrade the Touch ID gate, and a hardware
  // gate never falls through to a weaker one. A compromised or absent pin
  // returns false cleanly without throwing, so the normal window routing is
  // unaffected.
  return presenceCapable();
}

/** Run one hardware round: send the challenge, await the verified answer.
 * Every failure path resolves false (deny); nothing here ever "falls back".
 * The slot is claimed BEFORE any await (nonce generation is synchronous):
 * two same-tick rounds used to both pass the guard, and the second's claim
 * would overwrite the first - orphaning its settle and letting its answer
 * verify against the wrong nonce. */
function runRound(payload: ConfirmPayload): Promise<boolean> {
  if (pending) {
    // A second concurrent round should be impossible (the service
    // serializes); refuse it rather than corrupt the outstanding one.
    console.warn("[bb] refusing concurrent presence round");
    return Promise.resolve(false);
  }
  const live = conn;
  if (!live) return Promise.resolve(false);
  return new Promise<boolean>((resolve) => {
    const claim: PendingRound = {
      stage: "preparing",
      nonce: generateNonce(),
      conn: live,
      settle: resolve,
    };
    pending = claim;
    // The round object THIS setup currently owns - advanced at the
    // preparing -> challenged transition, so the catch below can tell "my
    // round is still outstanding" from "the slot now holds someone ELSE's
    // round" (this setup rejecting late must never cancel a successor).
    let mine: PendingRound = claim;
    void (async () => {
      if (!(await presenceCapable())) {
        if (pending === mine) pending = null;
        resolve(false);
        return;
      }
      const context = await presenceContext(payload);
      // The awaits above are a window where the claim can be settled out
      // from under us (a detach, a premature frame): only its owner may
      // advance it, and a settled claim must not send a challenge.
      if (pending !== mine) return;
      // Defense in depth beside the verdict-time identity check: if the
      // connection this round was minted on is no longer the live one, the
      // challenge would go out on a stale connection - cancel the round instead.
      if (conn !== live) {
        cancelPending("native port changed before the challenge was sent");
        return;
      }
      mine = {
        stage: "challenged",
        nonce: claim.nonce,
        context,
        conn: live,
        settle: resolve,
      };
      pending = mine;
      if (
        !live.post({
          type: "presence_challenge",
          nonce: claim.nonce,
          context,
        } satisfies PresenceChallengeWire)
      ) {
        cancelPending("challenge send failed");
      }
    })().catch((e) => {
      // Cancel ONLY the round this setup still owns (preparing or
      // challenged). If a teardown already settled it and a new round has
      // since claimed the slot, a stale rejection landing here must leave
      // that successor untouched; the resolve backstop is idempotent.
      console.error("[bb] presence round setup failed; denying", e);
      if (pending === mine) cancelPending("presence round setup failed");
      resolve(false);
    });
  });
}

/** The provider the service routes "eval"/"upload" to when presence routing
 * is enabled. Composes the window provider for display: the window shows
 * WHAT is being approved (and offers Deny - removing capability stays
 * friction-free), while the verdict comes from the hardware round. */
export class EnclavePresenceProvider implements ConfirmationProvider {
  constructor(private display: ConfirmationProvider) {}

  present(payload: ConfirmPayload): Presentation {
    const window = this.display.present(payload);
    let settled = false;
    const verdict = new Promise<boolean>((resolve) => {
      const settle = (approved: boolean) => {
        if (settled) return;
        settled = true;
        resolve(approved);
      };
      // The display window only ever reports denials (closed / failed to
      // open); a rejection is a denial too.
      window.verdict.then(
        () => settle(false),
        () => settle(false),
      );
      runRound(payload).then(settle, () => settle(false));
    });
    return {
      verdict,
      dismiss: () => {
        // Deadline hit or the service settled: burn the outstanding nonce so
        // a late proof cannot approve anything, then drop the window.
        cancelPending("confirmation dismissed");
        window.dismiss();
      },
    };
  }
}

/** Tests only: forget the connection and any outstanding round. */
export function resetPresenceForTests(): void {
  conn = null;
  pending = null;
}
