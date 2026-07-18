// The Enclave user-presence confirmation provider (ADR-0031): the approval
// mechanism behind the "eval" and "upload" confirmation kinds on a capable,
// enrolled device. The window surface stays - it SHOWS what is being
// approved - but approval itself is the host-side Secure Enclave signature,
// whose user-presence ACL raises the Touch ID prompt. What makes this
// unforgeable end to end:
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

import type { ConfirmPayload } from "@chromium-bridge/shared";
import {
  PresenceErrorFrameSchema,
  PresenceInboundFrameSchema,
  PresenceProofFrameSchema,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { getSetting } from "../../shared/settings";
import { getCompromised, getPin, setCompromised } from "../enclave-pin";
import { generateNonce, hexEncode, verifyPresenceProofAgainstPin } from "../enclave-verify";
import { platformCanEnroll } from "../enrollment";
import type { ConfirmationProvider, Presentation } from "./service";

type PostFrame = (frame: object) => boolean;
let post: PostFrame | null = null;
// Monotonic port-connection generation. Bumped on every attach AND detach, so
// a round can tell whether the exact port it sent its challenge on is still
// the live one at verdict time - a plain `post !== null` check would miss a
// disconnect+reconnect that installs a NEW port before verification finishes.
let portGeneration = 0;

/** One outstanding presence round. Single-flight by construction: the
 * confirmation service shows one surface at a time, and the host refuses a
 * concurrent round with `busy` anyway. */
interface PendingRound {
  nonce: string;
  context: string;
  /** The port generation the challenge was sent on. If it no longer matches
   * `portGeneration` at verdict time, the port dropped (or was replaced) and
   * the round fails closed. */
  generation: number;
  settle: (approved: boolean) => void;
}
let pending: PendingRound | null = null;

export function attachPort(p: PostFrame): void {
  post = p;
  portGeneration += 1;
}

/** Port gone: the outstanding round can never complete - deny it. */
export function detachPort(): void {
  post = null;
  portGeneration += 1;
  cancelPending("native port disconnected");
}

function cancelPending(why: string): void {
  const round = pending;
  pending = null;
  if (round) {
    console.warn("[bb] presence round cancelled:", why);
    round.settle(false);
  }
}

/** Classification for the port demux: is this frame a presence answer? */
export function isPresenceFrame(msg: unknown): boolean {
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
    // and be replaced by a fresh one) while they run. detachPort cancels the
    // OUTSTANDING round, but this round was already claimed off `pending`, so
    // the cancel could not reach it. The generation token is what closes both
    // holes: if the live port is no longer the exact one this challenge was
    // sent on, the op can no longer proceed on it, so a stale-but-valid
    // approval must not stand.
    if (portGeneration !== round.generation) {
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
 * far under the host's 4096-byte context bound by construction. */
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

/** The service's routing predicate for the "eval"/"upload" kinds: the user
 * setting (default ON) AND device capability. Opting out falls back to the
 * off-DOM window confirmation - still confirmed, not hardware-gated. */
export async function presenceRoutingEnabled(): Promise<boolean> {
  if ((await getSetting("touchIdConfirm")) === false) return false;
  return presenceCapable();
}

/** Run one hardware round: send the challenge, await the verified answer.
 * Every failure path resolves false (deny); nothing here ever "falls back". */
function runRound(payload: ConfirmPayload): Promise<boolean> {
  if (pending) {
    // A second concurrent round should be impossible (the service
    // serializes); refuse it rather than corrupt the outstanding one.
    console.warn("[bb] refusing concurrent presence round");
    return Promise.resolve(false);
  }
  if (!post) return Promise.resolve(false);
  return new Promise<boolean>((resolve) => {
    void (async () => {
      if (!(await presenceCapable())) {
        resolve(false);
        return;
      }
      const nonce = generateNonce();
      const context = await presenceContext(payload);
      // Record the generation of the port we are about to send on, so the
      // verdict can reject an answer if the port dropped or was replaced
      // while the host was signing.
      const generation = portGeneration;
      pending = { nonce, context, generation, settle: resolve };
      if (!post?.({ type: "presence_challenge", nonce, context })) {
        cancelPending("challenge send failed");
      }
    })().catch((e) => {
      console.error("[bb] presence round setup failed; denying", e);
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

/** Tests only: forget the port and any outstanding round. */
export function resetPresenceForTests(): void {
  post = null;
  pending = null;
}
