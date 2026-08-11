// The enrollment status shape, shared by its producer (the service worker's
// getEnrollmentStatus in lib/background/enrollment.ts) and its consumers
// (the popup and options views, via the get_enrollment runtime message).
// ONE definition on purpose: this file replaces the hand-written UI mirror
// that used to live in lib/messages.ts, which could drift from the
// background's type without any compiler noticing. Type-only and
// dependency-free, so both worlds can import it.

/** The fields every state carries. Enrollment is unconditionally required
 * (ADR-0032 retired the requireEnrollment setting), so `blocked` is decided
 * by the state and the platform alone. */
interface EnrollmentStatusBase {
  /** False on platforms without a Secure Enclave (non-mac): enrollment is
   * unavailable there and the gate never blocks, per the browser's own
   * platform probe (not the host's claim). */
  platformSupported: boolean;
  /** Bridge requests are currently refused by the gate. Structurally pinned
   * where the state alone decides it: `pinned` is never blocked and
   * `compromised` always is; the unpaired/pending arms carry the
   * platform-dependent verdict. */
  blocked: boolean;
  lastError?: string;
  paused?: boolean;
  /** ADR-0025: an unpair's host-key deletion has not been acknowledged yet
   * (it completes on the next host connection). */
  hostRevokePending?: boolean;
}

/** Discriminated on `state`, so which fields are present is determined by
 * the state instead of eight independent optionals: a pending or pinned
 * status always carries its key identity, a compromised one always carries
 * its reason, and `{ state: "compromised" }` with no reason cannot be built.
 * The keyId/fingerprint pair is structural everywhere it appears - the
 * compromised arm either names BOTH (the pin the failure was measured
 * against) or neither, never a keyId without its display fingerprint. */
export type EnrollmentStatus = EnrollmentStatusBase &
  (
    | { state: "unpaired" }
    | { state: "pending"; keyId: string; fingerprint: string }
    | {
        state: "pinned";
        blocked: false;
        keyId: string;
        fingerprint: string;
        pinnedAt: number;
        lastVerifiedAt?: number;
      }
    | ({ state: "compromised"; blocked: true; compromisedReason: string } & (
        | { keyId: string; fingerprint: string }
        | { keyId?: undefined; fingerprint?: undefined }
      ))
  );
