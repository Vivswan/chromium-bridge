// The extension-side audit ring (ADR-0030): a bounded, display-only record of
// the extension's own user-facing security decisions - confirmations shown /
// allowed / denied, enrollment approvals, revocations and kill toggles issued
// from the options page - kept in the #32 trusted storage for the read-only
// options panel, and forwarded (best-effort) to the native host so the
// decisions land in the host's durable 0600 audit file too.
//
// Strictly observational, never load-bearing: recording happens AFTER the
// decision it describes, every failure is swallowed (a full ring or a dead
// port must never fail an op, and certainly never fail it OPEN), and reads
// drop malformed entries instead of guessing. Appends are serialized through
// a promise chain because SW event handlers interleave at awaits and a lost
// entry would silently thin the trail.
//
// The host accepts only the extension-owned kinds over the audit_event frame
// (confirm_*/enroll_*) and stamps `surface: extension` itself, so nothing this
// module sends can forge a host-side event; the local-only kinds (kill/client
// toggles, which the host audits authoritatively when it HANDLES them) stay
// in the ring for the panel and are not forwarded.

import { type AuditEntry, AuditEntrySchema, type AuditEventKind } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

const AUDIT_RING_KEY = "auditRing";

/** Ring capacity. At ~150 bytes an entry this bounds the ring to ~30 KB of
 * storage; older entries fall off (the host file is the durable trail). */
const AUDIT_RING_MAX = 200;

/** The kinds forwarded to the host's on-disk trail. Must match the host's
 * `audit::extension_kind` whitelist; anything else is local-display only. */
const FORWARDED_KINDS: ReadonlySet<AuditEventKind> = new Set([
  "confirm_shown",
  "confirm_allowed",
  "confirm_denied",
  "enroll_approved",
  "enroll_rejected",
  "enroll_revoked",
]);

// The port sender, registered by port.ts while a port is up (same shape as
// clients.ts / kill.ts).
let postFrame: ((frame: object) => boolean) | null = null;

export function attachPort(post: (frame: object) => boolean): void {
  postFrame = post;
}

export function detachPort(): void {
  postFrame = null;
}

// Serialize appends: concurrent read-modify-write of the ring would lose
// entries.
let appendChain: Promise<unknown> = Promise.resolve();

export interface AuditFields {
  outcome?: string;
  tool?: string;
  name?: string;
  detail?: string;
}

/** Record one event. Never throws, never blocks the caller. `forward: false`
 * keeps an event out of the host file (used for events the host already
 * records authoritatively itself). */
export function auditEvent(
  kind: AuditEventKind,
  fields: AuditFields = {},
  opts: { forward?: boolean } = {},
): void {
  // Validate at write time with the same schema reads use, so an oversized
  // or malformed field is dropped HERE (loudly) instead of being stored and
  // silently discarded by the strict read later.
  const parsed = AuditEntrySchema.safeParse({ at: Date.now(), kind, ...fields });
  if (!parsed.success) {
    console.warn("[bb] audit event dropped (invalid fields)", kind, parsed.error);
    return;
  }
  const entry: AuditEntry = parsed.data;
  appendChain = appendChain
    .then(async () => {
      const ring = await readRing();
      ring.push(entry);
      await browser.storage.local.set({ [AUDIT_RING_KEY]: ring.slice(-AUDIT_RING_MAX) });
    })
    .catch((e) => {
      // Drop-on-failure, loudly: the decision already happened and must not
      // be re-litigated because its bookkeeping failed.
      console.warn("[bb] audit ring append failed; event dropped from the ring", e);
    });
  if (opts.forward !== false && FORWARDED_KINDS.has(kind)) {
    try {
      // Best-effort: with the port down the host file misses this event (the
      // ring still has it) - a named residual, not silently widened by
      // queueing unbounded frames.
      postFrame?.({ type: "audit_event", kind, ...fields });
    } catch (e) {
      console.warn("[bb] audit event forward failed", e);
    }
  }
}

/** The ring, newest last. Malformed entries are dropped (display-only data;
 * dropping is the fail-closed direction for a read). */
export async function readRing(): Promise<AuditEntry[]> {
  const { [AUDIT_RING_KEY]: value } = await browser.storage.local.get(AUDIT_RING_KEY);
  if (!Array.isArray(value)) return [];
  return value.flatMap((raw) => {
    const parsed = AuditEntrySchema.safeParse(raw);
    return parsed.success ? [parsed.data] : [];
  });
}

/** The storage key the options panel watches for event-driven refreshes. */
export const AUDIT_RING_STORAGE_KEY = AUDIT_RING_KEY;

/** Tests only. */
export function resetAuditForTests(): void {
  postFrame = null;
  appendChain = Promise.resolve();
}
