// The extension side of host-owned policy (ADR-0032): `policy_current` pushes are verified against the extension's
// OWN pinned key, ratcheted, stored as the effective policy behind a one-way cutover flag, and gate each connection
// through the dispatch barrier enrollment.ts consults. `lang_current` rides the separate language lane below.
//
// A refusal changes nothing stored: the stored effective stays enforced. Pre-cutover the barrier is inert (the legacy
// settings govern); post-cutover a connection stays behind it until it has verified a push, and a later refused push
// leaves that verified mark in place. Only a signature failure drops the mark and latches the SW life (markPolicyCompromised).
// A push is consumed only in this order, and the frames carry no key identity the extension honors:
//   strict frame parse -> signature over the EXACT decoded bytes against the PINNED key -> strict PolicyDocSchema parse of those bytes
//
//   pinned, revision <= stored, bytes differ        -> refused (byte-identical is the idempotent push-on-connect replay)
//   pinned, relaxes the STORED effective            -> refused unless revision is strictly higher AND signed `touched` names each field
//   unpinned                                        -> revision neither enforced nor stored (0); see the ratchet gate in handlePolicyCurrent
//   unsigned record over a retained pinned record   -> writeStoredRecord throws: that record is the same-key re-pair's anti-replay anchor
//   overlay relaxing the baseline on one field      -> the WHOLE push refused
//   signature fails against the pin                 -> bridge marked compromised, barrier closed on that connection (the presence.ts posture)
//   unsigned baseline on a pinned extension         -> refused on every platform; the unpinned approval window exists only via the approver seam
//
// Every ratchet state is bound to a PolicyScope (the pinned keyId, or the unpinned lane): a record or verified mark whose
// scope no longer matches the current pin is inert, so a push that raced a re-pair, or an old baseline replayed after a
// same-key revoke+re-pair, cannot be enforced. resolvePolicyState folds the persisted facts into one PolicyState arm.
//
// port.ts hands this module the port (attachPort) and routes policy/lang frames BEFORE the request parse and the kill
// and enrollment gates, so a killed bridge still consumes pushes; frames process strictly in arrival order. This module
// sends only `legacy_settings` and `lang_set`, each only on a connection whose host already pushed the matching frame.

import {
  foldPolicyOverlay,
  KEY_ID_HEX,
  LangCurrentFrameSchema,
  type LangSetWire,
  type LegacySettingsWire,
  PolicyCurrentFrameSchema,
  PolicyDocSchema,
  PolicyInboundFrameSchema,
  type PolicyValues,
  parseStoredPolicyValues,
  policyValuesEqual,
  policyValuesFromDoc,
  relaxedPolicyFields,
  type StoredPolicyState,
  StoredPolicyStateSchema,
  UI_LANGUAGES,
  type UiLanguageValue,
  unreachable,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { auditEvent } from "./audit-log";
import { getCompromised, getPin, setCompromised } from "./enclave-pin";
import { base64Decode, verifyPolicySignatureAgainstPin } from "./enclave-verify";
import {
  getLegacySettingsSent,
  markLegacySettingsSent,
  readLegacySettingsBag,
} from "./legacy-import";
import { hardenStorageAccess } from "./trusted-storage";

const POLICY_STATE_KEY = "bridgePolicyState";
/** Exported only for legacy-cleanup.ts, which reads the flag itself and never writes it; every cutover decision stays here. */
export const POLICY_CUTOVER_KEY = "bridgePolicyCutover";

/** The storage keys the persisted policy state lives under, for
 * storage.onChanged consumers that must react on the policy PUSH path (the
 * accepted push writes these keys): cdp/registry.ts re-evaluates the
 * effective cdpMode and tears down live sessions when it turned off. */
export const POLICY_STORAGE_KEYS = [POLICY_CUTOVER_KEY, POLICY_STATE_KEY] as const;
const POLICY_PRIOR_PIN_KEY = "bridgePolicyPriorPin";

// ---- in-life latches (SW-lifetime, in memory only) ----------------------------
//
// The four module-level values below hold facts a persisted read cannot: they
// survive across the awaits WITHIN one service-worker life but reset to their
// initial value on SW death (when the durable setCompromised mark, the durable
// prior-pin identity, and the stored ratchet re-derive the posture). Each is the
// structural answer to a race the persisted state alone cannot see.

/** Set SYNCHRONOUSLY by markPolicyCompromised before any await, so a failed setCompromised persist cannot leave a barrier
 * that a replayed byte-identical genuine frame (verifies, ratchets as an idempotent replay) would reopen. Cleared within a
 * life only by onPinPinned's new-key path; a valid push, a cutover change, or a same-key or unknown-prior re-pair keeps it. */
let compromisedThisLife = false;

/** Bumped synchronously by onPinRevoked and onPinPinned BEFORE their awaits, so an in-flight push detects a pin move even
 * when the keyId comes back equal (a same-key revoke+re-pair); a fresh SW starts at 0 and re-verifies from scratch.
 * The commit-end undo relies on onPinPinned's order below: a push that saw no pinGeneration move cannot have missed a reset.
 *   pinGeneration += 1 -> ratchetResetGeneration += 1 -> storage.remove(POLICY_STATE_KEY) */
let pinGeneration = 0;

/** The same-life mirror of the prior pin identity: the keyId the last
 * onPinPinned bound, or the last onPinRevoked revoked. A fast path only - the
 * DURABLE prior (POLICY_PRIOR_PIN_KEY, written on the revoke path) is what
 * survives an SW restart and is consulted FIRST. onPinPinned owns the novelty
 * rules; they are stated once, there. */
let lastPinnedKeyId: string | null = null;

/** Bumped only by onPinPinned's new-key reset, the branch that removes the stored record. The commit-end undo compares it:
 * after a reset ran mid-push, restoring the pre-write record would resurrect the anchor the reset deleted, so it removes
 * instead. Bump order relative to pinGeneration is documented there. */
let ratchetResetGeneration = 0;

// ---- the ratchet scope --------------------------------------------------------

/** The identity a ratchet state is bound to (ADR-0032 decision 3). Two states share a ratchet only when their scopes are
 * EQUAL: a different pinned key, or the pinned<->unpinned boundary, is a fresh scope that never inherits the old anchor. */
export type PolicyScope = { pinned: true; keyId: string } | { pinned: false };

function scopesEqual(a: PolicyScope, b: PolicyScope): boolean {
  return a.pinned && b.pinned ? a.keyId === b.keyId : a.pinned === b.pinned;
}

function scopeToStored(scope: PolicyScope): string | null {
  return scope.pinned ? scope.keyId : null;
}

function scopeFromStored(stored: string | null): PolicyScope {
  return stored === null ? { pinned: false } : { pinned: true, keyId: stored };
}

/** The scope the CURRENT pin defines. Read fresh at every trust decision so a
 * pin transition - which runs on enrollment's SEPARATE serialized queue, not
 * this module's frame chain - is observed immediately: a record or verified
 * mark whose scope no longer matches is inert the instant the pin moves. */
async function currentScope(): Promise<PolicyScope> {
  const pin = await getPin();
  return pin ? { pinned: true, keyId: pin.keyId } : { pinned: false };
}

/** A frozen shallow clone (disabledTools array frozen too): what the unpinned approver receives, so it observes exactly
 * the values this push will commit and cannot mutate the to-be-stored object. Typed as PolicyValues to match the seam;
 * the freeze is a runtime guard, not a type change. */
function freezePolicyValues(values: PolicyValues): PolicyValues {
  const clone: PolicyValues = { ...values, disabledTools: [...values.disabledTools] };
  Object.freeze(clone.disabledTools);
  Object.freeze(clone);
  return clone;
}

// ---- port plumbing (mirrors presence.ts) --------------------------------------

type PostFrame = (frame: object) => boolean;

/** A fresh attachment per attachPort, so "did THIS connection verify a push, and under which scope?" is a
 * reference-identity fact a reconnect cannot inherit (ADR-0032 decision 4). The verified arm carries scope and
 * generation so the barrier closes the instant the pin moves away from either. */
type AttachmentPolicy =
  | { kind: "awaiting" }
  | { kind: "verified"; scope: PolicyScope; generation: number };

/** Stamped only by notePinProvenOnConnection from a fresh-nonce challenge-response on this connection. The policy
 * verified mark is deliberately not folded in: a `policy_current` signature covers only baseline bytes a substituted host
 * can replay verbatim, so it proves the document, never the peer.
 *   generation -> the pin epoch the challenge STARTED under (caller-captured), so a re-pair mid-challenge cannot launder old evidence */
type AttachmentIdentity =
  | { kind: "unproven" }
  | { kind: "proven"; keyId: string; generation: number };

/** One port attachment. Only the `legacy_settings` and `lang_set` sends below ever post through `post`. */
interface PortAttachment {
  post: PostFrame;
  policy: AttachmentPolicy;
  identity: AttachmentIdentity;
  /** THIS connection's host reported `reason:"absent"` (no policy store, no
   * prior receipt). Latched per attachment so identity proof arriving later
   * on the SAME connection can complete a send the report-time gate refused
   * for lack of evidence; a reconnect inherits nothing. */
  absentReported: boolean;
  /** THIS connection's host has pushed a schema-valid `lang_current`: the
   * never-speak-first gate for `lang_set` (ADR-0032 decisions 4 and 7). An
   * old host that never pushes one never sees a language frame it would
   * fatally forward; a reconnect inherits nothing. */
  langSeen: boolean;
  /** The first-pairing adoption `lang_set` (decision 7) already went out on
   * THIS connection: at most one per connection, however many seq:0 pushes
   * the host repeats. The honest host's reply push carries seq >= 1, which
   * ends the adoption condition entirely. */
  langAdoptionOffered: boolean;
}

let port: PortAttachment | null = null;

export function attachPort(post: PostFrame): void {
  port = {
    post,
    policy: { kind: "awaiting" },
    identity: { kind: "unproven" },
    absentReported: false,
    langSeen: false,
    langAdoptionOffered: false,
  };
  // The apply cursor is per-connection, like the two latches above: a
  // departed peer's {value, seq:MAX} push must not suppress the genuine
  // host's real, lower seq on the next connection (its own push-on-connect
  // re-applies idempotently; see the lang section's cursor docs).
  lang = null;
}

export function detachPort(): void {
  port = null;
}

// ---- lang_current: the shared-language lane (ADR-0032 decision 7) -------------------
//
// A storage.onChanged listener cannot tell a user's write from an applied push, so emission never hangs off storage
// events and a set-push-apply cycle emits exactly one `lang_set`:
//   APPLY     host -> extension   writes only the `uiLanguage` key (the i18n watcher swaps locales); never emits
//   CHOOSE    extension -> host   chooseLanguage, from the options picker's gesture only; the host's echo returns via APPLY
//   ADOPTION  extension -> host   seq:0 means the host value was never set; an explicitly-set local value is offered once
//
// The trust bar is PINNED, one notch below the legacy bag's pinned + proven possession: the bag discloses the user's
// settings, while a hostile PAIRED host flipping the UI language is an accepted cosmetic nuisance, so no commit-time epoch recheck either.

const UI_LANGUAGE_KEY = "uiLanguage";

/** The last applied host push on the CURRENT connection; its `seq` is the apply cursor (only a strictly greater push
 * applies). In memory and reset by attachPort on purpose: the host re-pushes on every connect, and a persisted cursor
 * would read that equal-seq push as already applied and suppress the repair of a stale local pick. */
let lang: { value: string; seq: number } | null = null;

/** Tests only: the applied-push cursor. Nothing security-relevant may ever
 * key on it (decision 7). */
export function getLangState(): { value: string; seq: number } | null {
  return lang;
}

/** The lane's trust bar (section docs above): PINNED - not the bag's
 * pinned + proven-possession, and not mere connectedness. Read fresh at
 * every decision, the same pinned signal every sibling gate consults. */
async function langLanePinned(): Promise<boolean> {
  return (await currentScope()).pinned;
}

/** Whether a host value is one of the shared uiLanguage values. Out-of-enum
 * is refused (the host refuses them too; this is the display-side backstop)
 * and the current value stands - the frame schema pins only the shape, so
 * this enum check is the consumer's job, done here before ANY use. */
function isSharedLanguage(value: string): value is UiLanguageValue {
  return (UI_LANGUAGES as readonly string[]).includes(value);
}

/** The APPLY path plus the adoption offer. Never emits on apply; the ONLY
 * emit in here is the once-per-connection adoption send for seq:0. Runs on
 * the frame chain (routeOne), so applies and sends never interleave. */
async function handleLangCurrent(msg: unknown, attachment: PortAttachment | null): Promise<void> {
  const parsed = LangCurrentFrameSchema.safeParse(msg);
  if (!parsed.success) {
    console.warn("[bb] dropping malformed lang_current frame");
    return;
  }
  // The host spoke the language lane on this connection: lang_set may go
  // out from now on (never-speak-first). A schema-valid frame is what
  // proves the peer handles these frames; the VALUE is judged separately.
  if (attachment) attachment.langSeen = true;
  // The pinned gate (the lane's trust bar, section docs above): an unpaired
  // extension keeps its local value - the push is ignored entirely, and the
  // adoption latch stays unset so a first pairing can still import.
  if (!(await langLanePinned())) return;
  const { value, seq } = parsed.data;
  if (seq === 0) {
    // seq 0 = the host store's never-explicitly-set default: no signal,
    // nothing to apply (the local preference stands), but it is the
    // first-pairing adoption trigger (ADR-0032 :670-672).
    await maybeAdoptExtensionLanguage(attachment);
    return;
  }
  // Sequence-suppressed (decision 7): only a strictly newer push applies;
  // an echo or replay has nothing to ride on.
  if (lang && seq <= lang.seq) return;
  // Out-of-enum: refused WITHOUT advancing the cursor, so a later genuine
  // push with the same seq still applies.
  if (!isSharedLanguage(value)) {
    console.warn("[bb] refusing lang_current outside the shared language enum");
    return;
  }
  // Write ONLY the uiLanguage key, and skip the write when storage already
  // agrees (the steady-state push-on-connect replay must not retrigger the
  // i18n watcher on every reconnect).
  const { [UI_LANGUAGE_KEY]: stored } = await browser.storage.local.get(UI_LANGUAGE_KEY);
  if (stored !== value) {
    await browser.storage.local.set({ [UI_LANGUAGE_KEY]: value });
  }
  // The writes awaited, and attachPort resets the cursor synchronously off
  // the frame chain: a departed connection's push resuming here must not
  // re-commit the old peer's seq over the NEW connection's fresh cursor.
  if (attachment !== port) return;
  // The cursor commits only once the write held (a throwing write unwinds
  // through the frame chain's catch with the cursor unmoved, so the host's
  // same-seq replay can still repair the stale storage).
  lang = { value, seq };
}

/** The one sanctioned non-gesture `lang_set`: seq:0 says the host value was never set, so an explicitly-set local
 * uiLanguage (raw key present and in-enum) is offered once per connection. Terminates by construction: the host's reply
 * push carries seq >= 1 and returns through the non-emitting apply path.
 *   host repeats seq:0  -> one offer per connection (langAdoptionOffered)
 *   reconnect           -> re-offers; a missed adoption costs latency, never the import */
async function maybeAdoptExtensionLanguage(attachment: PortAttachment | null): Promise<void> {
  if (!attachment || attachment !== port) return;
  if (attachment.langAdoptionOffered) return;
  // A real push already applied on this connection: the host HAS an
  // explicit value, so a later seq:0 is inconsistent noise, not an adoption
  // trigger.
  if (lang !== null) return;
  const { [UI_LANGUAGE_KEY]: stored } = await browser.storage.local.get(UI_LANGUAGE_KEY);
  if (typeof stored !== "string" || !isSharedLanguage(stored)) return;
  // The read awaited: re-check the connection so a reconnect mid-read
  // cannot ride the dead attachment's offer.
  if (attachment !== port) return;
  attachment.langAdoptionOffered = true;
  attachment.post({ type: "lang_set", value: stored } satisfies LangSetWire);
}

/** The only gesture-driven `lang_set` emitter (the options picker's `lang_choose` message; the picker's own local write
 * keeps the UI responsive offline). Serialized on the frame chain so a send never interleaves with an apply, and gated on
 * PINNED plus `langSeen`: unpaired or without a lang-capable connection the choice stays local, and the host's next
 * push-on-connect re-asserts the host truth. Resolves with whether a frame was posted. */
export function chooseLanguage(value: UiLanguageValue): Promise<boolean> {
  const send = frameChain.then(async () => {
    const attachment = port;
    if (!attachment || !attachment.langSeen) return false;
    if (!(await langLanePinned())) return false;
    // The pinned read awaited: only the still-live attachment may emit.
    if (attachment !== port) return false;
    return attachment.post({ type: "lang_set", value } satisfies LangSetWire);
  });
  frameChain = send.then(
    () => undefined,
    (e) => {
      console.warn("[bb] lang_set send failed", e);
    },
  );
  return send;
}

// ---- the persisted reads (each discriminates its three outcomes) ---------------

/** `corrupt` (present but not exactly `true`) is tampering and must not read as armed or unarmed: it latches closed
 * (ADR-0032 decision 8). Written only as `true`; only onPinPinned's new-key path touches a corrupt flag, rewriting it to `true`. */
type CutoverRead = "unarmed" | "armed" | "corrupt";

/** Classify a raw stored cutover value. `undefined` is the absent signal
 * (storage cannot hold undefined); any other non-`true` value is tampering. */
function classifyCutover(value: unknown): CutoverRead {
  if (value === undefined) return "unarmed";
  return value === true ? "armed" : "corrupt";
}

async function readCutover(): Promise<CutoverRead> {
  const { [POLICY_CUTOVER_KEY]: value } = await browser.storage.local.get(POLICY_CUTOVER_KEY);
  return classifyCutover(value);
}

/** Corrupt (present but failing the strict schema) is NEVER folded into absent: that is the fail-open the kill mirror's
 * STRICT precedent forbids. */
type StoredRead =
  | { kind: "absent" }
  | { kind: "corrupt" }
  | { kind: "valid"; record: StoredPolicyState };

/** Classify a raw stored record value. `undefined` is the absent signal; any
 * stored value that fails the strict schema is corrupt, never absent. */
function classifyStored(value: unknown): StoredRead {
  if (value === undefined) return { kind: "absent" };
  const parsed = StoredPolicyStateSchema.safeParse(value);
  if (!parsed.success) return { kind: "corrupt" };
  // The schema already parsed `effective` strictly; re-parse through the
  // canonical strict reader so any future divergence stays fail-closed.
  const effective = parseStoredPolicyValues(parsed.data.effective);
  if (!effective) return { kind: "corrupt" };
  return { kind: "valid", record: { ...parsed.data, effective } };
}

async function readStoredRecord(): Promise<StoredRead> {
  const { [POLICY_STATE_KEY]: value } = await browser.storage.local.get(POLICY_STATE_KEY);
  return classifyStored(value);
}

/** The keyId pinned when the last revoke ran, written by onPinRevoked and consumed by the next onPinPinned. Durable
 * because the MV3 service worker commonly dies between revoke and re-pair; an in-memory prior would then read every
 * re-pair as "prior unknown", never a new key, and neither the compromise latch nor a corrupt cutover flag could recover.
 *
 * It carries LESS trust than the pin store it copies (a bare string, no pubkey to check against SHA-256), so only the
 * keyId shape is validated, and neither residual is closable here (there is no in-extension secret to MAC with):
 *   tamperer writes a different keyId-shaped string  -> next re-pair reads as new; no more than deleting bridgePolicyState, which it already can
 *   tamperer writes anything else                    -> reads as unknown; recovery stalls until the next revoke overwrites it (DoS-equivalent) */
type PriorPinRead = { kind: "known"; keyId: string } | { kind: "unknown" };

function classifyPriorPin(value: unknown): PriorPinRead {
  // Anything not keyId-shaped (absent, non-string, "", uppercase hex, wrong length) is unknown, which fails closed to
  // "not a new key". KEY_ID_HEX is the shared keyId regex, so this validator cannot drift from it.
  return typeof value === "string" && KEY_ID_HEX.test(value)
    ? { kind: "known", keyId: value }
    : { kind: "unknown" };
}

async function readPriorPin(): Promise<PriorPinRead> {
  const { [POLICY_PRIOR_PIN_KEY]: value } = await browser.storage.local.get(POLICY_PRIOR_PIN_KEY);
  return classifyPriorPin(value);
}

/** One storage `get` for both keys: resolvePolicyState folds them together, and two separate reads could tear across a
 * pin transition or a partial write and hand the fold an inconsistent pair. */
async function readPolicyStorage(): Promise<{ cutover: CutoverRead; stored: StoredRead }> {
  const raw = await browser.storage.local.get([POLICY_CUTOVER_KEY, POLICY_STATE_KEY]);
  return {
    cutover: classifyCutover(raw[POLICY_CUTOVER_KEY]),
    stored: classifyStored(raw[POLICY_STATE_KEY]),
  };
}

// ---- the resolved policy state (the no-invalid-states sum type) ----------------

/** The persisted policy state, resolved against a scope into exactly one arm.
 * No contradictory combination is representable. */
type PolicyState =
  | { kind: "legacy" }
  | { kind: "awaitingBaseline"; scope: PolicyScope }
  | { kind: "active"; scope: PolicyScope; record: StoredPolicyState }
  | { kind: "compromised" };

/** Fold the cutover fact and the stored record - each read three ways - plus
 * the scope check into the single logical state. This is the one place the
 * lifecycle invariants live; every consumer (the gate, the snapshot, the push
 * ratchet) branches on the result rather than re-deriving flags. */
async function resolvePolicyState(scope: PolicyScope): Promise<PolicyState> {
  // The in-life latch dominates every persisted fact; its declaration names the replay it stops.
  if (compromisedThisLife) return { kind: "compromised" };
  const { cutover, stored } = await readPolicyStorage();
  if (cutover === "corrupt") return { kind: "compromised" };
  if (cutover === "unarmed") {
    // Pre-cutover the record should not exist yet: `armCutover` precedes the
    // record write, so a record present with no cutover is tampering - latch
    // closed rather than fall back to legacy on it.
    return stored.kind === "absent" ? { kind: "legacy" } : { kind: "compromised" };
  }
  // Cutover armed:
  if (stored.kind === "corrupt") return { kind: "compromised" };
  if (stored.kind === "absent") return { kind: "awaitingBaseline", scope };
  const recordScope = scopeFromStored(stored.record.scope);
  // Out of scope (a push that raced a re-pair, or a record left by a different key): the old effective is NOT enforced.
  // A different pinned key starts a fresh ratchet; the unpinned scope over a retained pinned record is refused at
  // writeStoredRecord, since that record is the same-key anti-replay anchor.
  if (!scopesEqual(recordScope, scope)) return { kind: "awaitingBaseline", scope };
  return { kind: "active", scope: recordScope, record: stored.record };
}

// ---- writers ------------------------------------------------------------------

/** Write the ratchet record. Returns whether a write landed, so the commit-end undo can skip restoring a record it never
 * replaced: a blind undo `set` would retrigger every storage.onChanged consumer, breaking the setMirror discipline below. */
async function writeStoredRecord(next: StoredPolicyState): Promise<boolean> {
  const stored = await readStoredRecord();
  // A corrupt record is the latched-closed state; a push silently replacing it would land an older baseline as
  // first-ever over tampering evidence. resolvePolicyState is the primary guard; this is the torn-read backstop.
  if (stored.kind === "corrupt") {
    throw new Error("refusing to overwrite a corrupt policy record");
  }
  // onPinRevoked RETAINS the pinned record so a same-key re-pair still refuses an old-baseline replay; while unpinned it
  // is inert, not disposable. Without this rule an unsigned "restriction" pushed during the unpinned window could ride
  // the user's values approval to overwrite the anchor, and an old, more-permissive signed baseline would then replay as
  // first-ever once the same key is re-paired. Accepted consequence: after a revoke the unpinned lane stores nothing
  // until a re-pair disposes of the record (a new key clears it; the same key puts it back in scope).
  if (next.scope === null && stored.kind === "valid" && stored.record.scope !== null) {
    throw new Error(
      "refusing to replace a retained pinned-scope policy record with an unsigned one",
    );
  }
  // Unchanged state writes nothing (the kill.ts setMirror discipline): `at` means "when the state last CHANGED", and a
  // rewrite would retrigger every storage.onChanged consumer on the steady-state push-on-connect replay.
  if (
    stored.kind === "valid" &&
    stored.record.scope === next.scope &&
    stored.record.revision === next.revision &&
    stored.record.baselineB64 === next.baselineB64 &&
    policyValuesEqual(stored.record.effective, next.effective)
  ) {
    return false;
  }
  await browser.storage.local.set({ [POLICY_STATE_KEY]: next });
  return true;
}

/** Exactly the record `b` describes, `at` stamp included: the commit-end undo may only touch the record the push itself
 * wrote, never what a newer pin transition or push has since put there. */
function sameStoredRecord(a: StoredPolicyState, b: StoredPolicyState): boolean {
  return (
    a.scope === b.scope &&
    a.revision === b.revision &&
    a.baselineB64 === b.baselineB64 &&
    a.at === b.at &&
    policyValuesEqual(a.effective, b.effective)
  );
}

/** Undo a stale commit-end write only while the stored record is exactly the one this push wrote; anything else means a
 * newer transition or push owns the slot. Corrupt is never folded into absent: it throws, as armCutover and writeStoredRecord do.
 *   no reset since the write  -> the pre-write record is restored
 *   ratchet RESET mid-flight  -> the pre-write record is a dead anchor; removed instead (lands in awaitingBaseline) */
async function undoRecordWrite(
  written: StoredPolicyState,
  prior: StoredRead,
  resetGenerationAtWrite: number,
): Promise<void> {
  const now = await readStoredRecord();
  if (now.kind !== "valid" || !sameStoredRecord(now.record, written)) return;
  // Re-checked after the awaited read above because a reset can complete during it. The microtask gap between this
  // check and the set() below cannot be closed in user space (browser.storage.local has no transaction); a reset inside
  // it degrades to a restore that the transition's own removal supersedes, never to an opened barrier.
  if (ratchetResetGeneration !== resetGenerationAtWrite) {
    await browser.storage.local.remove(POLICY_STATE_KEY);
    return;
  }
  if (prior.kind === "valid") {
    await browser.storage.local.set({ [POLICY_STATE_KEY]: prior.record });
    return;
  }
  if (prior.kind === "absent") {
    await browser.storage.local.remove(POLICY_STATE_KEY);
    return;
  }
  throw new Error("refusing to undo a policy record write over a corrupt prior record");
}

/** Arm the one-way cutover (ADR-0032 decision 8). Set on the first accepted
 * push, cleared by nothing on the accept path. Deliberately armed BEFORE the
 * record write: if the SW dies between the two, the resulting armed +
 * absent-record state resolves to awaitingBaseline (deny baseline + closed
 * barrier = fail closed), never legacy-enforced-despite-an-applied-policy. */
async function armCutover(): Promise<void> {
  const cutover = await readCutover();
  if (cutover === "armed") return;
  // Laundering a tampered flag into a clean `true` would erase the evidence resolvePolicyState latches on; it already
  // refused this push, so this is the torn-read backstop and throwing keeps the accept fail-closed.
  if (cutover === "corrupt") {
    throw new Error("refusing to overwrite a corrupt cutover flag");
  }
  await browser.storage.local.set({ [POLICY_CUTOVER_KEY]: true });
  console.log("[bb] policy cutover armed: host policy governs from here on (one-way)");
}

/** Whether the first policy push has ever been accepted (ADR-0032 decision
 * 8). Fail-closed on a corrupt flag: a tampered value reads as armed, so the
 * barrier governs rather than falling back to legacy. */
export async function policyCutoverArmed(): Promise<boolean> {
  return (await readCutover()) !== "unarmed";
}

// ---- the dispatch barrier (consulted by enrollment.ts's gate) -------------------

export type PolicyGate = { allowed: true } | { allowed: false; reason: string };

const BARRIER_REASON =
  "policy barrier: no verified policy push has been accepted on this host connection under " +
  "the current pin, so every bridge request is refused (ADR-0032). A policy-capable host " +
  "pushes its policy at connect; a host that stays silent or pushes junk keeps the bridge " +
  "refusing.";

const LATCHED_REASON =
  "policy state latched closed: the stored policy record or the cutover flag is corrupt " +
  "(tampering evidence). Every bridge request is refused until you revoke the pin and " +
  "re-pair (ADR-0032 decision 4, the kill-mirror STRICT precedent).";

const COMPROMISED_LIFE_REASON =
  "policy state latched closed: a policy baseline failed signature verification against the " +
  "pinned key this session (host-substitution evidence, ADR-0031 posture). Every bridge " +
  "request is refused for the rest of this browser session; revoke the pin and re-pair with " +
  "a fresh key to recover (ADR-0032, E2F-1).";

/** The per-connection dispatch barrier (ADR-0032 decision 4). Post-cutover,
 * bridge requests are refused until a policy push has verified and applied on
 * the CURRENT host connection UNDER THE CURRENT SCOPE AND GENERATION - so no op
 * can race ahead of the connect push and run under a cached copy the host has
 * since tightened, and a pin transition (scope OR generation move) closes the
 * barrier the instant it lands. Pre-cutover the barrier is inert: the legacy
 * local settings govern. A corrupt store, or an in-life signature failure,
 * latches it closed regardless of the connection. */
export async function policyDispatchGate(): Promise<PolicyGate> {
  // A signature failure this SW life refuses everything, whatever the cutover, pin, or record say.
  if (compromisedThisLife) return { allowed: false, reason: COMPROMISED_LIFE_REASON };
  const scope = await currentScope();
  const state = await resolvePolicyState(scope);
  if (state.kind === "legacy") return { allowed: true };
  if (state.kind === "compromised") return { allowed: false, reason: LATCHED_REASON };
  // The barrier opens only for an ACTIVE record when THIS connection verified a push under the current scope AND pin
  // generation: a mark from before a same-key re-pair carries the old generation and no longer opens the gate.
  if (
    state.kind === "active" &&
    port?.policy.kind === "verified" &&
    scopesEqual(port.policy.scope, scope) &&
    port.policy.generation === pinGeneration
  ) {
    return { allowed: true };
  }
  return { allowed: false, reason: BARRIER_REASON };
}

// ---- the read API (effective-policy.ts consumes this) ----------------------------

/** The persisted posture, typed so a BLOCKED state is not consumable as policy values: awaitingBaseline and compromised
 * carry a reason, never a PolicyValues, so no enforcement caller can mistake the deny baseline for an applicable policy.
 * effective-policy.ts folds `legacy` with the legacy settings read; every enforcement site consumes ITS wrapper, not this. */
export type PolicyPosture =
  | { kind: "legacy" }
  | { kind: "active"; effective: PolicyValues }
  | { kind: "blocked"; reason: string };

const AWAITING_REASON =
  "policy cutover is armed but no in-scope verified policy baseline is stored (ADR-0032 " +
  "decision 4): the deny posture governs and every enforcement read refuses until a " +
  "baseline verifies under the current pin.";

export async function getPolicyPosture(): Promise<PolicyPosture> {
  const state = await resolvePolicyState(await currentScope());
  switch (state.kind) {
    case "legacy":
      return { kind: "legacy" };
    case "active":
      return { kind: "active", effective: state.record.effective };
    case "awaitingBaseline":
      return { kind: "blocked", reason: AWAITING_REASON };
    case "compromised":
      return {
        kind: "blocked",
        reason: compromisedThisLife ? COMPROMISED_LIFE_REASON : LATCHED_REASON,
      };
    default:
      return unreachable(state);
  }
}

/** The resolved state as tests and diagnostics pin it, minus scope/record internals. Only `active` carries an effective
 * policy, so the blocked arms cannot be read as an applied policy. Enforcement uses getPolicyPosture, never this. */
export type PolicySnapshot =
  | { kind: "legacy" }
  | { kind: "awaitingBaseline" }
  | { kind: "active"; effective: PolicyValues }
  | { kind: "compromised" };

/** The RAW resolved view, for tests and diagnostics that pin the stored
 * state directly. */
export async function getPolicySnapshotForTests(): Promise<PolicySnapshot> {
  const state = await resolvePolicyState(await currentScope());
  switch (state.kind) {
    case "legacy":
      return { kind: "legacy" };
    case "awaitingBaseline":
      return { kind: "awaitingBaseline" };
    case "active":
      return { kind: "active", effective: state.record.effective };
    case "compromised":
      return { kind: "compromised" };
    default:
      return unreachable(state);
  }
}

/** The valid persisted record, or null (absent or corrupt). A raw accessor
 * for tests and diagnostics; scope-aware enforcement goes through
 * resolvePolicyState, not this. */
export async function getStoredPolicyState(): Promise<StoredPolicyState | null> {
  const stored = await readStoredRecord();
  return stored.kind === "valid" ? stored.record : null;
}

// ---- pin lifecycle hooks (called from enrollment.ts) ----------------------------

/** A key was (re-)pinned (ADR-0032 decision 3). Novelty is decided from the PRIOR PIN IDENTITY (the durable prior
 * written at revoke, then this life's mirror), never from the stored record's scope: a same-key re-pair whose record is
 * absent or corrupt must not read as a new key. Always drops this connection's verified mark, bumps the generation
 * epoch, and never clears an armed cutover.
 *   prior known, different  -> ratchet reset, compromise latch cleared, corrupt cutover flag normalized, ratchetResetGeneration bumped
 *   prior known, equal      -> anchor retained, so an old permissive baseline cannot replay after revoke+re-pair with no fresh presence
 *   prior unknown           -> fail closed to "not new": latch kept, ratchet retained */
export async function onPinPinned(newKeyId: string): Promise<void> {
  // Synchronously FIRST: a push in flight must observe that the pin moved even when the new keyId equals the old.
  pinGeneration += 1;
  // The durable prior wins over this life's mirror: it survives the SW restart that so often falls between revoke and re-pair.
  const durablePrior = await readPriorPin();
  const priorKeyId = durablePrior.kind === "known" ? durablePrior.keyId : lastPinnedKeyId;
  const isNewKey = priorKeyId !== null && priorKeyId !== newKeyId;
  lastPinnedKeyId = newKeyId;
  if (isNewKey) {
    ratchetResetGeneration += 1;
    await browser.storage.local.remove(POLICY_STATE_KEY);
    // A NEW-key re-pair is fresh, presence-verified evidence the substituted signer is gone: the ONLY in-life clear.
    compromisedThisLife = false;
    // A corrupt cutover flag latches the state closed and LATCHED_REASON promises re-pair recovery; this is the only
    // writer that can honour it (armCutover throws on corrupt). It is normalized to `true`, not cleared, so recovery
    // lands in awaitingBaseline and the cutover stays one-way.
    if ((await readCutover()) === "corrupt") {
      await browser.storage.local.set({ [POLICY_CUTOVER_KEY]: true });
    }
  }
  // Consumed LAST so an SW death mid-reset cannot leave the prior consumed with the recovery half-done. Re-reading a
  // stale prior is safe: every route back here (revokePin, or approvePending over a pin record that stopped parsing)
  // requires a full presence ceremony, and revokePin overwrites the prior with the real pin first.
  // Remaining window: no restart-reconciliation hook exists, so an SW death between the reset and this remove costs
  // the user one extra revoke+re-pair, never a wrong novelty decision or a fail-open state.
  await browser.storage.local.remove(POLICY_PRIOR_PIN_KEY);
  if (port) {
    port.policy = { kind: "awaiting" };
    // Identity proof is bound to the pin it was earned under: the generation stamp already makes it inert, this keeps the state honest too.
    port.identity = { kind: "unproven" };
  }
}

/** The pin was revoked (ADR-0032 decision 3). RETAINS the ratchet record so a same-key re-pair still refuses an
 * old-baseline replay; the scope check keeps it inert while unpinned, and writeStoredRecord's pinned-anchor rule keeps
 * any unsigned push from replacing it. Never clears cutover or the in-life compromise latch (only onPinPinned's new-key path does).
 *   revokedKeyId: string  -> persisted as the durable prior the next onPinPinned decides novelty against
 *   revokedKeyId: null    -> nothing was pinned; an existing durable prior is left intact, or the recovery path would strand */
export async function onPinRevoked(revokedKeyId: string | null): Promise<void> {
  // Synchronously, so the second leg of a same-key revoke+re-pair is distinguishable from the pre-revoke pin.
  pinGeneration += 1;
  if (revokedKeyId !== null) lastPinnedKeyId = revokedKeyId;
  if (port) {
    port.policy = { kind: "awaiting" };
    port.identity = { kind: "unproven" };
  }
  if (revokedKeyId !== null) {
    await browser.storage.local.set({ [POLICY_PRIOR_PIN_KEY]: revokedKeyId });
  }
}

// ---- the unpinned window-approval seam --------------------------------------------

export interface UnpinnedRelaxation {
  /** The folded effective values (baseline + overlay) awaiting approval, a frozen copy. The parsed document is
   * deliberately not handed over: the approver presents values, and a live reference to what the commit consumes would widen the seam. */
  effective: PolicyValues;
  /** The stored effective it would relax (null = first document ever),
   * also a frozen copy. */
  storedEffective: PolicyValues | null;
}

export type UnpinnedRelaxationApprover = (relaxation: UnpinnedRelaxation) => Promise<boolean>;

let unpinnedApprover: UnpinnedRelaxationApprover | null = null;

/** Register the unpinned lane's approval surface (ADR-0032 decision 3): the off-DOM confirmation window that holds an
 * unpinned relaxation unapplied until the user approves it (policy-approval.ts registers it). While none is registered
 * every unpinned relaxation, including the first-ever document, is refused. Never consulted on a pinned extension. */
export function setUnpinnedRelaxationApprover(approver: UnpinnedRelaxationApprover | null): void {
  unpinnedApprover = approver;
}

// ---- inbound frames --------------------------------------------------------------

/** Classification for the port demux: is this frame a policy/language push? */
export function isPolicyFrame(msg: unknown): boolean {
  return PolicyInboundFrameSchema.safeParse(msg).success;
}

// Frames are processed strictly in arrival order (the kill.ts chain): the
// accept path awaits crypto and storage, so two overlapping pushes could
// otherwise land their ratchet writes in the wrong order.
let frameChain: Promise<void> = Promise.resolve();

/** The unsigned push held at the approver, or null; set around the approver await only. handlePolicyFrame collapses an
 * inbound frame only when ALL THREE match: a different overlay is a tightening that must not be lost, and a different
 * attachment is a reconnect's push-on-connect that must run so the NEW connection earns its own verified mark. */
let pendingApproval: {
  baselineB64: string;
  overlayJson: string;
  attachment: PortAttachment | null;
} | null = null;

/** Route one inbound policy/lang frame. The attachment is captured synchronously so the verified mark lands on exactly
 * the connection the frame arrived on; a reconnect mid-verification stays unverified until its own connect push.
 *
 * port.ts void-routes these frames like the kill frames, so requests already past the gate can dispatch while a
 * bad-signature push is still verifying; a synchronous verifying-hold is deliberately not built (the kill frames' trade-off).
 * Recorded in docs/security/threat-model.md, "Host-owned policy (ADR-0032) residual ledger".
 *   bad push arrives -> requests past the gate run under the stored effective -> signature fails -> latch set synchronously
 * Nothing that reads the gate or dispatch after the latch passes. */
export function handlePolicyFrame(msg: unknown): Promise<void> {
  const attachment = port;
  // A TRULY IDENTICAL replay of the push held at the approver (same baseline, overlay, attachment) is dropped: the
  // pending prompt's verdict covers it, and another prompt would let a hostile unpinned host occupy the confirmation
  // FIFO. Anything less serializes on the frame chain: a different overlay is the host tightening mid-window, and a
  // different attachment is a reconnect that must earn its own mark. Distinct candidates still cost one prompt each
  // (audited on denial); that occupancy is recorded in docs/security/threat-model.md's residual ledger.
  if (pendingApproval !== null && attachment === pendingApproval.attachment) {
    const dup = PolicyCurrentFrameSchema.safeParse(msg);
    if (
      dup.success &&
      dup.data.ok === true &&
      dup.data.baseline === pendingApproval.baselineB64 &&
      JSON.stringify(dup.data.overlay ?? null) === pendingApproval.overlayJson
    ) {
      console.warn("[bb] dropping a policy push identical to one already awaiting approval");
      return frameChain;
    }
  }
  frameChain = frameChain
    .then(() => routeOne(msg, attachment))
    .catch((e) => {
      console.warn("[bb] policy frame handling failed", e);
    });
  return frameChain;
}

async function routeOne(msg: unknown, attachment: PortAttachment | null): Promise<void> {
  const inbound = PolicyInboundFrameSchema.safeParse(msg);
  if (!inbound.success) return;
  if (inbound.data.type === "lang_current") {
    await handleLangCurrent(msg, attachment);
    return;
  }
  await handlePolicyCurrent(msg, attachment);
}

/** A refusal changes nothing, and says so: the stored effective stays enforced and the connection's verified mark, if
 * it has one, is kept (only markPolicyCompromised drops it), and the failure is surfaced rather than smoothed over
 * (ADR-0032 decision 4). The attack-shaped refusals (a rejected policy CLAIM after crypto/ratchet reasoning) are also
 * routed to the audit ring as `policy_refused`; the benign shape/version-skew refusals are console-only, so the ring
 * stays a meaningful security trail. */
function refuse(why: string, opts: { audit?: boolean } = {}): void {
  console.warn("[bb] policy push refused:", why);
  if (opts.audit) auditEvent("policy_refused", { detail: why.slice(0, 512) });
}

/** A signature failed against the pin (ADR-0031 posture): positive evidence the signer does not hold the pinned key.
 * The in-life latch is SET and this connection's verified mark dropped SYNCHRONOUSLY, before any await, so a replayed
 * byte-identical genuine frame cannot ride the idempotent-replay path back to a verified mark while, or after, the
 * durable persist fails.
 *
 * Residual, recorded in docs/security/threat-model.md ("Host-owned policy (ADR-0032) residual ledger"): the latch is in
 * memory, so a failed setCompromised persist followed by an SW restart leaves a fresh SW that accepts a replayed genuine
 * frame. Closing it needs a durable write-before-proceed or a boot-time re-attestation, not a wider in-memory latch.
 *
 *   the barrier reopens only to  -> a policy the pinned key signed at or above the stored revision
 *   enclave re-attestation       -> adds nothing unless hostReverifyMs is set (its default 0 never re-verifies) */
async function markPolicyCompromised(
  attachment: PortAttachment | null,
  reason: string,
): Promise<void> {
  // SYNCHRONOUS, before any await: this is the whole point of the sticky latch.
  compromisedThisLife = true;
  if (attachment) attachment.policy = { kind: "awaiting" };
  console.error("[bb] policy baseline failed signature verification:", reason);
  auditEvent("policy_compromised", { detail: reason.slice(0, 512) });
  try {
    await setCompromised({
      reason: `policy baseline failed signature verification: ${reason}`,
      at: Date.now(),
    });
  } catch (e) {
    console.error(
      "[bb] FAIL-CLOSED: could not persist the policy compromise mark; the in-life sticky " +
        "latch and the dropped verified mark keep the dispatch barrier closed for this SW life",
      e,
    );
  }
}

async function handlePolicyCurrent(msg: unknown, attachment: PortAttachment | null): Promise<void> {
  const parsed = PolicyCurrentFrameSchema.safeParse(msg);
  if (!parsed.success) return refuse("malformed policy_current frame");
  // The frame schema is loose and its parse output RETAINS unknown keys: only the named fields below may be read; never
  // spread, iterate, or forward the frame object.
  const { ok, baseline, sig, overlay, reason, error } = parsed.data;

  if (ok !== true || baseline === undefined) {
    // Only the structured `reason:"absent"` (the host attests it has NO signed baseline) may offer the legacy bag, and
    // the offer is gated further inside (ADR-0032 decision 8). The host derives the reason from its policy store alone,
    // so a re-push after our bag was recorded still says absent; the send-once flag and the host's first-bag-wins store
    // make that a no-op. An old host that omits the field lands here as `undefined` and never triggers.
    if (reason === "absent") await offerLegacyBag(attachment);
    // Nothing to verify and nothing changes; a policy-capable peer gone silent or wrong NEVER opens the gate.
    return refuse(`host provided no baseline${error ? ` (${error})` : ""}`);
  }

  let docBytes: Uint8Array;
  try {
    docBytes = base64Decode(baseline);
  } catch (e) {
    return refuse(`baseline is not canonical base64: ${e instanceof Error ? e.message : e}`);
  }

  // Snapshot the scope and generation here and re-check them at commit: a pin transition on enrollment's separate queue
  // must not let this push land in the wrong scope or resurrect a mark across a same-key revoke+re-pair. The pin OBJECT
  // is read once: keyId = SHA-256(pubkey), so binding the scope to the keyId binds it to the exact verifying key.
  const generationAtStart = pinGeneration;
  const pinAtStart = await getPin();
  const scopeAtStart: PolicyScope = pinAtStart
    ? { pinned: true, keyId: pinAtStart.keyId }
    : { pinned: false };
  if (pinAtStart) {
    if (sig === undefined) {
      // The no-downgrade rule (ADR-0032 decision 3): a pinned extension never accepts an unsigned baseline. A missing
      // signature is a refusal, not crypto evidence; nothing here proves who sent it.
      return refuse("unsigned baseline on a pinned extension", { audit: true });
    }
    const verdict = await verifyPolicySignatureAgainstPin(sig, docBytes, pinAtStart.pubkeyB64);
    if (!verdict.ok) return markPolicyCompromised(attachment, verdict.reason);
  }

  // Strict-parse the SAME bytes the signature covered - only after it held
  // (pinned lane); on an unpinned machine strict parsing is the entry point
  // (there is nothing to verify, decision 3).
  let docJson: unknown;
  try {
    docJson = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(docBytes));
  } catch {
    return refuse("baseline bytes are not UTF-8 JSON");
  }
  const doc = PolicyDocSchema.safeParse(docJson);
  if (!doc.success) return refuse("baseline document failed the strict schema");
  const baselineValues = policyValuesFromDoc(doc.data);

  // The unsigned overlay may only restrict the verified baseline. Its SHAPE
  // was strict-parsed by the frame schema; its DIRECTION is recomputed here
  // from the generated table, field by field, and one relaxing entry fails
  // the whole push (decision 4). Folding is by catalogue name only, so the
  // folded effective differs from the baseline exactly on the overlay's own
  // entries.
  const effective = foldPolicyOverlay(baselineValues, overlay ?? {});
  const overlayRelaxes = relaxedPolicyFields(effective, baselineValues);
  if (overlayRelaxes.length > 0) {
    return refuse(`overlay relaxes the baseline on: ${overlayRelaxes.join(", ")}`, { audit: true });
  }

  // The ratchet anchor is the ACTIVE stored record under the snapshot scope. A corrupt store latches closed: a push must
  // not silently "fix" it by landing an older baseline as first-ever. awaitingBaseline/legacy carry no anchor.
  const state = await resolvePolicyState(scopeAtStart);
  if (state.kind === "compromised") {
    return refuse("stored policy state is corrupt; latched closed until re-pair", { audit: true });
  }
  const anchor = state.kind === "active" ? state.record : null;
  // The revision/touched ratchet binds only the PINNED scope: the signature is what makes those fields mean anything. On
  // the unpinned scope every field is attacker-writable, and enforcing the revision would hand a local forger a permanent
  // denial lever (push revision=MAX and every later genuine unsigned push is refused). That lane's protections are the
  // direction checks above and the approval window below; the anchor still matters as what they compare against.
  if (anchor && scopeAtStart.pinned) {
    // The revision ratchet: strictly higher, or byte-identical to the stored
    // baseline (the idempotent push-on-connect replay).
    if (doc.data.revision < anchor.revision) {
      return refuse(`replayed revision ${doc.data.revision} below stored ${anchor.revision}`, {
        audit: true,
      });
    }
    if (doc.data.revision === anchor.revision && baseline !== anchor.baselineB64) {
      return refuse("revision reuse with different document bytes", { audit: true });
    }
    // The value ratchet, anchored on the STORED effective: nothing the
    // extension ever applied gets laxer without a strictly newer signed
    // document whose touched set names the field. Anchoring here (not on the
    // baseline) is what refuses replaying the genuine current baseline with
    // its overlay stripped, and the touched-set check is what refuses a fresh
    // signature being stretched into a blanket relaxation warrant.
    const relaxed = relaxedPolicyFields(effective, anchor.effective);
    if (relaxed.length > 0) {
      if (doc.data.revision <= anchor.revision) {
        return refuse(`relaxation without a fresh revision on: ${relaxed.join(", ")}`, {
          audit: true,
        });
      }
      const outsideTouched = relaxed.filter((f) => !doc.data.touched.includes(f));
      if (outsideTouched.length > 0) {
        return refuse(
          `baseline relaxes fields outside its signed touched set: ${outsideTouched.join(", ")}`,
          { audit: true },
        );
      }
    }
  }

  if (!scopeAtStart.pinned) {
    // The unpinned lane (ADR-0032 decision 3): a document that only restricts applies silently; a relaxation, including
    // the first document ever, applies only on the user's window approval and is refused while no approver is
    // registered. The approver await can last minutes; the commit recheck below stops a pin landing in that window from
    // turning this unsigned document into an enforced, barrier-opening policy.
    const needsApproval = !anchor || relaxedPolicyFields(effective, anchor.effective).length > 0;
    if (needsApproval) {
      // After a revoke a RETAINED pinned-scope record makes this push unstorable whatever the user answers, so refuse
      // here, audited, instead of burning a real approval gesture and dying unaudited in frameChain's catch at the write.
      const storedNow = await readStoredRecord();
      if (storedNow.kind === "valid" && storedNow.record.scope !== null) {
        return refuse(
          "unsigned push cannot replace the retained pinned-scope anchor; re-pair to recover (U1)",
          { audit: true },
        );
      }
      const approver = unpinnedApprover;
      if (!approver) {
        return refuse("unpinned relaxation with no approval surface registered", { audit: true });
      }
      // Held for the approver await so handlePolicyFrame collapses identical replays, or a hostile host could stack N
      // copies of one document into N sequential occupations of the confirmation FIFO.
      pendingApproval = {
        baselineB64: baseline,
        overlayJson: JSON.stringify(overlay ?? null),
        attachment,
      };
      let approved: boolean;
      try {
        approved = await approver({
          // Frozen copies: the approver must see exactly what this push commits and cannot mutate it.
          effective: freezePolicyValues(effective),
          storedEffective: anchor ? freezePolicyValues(anchor.effective) : null,
        }).catch(() => false);
      } finally {
        pendingApproval = null;
      }
      if (!approved) {
        // Audited: one decline is a user choice, but repeated declines are the signal of a hostile unpinned host
        // grinding at the approval window, and the ring is where that pattern shows.
        return refuse("unpinned relaxation not approved by the user", { audit: true });
      }
    }
  }

  // Re-read the scope and compare the generation AFTER the possibly minutes-long approver await and before the writes:
  // a different scope (crucially unpinned-at-snapshot -> pinned-at-commit, which would commit an UNSIGNED document under
  // a just-pinned key) or a same-key revoke+re-pair drops the push. A second recheck after the writes covers their own awaits.
  const scopeAtCommit = await currentScope();
  if (!scopesEqual(scopeAtCommit, scopeAtStart) || pinGeneration !== generationAtStart) {
    return refuse(
      "pin scope or generation changed while the push was in flight; dropping to stay fail-closed",
      { audit: true },
    );
  }

  // Arm cutover BEFORE the record write (the fail-closed ordering on armCutover); arming is one-way, so a stale arm is harmless.
  await armCutover();
  // Captured BEFORE the awaited prior-snapshot read: a reset completing during that read would otherwise leave the undo
  // comparing equal epochs and restoring an anchor the reset just deleted. Capturing early can only turn a restore into a remove.
  const resetGenerationAtWrite = ratchetResetGeneration;
  // Snapshot the record BEFORE our write so a race detected after it can be undone by restoring exactly it (dropping the
  // anchor would reopen the old-baseline replay). A ratchet RESET mid-flight is the one case that removes instead: the
  // snapshot is then a dead anchor. resolvePolicyState already refused corrupt, so this is `valid` or `absent`.
  const priorRecord = await readStoredRecord();
  const committed: StoredPolicyState = {
    scope: scopeToStored(scopeAtStart),
    effective,
    // An unsigned document's revision is unauthenticated noise: store 0 so the
    // record can never smuggle a forged revision into a ratchet decision. The
    // scope stamp already keeps the signed lane from anchoring on an
    // unsigned-era record (a pin transition is a fresh scope); the clamp makes
    // the stored value honest by construction, not by call order.
    revision: scopeAtStart.pinned ? doc.data.revision : 0,
    baselineB64: baseline,
    at: Date.now(),
  };
  const wrote = await writeStoredRecord(committed);
  // armCutover and writeStoredRecord awaited, so a same-key revoke+re-pair can still move the pin after the pre-write
  // recheck. A stale mark is already inert (the gate rejects a generation mismatch), but the stale RECORD could later
  // resurrect as a ratchet anchor, so undo the write (ownership-checked) and stamp no mark.
  const scopeAtEnd = await currentScope();
  if (!scopesEqual(scopeAtEnd, scopeAtStart) || pinGeneration !== generationAtStart) {
    // `wrote` is the primary guard: a write suppressed as unchanged set nothing, and a blind re-set would retrigger every
    // storage.onChanged consumer. undoRecordWrite's `at` comparison is only a backstop; it fails in a same-millisecond
    // collision. The undo is wrapped so an exception can never skip refuse() and its audit entry (frameChain's catch is silent).
    if (wrote) {
      try {
        await undoRecordWrite(committed, priorRecord, resetGenerationAtWrite);
      } catch (e) {
        console.error(
          "[bb] FAIL-CLOSED: could not undo a stale policy record write; the barrier stays " +
            "closed on this connection and the push is refused",
          e,
        );
      }
    }
    return refuse(
      "pin scope or generation changed during the commit writes; undoing the record write to stay fail-closed",
      { audit: true },
    );
  }
  // The mark carries the snapshot scope and generation, both still equal to the commit values. It lands only when this
  // frame's attachment is STILL the live port: stamping a dead attachment would verify a connection that no longer exists
  // while the live one earned nothing, so stamp nothing; the record stays applied and the new connection's own push earns its mark.
  if (attachment && attachment === port) {
    attachment.policy = { kind: "verified", scope: scopeAtStart, generation: generationAtStart };
  } else if (attachment) {
    console.warn(
      "[bb] policy push applied, but the host connection changed mid-flight; no verified mark " +
        "stamped - the new connection's own push opens its barrier",
    );
  }
  console.log("[bb] policy push applied: revision", doc.data.revision);
}

// ---- the legacy-settings send-once (ADR-0032 decision 8) ------------------------------
//
// `legacy_settings { bag }` offers the snapshotted legacy settings to a host that attests it has no policy store, so
// the app's first-run import can show them and the user can sign revision 1; the host only records it and sends no
// reply. Decision 8's "a policy-capable host has identified itself" is read as fresh-nonce proof of the pinned key on
// THIS connection, not as a well-formed frame; trySendLegacyBag carries each gate condition with its reason.
//
// An `absent` report with no proof yet latches `absentReported`; notePinProvenOnConnection completes the send when the
// proof lands on the SAME connection. The next connect re-offers, so a missed pairing costs latency, never the migration.

/** An opaque handle to the CURRENT connection for callers that verify a proof asynchronously: captured when the
 * challenge goes OUT and handed back with the result, so proof earned on a dead connection credits nobody. */
export function currentConnectionToken(): object | null {
  return port;
}

/** The pin epoch right now, captured by evidence callers when their round STARTS and handed back with the proof;
 * notePinProvenOnConnection says why the start epoch, never the live one, is what gets stamped. */
export function currentPinGeneration(): number {
  return pinGeneration;
}

/** Stamp a fresh-nonce, pin-verified proof of possession on the live attachment. A proof whose challenge predates a pin
 * move proves the OLD pin's holder, so a moved epoch refuses the stamp even when a same-key revoke+re-pair left the keyId equal.
 *   enrollment  -> epoch captured at challenge send
 *   presence    -> captured at round claim, two awaits before the challenge posts; a move in between discards good evidence, never admits old */
export function notePinProvenOnConnection(
  token: object | null,
  keyId: string,
  generationAtChallenge: number,
): void {
  const attachment = port;
  if (token === null || attachment === null || attachment !== token) return;
  if (generationAtChallenge !== pinGeneration) return;
  attachment.identity = { kind: "proven", keyId, generation: generationAtChallenge };
  if (attachment.absentReported) {
    frameChain = frameChain
      .then(() => trySendLegacyBag(attachment))
      .catch((e) => {
        console.warn("[bb] legacy settings send failed", e);
      });
  }
}

/** A `reason:"absent"` push arrived on `attachment` (already on the frame
 * chain): latch the report and attempt the send now. */
async function offerLegacyBag(attachment: PortAttachment | null): Promise<void> {
  if (!attachment) return;
  attachment.absentReported = true;
  await trySendLegacyBag(attachment);
}

/** Attempt the send-once under the full gate (section header above). Every
 * refusal is silent state-wise: nothing is written, nothing is posted, and
 * the durable flag moves only AFTER a successful post. */
async function trySendLegacyBag(attachment: PortAttachment): Promise<void> {
  // Only the live connection may receive the bag; a stale attachment's own
  // report and proof die with it (the reconnect's push re-offers).
  if (attachment !== port) return;
  // A host that failed crypto this SW life gets nothing, whatever it reports.
  if (compromisedThisLife) return;
  const proof = attachment.identity;
  if (proof.kind !== "proven" || proof.generation !== pinGeneration) return;
  // Every fact below lives in extension storage: confirm it is confined to extension contexts THIS SW life before
  // believing any of it (ADR-0027). This path is NOT behind the enrollment gate (policy frames route before it), so the
  // restriction is awaited here, fail-closed on failure.
  if (!(await hardenStorageAccess()).ok) return;
  // The DURABLE enclave compromise mark too: a failed presence or verify proof latches only that mark, and a proof
  // stamped on this connection BEFORE that failure must not ship the bag after it.
  if (await getCompromised()) return;
  const scope = await currentScope();
  // The unpinned lane never sends: with no pin there is no mechanism that could identify the peer (decision 8's unpinned
  // machines keep their legacy settings until pairing).
  if (!scope.pinned || scope.keyId !== proof.keyId) return;
  // Once sent, sent forever (legacy-import.ts): a re-send is the replant vector the host's consumed tombstone refuses.
  if (await getLegacySettingsSent()) return;
  // Pre-cutover only: `legacy` is the one state whose bag is the governing settings. awaitingBaseline/active mean cutover
  // happened (the bag is history, not policy); compromised ships nothing to a suspect peer.
  const state = await resolvePolicyState(scope);
  if (state.kind !== "legacy") return;
  const bag = await readLegacySettingsBag();
  // The reads above awaited: re-check the connection, the pin epoch, AND both compromise marks. A durable mark landed by
  // a failing proof during those awaits bumps neither the generation nor the attachment, so only this recheck can see it.
  if (attachment !== port || pinGeneration !== proof.generation) return;
  if (compromisedThisLife || (await getCompromised())) return;
  if (!attachment.post({ type: "legacy_settings", bag } satisfies LegacySettingsWire)) return;
  await markLegacySettingsSent();
  auditEvent("legacy_settings_sent", { detail: `to pinned key ${proof.keyId}` });
  console.log("[bb] legacy settings bag sent for migration - once, ever (ADR-0032 decision 8)");
}

/** Tests only: forget the port, the language state, any registered approver,
 * the frame chain, and the in-life latches (the sticky compromise flag, the
 * generation epoch, the reset epoch, and the last-pinned mirror) - i.e.
 * everything an SW restart would reset. Stored policy state deliberately stays,
 * INCLUDING the durable prior-pin identity, which is exactly what a restart is
 * meant to preserve - suites that need a clean store reset fakeBrowser storage. */
export function resetPolicySyncForTests(): void {
  port = null;
  lang = null;
  unpinnedApprover = null;
  pendingApproval = null;
  compromisedThisLife = false;
  pinGeneration = 0;
  ratchetResetGeneration = 0;
  lastPinnedKeyId = null;
  frameChain = Promise.resolve();
}
