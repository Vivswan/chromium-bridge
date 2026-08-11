// The extension half of ADR-0032 host-owned policy, Phase 3 consumption
// core: verification of `policy_current` pushes against the extension's OWN
// pinned key, the value ratchet, the stored effective policy, the one-way
// cutover flag, and the per-connection dispatch barrier the enrollment gate
// consults. `lang_current` is consumed by the Phase-4 language lane (the
// apply/choose split at the `lang_current` section below).
//
// Fail closed everywhere (ADR-0032 decisions 3 and 4):
// - a push is consumed only through: strict frame validation -> signature
//   over the EXACT decoded baseline bytes against the PINNED key (the
//   frames carry no key identity the extension honors) -> strict
//   PolicyDocSchema parse of those same bytes;
// - the ratchet (PINNED scope only - the signature is what makes `revision`
//   and `touched` mean anything, both live inside the signed bytes): a
//   revision <= the stored highest-seen is refused unless the bytes are
//   identical to the stored baseline (the idempotent push-on-connect
//   replay), and a push whose folded effective would relax the STORED
//   effective on any field is refused unless the document's revision is
//   strictly higher AND its signed `touched` set names every relaxed field
//   - which is exactly what refuses the overlay-strip replay. On the
//   UNPINNED scope every field of the document is unauthenticated, so the
//   revision is neither enforced nor stored (a forged revision=MAX
//   "restriction" would otherwise brick every later unsigned push - see
//   the ratchet gate in handlePolicyCurrent); that lane's protections are
//   the direction checks, the Lane U approval window, and the
//   pinned-anchor preservation rule in writeStoredRecord, and unsigned
//   accepts store revision 0;
// - an unsigned (scope-null) record can NEVER replace a retained
//   PINNED-scope record: the retained record is the anti-replay anchor a
//   same-key re-pair depends on, and writeStoredRecord throws rather than
//   let an approved unsigned push (a policy-VALUES approval, never an
//   anchor-disposal warrant) destroy it;
// - the unsigned overlay may only restrict the verified baseline: one
//   relaxing entry fails the WHOLE push;
// - a push that fails in ANY way changes nothing: the stored effective
//   stays enforced (never "defaults on garbage") and the connection stays
//   in the deny state behind the barrier;
// - a signature that does not verify against the pin marks the bridge
//   compromised (the presence.ts posture: a crypto mismatch is evidence
//   about the signer, never a mere refusal), and synchronously closes the
//   barrier on the connection the bad push arrived on;
// - on a PINNED extension an unsigned baseline is refused outright, on any
//   platform, for any reason (the no-downgrade rule between the lanes); the
//   unpinned-machine window-approval lane is Lane U's surface, reached only
//   through the exported approver seam below and refused while none exists.
//
// THE STATE MODEL (a scope-stamped, no-invalid-states shape - the structural
// answer to the four blocking lifecycle findings, not per-finding patches):
//
// - Every ratchet state is BOUND TO A SCOPE: the pinned enrollment keyId that
//   governs it, or the unpinned lane (PolicyScope). The scope is stamped into
//   the persisted record and into the per-connection verified mark, and every
//   trust decision re-reads the CURRENT scope and refuses to honor a state
//   whose scope no longer matches. This is what makes an in-flight push that
//   raced a re-pair (finding 1), and an old baseline replayed after a
//   revoke+re-pair of the SAME key (finding 2), impossible to enforce:
//   binding is to the KEY, never to a free-floating boolean.
// - The persisted policy state resolves to exactly one of:
//     legacy            - cutover never armed; the legacy local settings govern.
//     awaitingBaseline  - cutover armed, no in-scope baseline yet (post-arm,
//                         post-reset, or a scope mismatch): deny baseline +
//                         closed barrier.
//     active            - cutover armed, an in-scope ratcheted baseline applies.
//     compromised       - a corrupt cutover flag or a corrupt stored record
//                         post-cutover: LATCHED closed until a re-pair clears
//                         it (the kill-mirror STRICT precedent; corrupt is
//                         DISTINCT from absent, never folded into it).
//   No contradictory combination (cutover-set-but-no-effective read as
//   legacy, corrupt read as absent) is representable.
// - The per-connection attachment carries `Awaiting | Verified{scope}`, not a
//   mutable boolean, so the barrier opens only for a connection that verified
//   a push UNDER THE CURRENT SCOPE.
//
// Same shape as kill.ts: port.ts hands this module the port (attachPort)
// and every policy/lang frame, and frames process strictly in arrival
// order. This module sends exactly TWO kinds of frame: the decision-8
// `legacy_settings` bag (the send-once section at the bottom), only on a
// connection whose host has already pushed `policy_current`, and the
// decision-7 `lang_set` (the language section below), only on a connection
// whose host has already pushed `lang_current` - so the never-speak-first
// rule of decision 4 holds structurally for both (`policy_get` is
// still future business). It deliberately does
// not consult the kill or enrollment gates: a killed bridge still processes
// policy pushes (control-plane mode, decision 6), which port.ts guarantees
// by routing these frames BEFORE the request parse and the gates.

import {
  foldPolicyOverlay,
  KEY_ID_HEX,
  LangCurrentFrameSchema,
  type LangSetWire,
  type LegacySettingsWire,
  POLICY_DEFAULTS,
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
/** The one-way cutover flag's storage key. Exported ONLY for the Phase 5
 * legacy cleanup (legacy-cleanup.ts), which re-reads the flag itself and
 * never writes it; every cutover decision stays in this module. */
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

/** The sticky in-life compromise latch (E2F-1). Set SYNCHRONOUSLY the instant a
 * policy baseline fails signature verification against the pin - before any
 * await - by markPolicyCompromised. Once set, resolvePolicyState resolves to
 * `compromised` REGARDLESS of the cutover flag, stored record, scope, or
 * verified mark, so the dispatch barrier and every enforcement read refuse for
 * the rest of this SW life.
 *
 * Why a durable mark is not enough: markPolicyCompromised persists
 * setCompromised asynchronously, and that persist can THROW. Without this
 * latch a hostile host that just failed a signature could REPLAY a captured
 * genuine, byte-identical frame - the signature verifies, the ratchet accepts
 * it as an idempotent replay, the attachment returns to verified, and the
 * barrier reopens with the enrollment gate never learning a compromise
 * happened. The latch is set before the persist is even attempted, so a failed
 * persist cannot leave a reopenable barrier behind.
 *
 * Cleared within a life ONLY by a NEW-key re-pair, where "new" is decided from
 * the PRIOR PIN IDENTITY (onPinPinned's prior-keyId check, F2): a fresh,
 * presence-verified enrollment key whose keyId genuinely differs from the last
 * pinned one is real new evidence the substituted signer is gone. NEVER cleared
 * by a later valid push, a cutover change, a same-key re-pair, or a re-pair
 * whose prior identity is unknown. */
let compromisedThisLife = false;

/** The pin-transition generation epoch (E2F-2). Bumped synchronously by every
 * pin transition (onPinRevoked, onPinPinned) BEFORE its awaits, so a push in
 * flight can detect that the pin moved even when the keyId ends up equal (an
 * ABA same-key revoke+re-pair). A push snapshots it at start alongside the
 * scope, refuses at commit if it moved, and stamps it into the verified mark so
 * a stale continuation from a prior generation cannot resurrect a verified
 * mark. In memory only: a fresh SW starts at 0 and re-verifies from scratch.
 *
 * COUPLING INVARIANT with ratchetResetGeneration, relied on by the commit-end
 * undo: every ratchetResetGeneration bump is PRECEDED by a pinGeneration bump
 * and IMMEDIATELY FOLLOWED by the record removal, in that order. So a reset is
 * never observable without the pin move that caused it also being observable,
 * and a push that sees an unchanged pinGeneration cannot have missed a reset. */
let pinGeneration = 0;

/** The same-life mirror of the prior pin identity: the keyId the last
 * onPinPinned bound, or the last onPinRevoked revoked. A fast path only - the
 * DURABLE prior (POLICY_PRIOR_PIN_KEY, written on the revoke path) is what
 * survives an SW restart and is consulted FIRST. onPinPinned owns the novelty
 * rules; they are stated once, there. */
let lastPinnedKeyId: string | null = null;

/** Bumped ONLY by onPinPinned's new-key reset path - the branch that removes the
 * stored record. A push's commit-end undo compares it (H4): if a ratchet RESET
 * ran while the push was in flight, the undo must NOT restore the pre-write
 * record, or an A->B->A transition would resurrect the very anchor the reset
 * deleted. In memory only, like the generation epoch. See the coupling invariant
 * on pinGeneration above: bump order is pinGeneration, then this, then the
 * record removal - the undo's epoch comparison is only sound under that order. */
let ratchetResetGeneration = 0;

// ---- the ratchet scope --------------------------------------------------------

/** The identity a ratchet state is bound to (ADR-0032 decision 3, finding 2):
 * the pinned enrollment keyId, or the unpinned lane. Two states share a
 * ratchet only when their scopes are EQUAL - a different pinned key, or the
 * pinned<->unpinned boundary, is a fresh scope that never inherits the old
 * anchor. */
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

/** A frozen shallow clone (disabledTools array frozen too): what the Lane U
 * approver receives, so it observes exactly the values this push will commit
 * and cannot mutate the to-be-stored object. Typed as PolicyValues to match
 * the seam; the freeze is a runtime guard, not a type change. */
function freezePolicyValues(values: PolicyValues): PolicyValues {
  const clone: PolicyValues = { ...values, disabledTools: [...values.disabledTools] };
  Object.freeze(clone.disabledTools);
  Object.freeze(clone);
  return clone;
}

// ---- port plumbing (mirrors presence.ts) --------------------------------------

type PostFrame = (frame: object) => boolean;

/** The per-connection barrier state (ADR-0032 decision 4): a fresh attachment
 * per attachPort, so "did THIS connection verify a policy push, and under
 * which scope?" is a reference-identity fact - a reconnect installs a new,
 * `awaiting` attachment that inherits nothing. `Verified{scope, generation}`
 * (not a bare boolean) is what lets the barrier close the instant the pin moves
 * away from the scope, OR the generation, the mark was earned under (E2F-2). */
type AttachmentPolicy =
  | { kind: "awaiting" }
  | { kind: "verified"; scope: PolicyScope; generation: number };

/** Per-connection proof-of-possession of the PINNED key (the decision-8
 * send-once gate, bottom of this file). `proven` is stamped ONLY by
 * notePinProvenOnConnection, whose callers hold a FRESH-NONCE
 * challenge-response verified against the pin on exactly this connection
 * (the enrollment verify ceremony, a presence round). The policy verified
 * mark above is deliberately NOT folded in here: a `policy_current`
 * signature covers only the baseline bytes, which a substituted host can
 * replay verbatim - it proves the DOCUMENT is genuine, never that the peer
 * holds the key. `generation` is the pin epoch the proof's round STARTED
 * under (captured by the caller before its challenge posts, never read live
 * at stamp time), so a same-key revoke+re-pair during the challenge window
 * cannot launder old-epoch evidence into the new epoch (E2F-2). */
type AttachmentIdentity =
  | { kind: "unproven" }
  | { kind: "proven"; keyId: string; generation: number };

/** One port attachment. `post` carries the decision-8 `legacy_settings`
 * send below and the decision-7 `lang_set` sends; nothing else in this
 * module ever posts. */
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

// ---- lang_current: the shared-language lane (ADR-0032 decision 7, Phase 4) -----
//
// The two directions are DIFFERENT paths on purpose (the app's lang-sync.ts
// split, adapted), and the whole echo-loop rule lives in that split:
//
//  - APPLY (host -> extension): an accepted push writes the value to the
//    `uiLanguage` storage key - the ONLY key this lane ever writes - and the
//    i18n runtime's storage.onChanged watcher swaps every open page's locale.
//    This path NEVER emits `lang_set`: a storage.onChanged listener cannot
//    tell a user's write from an applied push, so emission must never hang
//    off storage events - it hangs off the two explicit paths below instead.
//  - CHOOSE (extension -> host): `chooseLanguage`, reached ONLY from the
//    options picker's user gesture via the `lang_choose` runtime message, is
//    the one gesture-driven `lang_set` emitter. The picker's local storage
//    write stays (responsive offline); the host's echo push comes back
//    through the non-emitting apply path, so a set-push-apply cycle emits
//    exactly one `lang_set`.
//  - ADOPTION (the one sanctioned non-gesture emit, decision 7 / the ADR's
//    first-pairing rule): a push with seq:0 means the host value was never
//    explicitly set anywhere; if the extension HAS an explicitly-set
//    uiLanguage, it offers that value once - see
//    maybeAdoptExtensionLanguage.
//
// THE LANE'S TRUST BAR IS PINNED (langLanePinned below): ADR-0032 scopes the
// shared language to WHILE PAIRED (decision 2 :47-49, decision 7 :568-571 -
// "an unpaired extension keeps its local value and its local picker", and
// adoption is "imported directly at first pairing"). Both directions gate on
// it: an unpinned extension ignores host language pushes AND keeps gestures
// local. Deliberately PINNED, not the legacy-bag send's PINNED + PROVEN
// possession: the bag demands a fresh-nonce proof because it DISCLOSES the
// user's settings to the peer, while language is a cosmetic, own-lane value
// (decision 7) whose worst abuse is the accepted UI-language flip - so
// pairing is the right bar, one deliberate notch below the bag's. For the
// same reason the gate is read fresh per decision with NO commit-time epoch
// recheck: a pin revoke landing inside an in-flight apply or adoption
// (microtask scale) is accepted within this same one-notch-lower bar.
//
// THE SEQ CURSOR IS DELIBERATELY IN MEMORY, reset at every (re)attach, never
// stored. The host pushes lang_current on every connect, so each connection
// re-applies the current {value, seq} - idempotent when storage already
// agrees (the equal-value write is skipped), and a REPAIR when a stale local
// uiLanguage diverged from the host (an offline local pick never reached the
// host and the host is canonical after first set, decision 7 / ADR :672). A
// PERSISTED cursor would suppress exactly that repair: equal seq would read
// as already-applied and the stale local value would fight the host forever.
// The per-attachment reset closes the same hole one notch further in: a
// paired-but-substituted host that pushed {value, seq:MAX} and disconnected
// must not suppress the genuine host's real, lower seq for the rest of the
// SW life - the genuine host's own push-on-connect starts a fresh cursor.
//
// SECURITY, stated honestly: lang_current arrives on the host channel with
// no signature and no ratchet - by design (decision 7). Nothing
// security-relevant may ever key on it; the value is enum-validated before
// use and the write surface is the single uiLanguage key. A hostile PAIRED
// host can flip the UI language - an accepted, cosmetic-only nuisance with
// zero capability attached, which is exactly why language gets the free
// lane and policy does not.

const UI_LANGUAGE_KEY = "uiLanguage";

/** The last applied host push on the CURRENT connection (null = none
 * applied; reset by attachPort). Its `seq` is the apply cursor: only a
 * strictly greater push applies. */
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

/** First-pairing adoption (ADR-0032 decision 7, :670-672): the host attests
 * its language was never explicitly set (seq:0); if the extension's
 * uiLanguage WAS explicitly set - the raw storage key exists and is
 * in-enum (absence means the schema default was never overridden; garbage
 * is not adopted) - send ONE `lang_set` carrying it. Reached only through
 * the caller's pinned gate, so it fires when the pin is established: exactly
 * the ADR's "imported directly at first pairing". This is the one
 * sanctioned exception to gesture-only emission, and it terminates by
 * construction: the host's reply push carries seq >= 1, which both ends the
 * seq:0 condition and comes back through the non-emitting apply path. The
 * per-connection latch bounds a host that keeps repeating seq:0 (buggy or
 * hostile) to one offer per connection; a reconnect re-offers, which is the
 * legacy-bag posture - a missed adoption costs latency, never the import. */
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

/** The CHOOSE path: the user picked a language in the options page (the
 * `lang_choose` runtime message; the picker's own local storage write keeps
 * the UI responsive offline). The ONLY gesture-driven `lang_set` emitter.
 * Serialized on the frame chain so a send never interleaves with an apply
 * (or another send) in flight, and gated on the lane's PINNED trust bar
 * (section docs above) plus `langSeen` (never-speak-first): unpaired or
 * with no live lang-capable connection the choice simply stays local
 * ("keeps its local picker"), and the host's next push-on-connect
 * re-asserts the host truth (canonical after first set). Resolves with
 * whether a frame was posted. */
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

/** The one-way cutover fact (ADR-0032 decision 8), read as three DISTINCT
 * outcomes. `corrupt` (present but not exactly `true`) is tampering and must
 * not be read as either armed or unarmed: it latches closed. Written only as
 * `true`; cleared by nothing except a NEW-key re-pair normalizing a CORRUPT
 * flag (E2F-4). */
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

/** The stored ratchet record, read as three DISTINCT outcomes (finding 3):
 * `absent` (the storage key is missing), `valid`, or `corrupt` (present but
 * fails the strict schema). Corrupt is NEVER folded into absent - that is the
 * fail-open the kill mirror's STRICT precedent forbids. */
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

/** The DURABLE prior-pin identity (H1): the keyId that was pinned when the last
 * revoke ran, written by onPinRevoked and consumed by the next onPinPinned.
 *
 * Why durable rather than an in-memory seed: the MV3 service worker very
 * commonly dies between the revoke and the re-pair, and the in-memory mirror
 * would be gone. Without a durable prior EVERY re-pair after an SW restart
 * reads as "prior unknown" -> never a new key -> the compromise latch is never
 * cleared and a CORRUPT cutover flag is never normalized, which would make both
 * LATCHED_REASON's and COMPROMISED_LIFE_REASON's promised "revoke and re-pair"
 * recovery false (onPinPinned's normalize path is the only writer anywhere that
 * can repair a tampered cutover flag).
 *
 * THE TRUST PROPOSITION, stated honestly. This value carries LESS trust than the
 * pin store it is copied from. The pin store's keyId is self-checking - it must
 * equal SHA-256(pubkey), and the enclave verify path recomputes that - whereas
 * this is a bare string with no accompanying pubkey to check it against, so
 * nothing here can prove it was ever a real key. All it gets is STRUCTURAL
 * validation (64 lowercase hex chars, the keyId shape), which is a filter on
 * garbage, not a proof of authenticity. It is written only on the user-present
 * revoke path from the pin store's own value.
 *
 * THE RESIDUALS, both directions, neither closable in the extension (there is no
 * in-extension secret to MAC this with - the enclave key is the host's):
 * - A tamperer who writes a DIFFERENT but validly-shaped keyId forces the next
 *   re-pair to read as "new": the ratchet resets, the latch clears, a corrupt
 *   cutover flag normalizes. That is bounded because it is equivalent to simply
 *   deleting bridgePolicyState outright, which the same tamperer can already do
 *   - it grants no capability the storage write itself did not.
 * - A tamperer who writes a non-string or a malformed string forces "not new":
 *   recovery stalls. That is DoS-equivalent to tampering the cutover flag, and
 *   it self-heals - the next revoke overwrites this key with the real pin.
 * Structural validation is what stops the WORSE case the shapeless version had:
 * any garbage string reading as a known prior, so the user's own SAME-key
 * re-pair looked new and silently reset the ratchet. */
type PriorPinRead = { kind: "known"; keyId: string } | { kind: "unknown" };

function classifyPriorPin(value: unknown): PriorPinRead {
  // Anything that is not a keyId-SHAPED string - absent, a number/object/array,
  // "", uppercase hex, or any other length - is unknown, which is fail-closed to
  // "not a new key" (latch kept, ratchet retained). KEY_ID_HEX is the single
  // shared keyId regex (keyId = lowercase-hex SHA-256 of the raw pubkey, so
  // exactly 64 hex chars), reused so this validator cannot drift from it.
  return typeof value === "string" && KEY_ID_HEX.test(value)
    ? { kind: "known", keyId: value }
    : { kind: "unknown" };
}

async function readPriorPin(): Promise<PriorPinRead> {
  const { [POLICY_PRIOR_PIN_KEY]: value } = await browser.storage.local.get(POLICY_PRIOR_PIN_KEY);
  return classifyPriorPin(value);
}

/** Read the cutover flag and the ratchet record from ONE storage snapshot
 * (E2F-5): the two facts are folded together by resolvePolicyState, and two
 * separate `get`s could tear (a pin transition or a partial write landing
 * between them), letting the fold reason over an inconsistent pair. One `get`
 * gives a single point-in-time view of both keys. */
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
  // The sticky in-life compromise latch (E2F-1) DOMINATES every persisted
  // fact: once a signature failed against the pin this SW life, no later valid
  // push, cutover value, stored record, or verified mark can resolve to
  // anything but compromised. This is what makes a replayed genuine frame -
  // which would otherwise verify and ratchet as an idempotent replay - unable
  // to reopen the barrier when the durable compromise persist failed.
  if (compromisedThisLife) return { kind: "compromised" };
  // One storage snapshot for both facts (E2F-5): the fold below reasons over
  // the cutover flag and the record together, so they must be read together.
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
  // Out of scope (a stale push that raced a re-pair, or a record left by a
  // different key): fail closed to awaitingBaseline. The old effective is NOT
  // enforced (deny baseline governs). A fresh in-scope push starts a new
  // ratchet only where the write is allowed to land: under a DIFFERENT pinned
  // key that is exactly the intended reset, while the UNPINNED scope over a
  // retained pinned-scope record is refused at writeStoredRecord (U1) - the
  // retained record is the same-key anti-replay anchor, never overwritable
  // by an unsigned document.
  if (!scopesEqual(recordScope, scope)) return { kind: "awaitingBaseline", scope };
  return { kind: "active", scope: recordScope, record: stored.record };
}

// ---- writers ------------------------------------------------------------------

/** Write the ratchet record. Returns whether a write actually landed, so the
 * commit-end undo (H5) can skip restoring a record it never replaced - an
 * unchanged-state push writes nothing, and a blind undo `set` would retrigger
 * every storage.onChanged consumer, breaking the setMirror discipline below. */
async function writeStoredRecord(next: StoredPolicyState): Promise<boolean> {
  const stored = await readStoredRecord();
  // Refuse to overwrite a corrupt read (E2F-5): a corrupt record is the
  // latched-closed state, and a push silently replacing it would be exactly
  // the finding-3 fail-open (an older baseline landing as first-ever over
  // tampering evidence). Recovery is a re-pair, which removes the key
  // directly, never a push. Throwing aborts the accept path fail-closed; the
  // read-time latch in resolvePolicyState is the primary guard and this is the
  // torn-read backstop.
  if (stored.kind === "corrupt") {
    throw new Error("refusing to overwrite a corrupt policy record");
  }
  // Refuse to replace a retained PINNED-scope record with an unsigned one
  // (U1). onPinRevoked deliberately RETAINS the pinned record so a same-key
  // re-pair still refuses an old-baseline replay (finding 2); the record is
  // merely INERT (out of scope) while unpinned, not disposable. Without this
  // rule an attacker could push an unsigned "restriction" during the
  // unpinned window, ride the user's approval (a policy-VALUES approval,
  // never an anchor-disposal warrant) to overwrite the anchor, and after the
  // user re-pairs the SAME key replay an old, more-permissive genuinely
  // signed baseline as first-ever with zero fresh presence. Consequence,
  // accepted as fail-closed: after a revoke the unpinned lane cannot store
  // ANY document until a re-pair disposes of the pinned record (a new key
  // clears it; the same key puts it back in scope) - the machine stays
  // barrier-closed rather than trade the anchor away.
  if (next.scope === null && stored.kind === "valid" && stored.record.scope !== null) {
    throw new Error(
      "refusing to replace a retained pinned-scope policy record with an unsigned one",
    );
  }
  // Unchanged state writes nothing (the kill.ts setMirror discipline): `at`
  // means "when the state last CHANGED", and an idempotent rewrite would
  // retrigger every storage.onChanged consumer on the steady-state
  // push-on-connect replay. Scope is part of identity here.
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

/** Is `a` EXACTLY the record `b` describes, `at` stamp included? The ownership
 * test the commit-end undo uses (H4): an undo may only touch the record the
 * push itself wrote, never whatever a newer pin transition or push has since
 * put there. */
function sameStoredRecord(a: StoredPolicyState, b: StoredPolicyState): boolean {
  return (
    a.scope === b.scope &&
    a.revision === b.revision &&
    a.baselineB64 === b.baselineB64 &&
    a.at === b.at &&
    policyValuesEqual(a.effective, b.effective)
  );
}

/** Undo a stale commit-end record write (F3), ownership-checked (H4).
 *
 * Only ever acts when the CURRENT stored record is byte-for-byte the one this
 * push wrote; anything else means a newer transition or push owns the slot now,
 * and leaving it alone (including leaving it ABSENT) is correct. When a ratchet
 * RESET ran while this push was in flight the pre-write record was deliberately
 * deleted, so restoring it would resurrect a dead anchor (the A->B->A case) -
 * remove instead, landing in awaitingBaseline (deny baseline + closed barrier).
 * Corrupt is NEVER folded into absent (H3): it throws, the torn-read-backstop
 * posture armCutover and writeStoredRecord already take. */
async function undoRecordWrite(
  written: StoredPolicyState,
  prior: StoredRead,
  resetGenerationAtWrite: number,
): Promise<void> {
  const now = await readStoredRecord();
  if (now.kind !== "valid" || !sameStoredRecord(now.record, written)) return;
  // Re-check the reset epoch here, right after the awaited read above: a reset
  // can complete DURING that read, and restoring the pre-write record after one
  // would resurrect the dead anchor the reset deleted - so remove instead.
  // THE LAST WINDOW, named: browser.storage.local has no transaction, so the
  // microtask gap between this check and the set() below cannot be closed in
  // user space. It is one-directional: a reset arriving inside it degrades to a
  // restore that a subsequent transition's own removal supersedes, never to a
  // wrong novelty decision or an opened barrier.
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
  // Refuse to overwrite a corrupt read (E2F-5): laundering a tampered flag
  // into a clean `true` would erase the tampering evidence that
  // resolvePolicyState latches on. resolvePolicyState already refused this
  // push (corrupt cutover -> compromised) before the accept path reached here;
  // this is the torn-read backstop, and throwing keeps the accept fail-closed.
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
  // The sticky in-life latch first (E2F-1): a signature failure this SW life
  // refuses everything, whatever the cutover/pin/record say.
  if (compromisedThisLife) return { allowed: false, reason: COMPROMISED_LIFE_REASON };
  const scope = await currentScope();
  const state = await resolvePolicyState(scope);
  if (state.kind === "legacy") return { allowed: true };
  if (state.kind === "compromised") return { allowed: false, reason: LATCHED_REASON };
  // awaitingBaseline | active: the barrier opens only for an ACTIVE (in-scope)
  // record when THIS connection verified a push under the current scope AND the
  // current pin generation (E2F-2: a stale verified mark from before an ABA
  // same-key re-pair carries the old generation and no longer opens the gate).
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

/** The persisted posture, typed so a BLOCKED state is not consumable as
 * policy values (SFX-1): awaitingBaseline and compromised carry a reason,
 * never a PolicyValues, so no enforcement caller can mistake the deny
 * baseline for an applicable policy outside the dispatch barrier.
 * effective-policy.ts folds `legacy` with the legacy settings read; every
 * enforcement site consumes ITS state-typed wrapper, not this directly. */
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

export interface PolicySnapshot {
  /** True once the first policy push was ever accepted (one-way); also true
   * while a corrupt flag/record has latched the state closed. */
  cutover: boolean;
  /** The post-cutover effective policy: the stored ratcheted effective while
   * ACTIVE, otherwise the frozen deny baseline. In the awaitingBaseline and
   * compromised arms the dispatch barrier refuses every request, so nothing
   * ever enforces against this fallback - POLICY_DEFAULTS is the deny baseline
   * on the four capability grants but NOT the restrictive pole on every field
   * (hostReverifyMs/disabledTools/ms-windows), and it is safe here only
   * because the barrier, not this value, is what fails those states closed.
   * Pre-cutover (`cutover:false`) the consumer reads the legacy local settings
   * instead. */
  effective: PolicyValues;
}

/** The RAW two-field view, for tests and diagnostics that pin the stored
 * values directly. Enforcement callers must use getPolicyPosture (via
 * effective-policy.ts): this shape folds the blocked states into
 * POLICY_DEFAULTS, which only the dispatch barrier makes safe. */
export async function getPolicySnapshotForTests(): Promise<PolicySnapshot> {
  const state = await resolvePolicyState(await currentScope());
  if (state.kind === "active") return { cutover: true, effective: state.record.effective };
  return { cutover: state.kind !== "legacy", effective: POLICY_DEFAULTS };
}

/** The valid persisted record, or null (absent or corrupt). A raw accessor
 * for tests and diagnostics; scope-aware enforcement goes through
 * resolvePolicyState, not this. */
export async function getStoredPolicyState(): Promise<StoredPolicyState | null> {
  const stored = await readStoredRecord();
  return stored.kind === "valid" ? stored.record : null;
}

// ---- pin lifecycle hooks (called from enrollment.ts) ----------------------------

/** A key was (re-)pinned (ADR-0032 decision 3). THE NOVELTY RULES, stated once:
 *
 * - Key-novelty is decided from the PRIOR PIN IDENTITY - the durable prior
 *   written at revoke (H1), falling back to this life's mirror - and NEVER from
 *   the stored record's scope (F2): a same-key re-pair whose record is absent or
 *   corrupt must not be misread as a new key.
 * - A CONFIRMED different prior keyId is the ONLY thing that resets the ratchet,
 *   clears the in-life compromise latch (E2F-1), normalizes a corrupt cutover
 *   flag (E2F-4), and bumps ratchetResetGeneration.
 * - An equal prior keyId RETAINS the anchor, which is what refuses an old
 *   permissive baseline from replaying after a revoke+re-pair with zero fresh
 *   presence (finding 2).
 * - An UNKNOWN prior (no durable prior and a fresh SW mirror - e.g. a first-ever
 *   pairing) is fail-closed to "not new": latch kept, ratchet retained.
 *
 * Always drops this connection's verified mark so the barrier re-verifies under
 * the new pin, and always bumps the generation epoch (E2F-2). NEVER clears an
 * armed cutover: post-reset the deny baseline plus the barrier govern until the
 * first baseline verifies under the new pin, never the legacy settings again. */
export async function onPinPinned(newKeyId: string): Promise<void> {
  // Bump the generation epoch FIRST, synchronously (E2F-2): a push in flight
  // must observe that the pin moved even when the new keyId equals the old.
  pinGeneration += 1;
  // The durable prior wins over this life's mirror: it is the one that survives
  // the SW restart that so often falls between the revoke and the re-pair.
  const durablePrior = await readPriorPin();
  const priorKeyId = durablePrior.kind === "known" ? durablePrior.keyId : lastPinnedKeyId;
  const isNewKey = priorKeyId !== null && priorKeyId !== newKeyId;
  lastPinnedKeyId = newKeyId;
  if (isNewKey) {
    ratchetResetGeneration += 1;
    await browser.storage.local.remove(POLICY_STATE_KEY);
    // A NEW-key re-pair is fresh, presence-verified evidence the substituted
    // signer is gone: clear the in-life compromise latch (E2F-1). The ONLY
    // place it is cleared within a SW life.
    compromisedThisLife = false;
    // Recover from a CORRUPT cutover flag (E2F-4): resolvePolicyState checks
    // cutover-corruption FIRST, so a tampered flag latches the state closed
    // forever, and LATCHED_REASON promises re-pair recovery - this normalize is
    // the only writer anywhere that can honour that promise (armCutover throws
    // on corrupt). Normalize the tampered value to its one-way armed value
    // (`true`) - not clear it - so recovery lands in awaitingBaseline (deny
    // baseline + closed barrier), preserving the one-way cutover rather than
    // falling back to legacy.
    if ((await readCutover()) === "corrupt") {
      await browser.storage.local.set({ [POLICY_CUTOVER_KEY]: true });
    }
  }
  // Consume the prior LAST, only once the reset above has fully landed: an SW
  // death mid-reset must not leave the prior already consumed and the recovery
  // half-done, which would strand the user in the latched state the re-pair was
  // meant to clear. Re-reading a not-yet-consumed prior is safe because every
  // route back into onPinPinned - another revokePin, or approvePending
  // proceeding when the pin record stops parsing (corrupt/tampered) - requires a
  // full presence ceremony (Touch ID), so no same-user process can turn a
  // stranded stale prior into a silent novelty decision; and the revokePin route
  // additionally overwrites the prior with the real current pin before it could
  // ever be re-read.
  //
  // The remaining window, named: there is no restart-reconciliation hook, so an
  // SW death between the reset and this remove leaves the prior in place. The
  // worst case is one extra revoke+re-pair cycle for the user - never a wrong
  // novelty decision, and never a state that fails open.
  await browser.storage.local.remove(POLICY_PRIOR_PIN_KEY);
  if (port) {
    port.policy = { kind: "awaiting" };
    // Identity proof is bound to the pin it was earned under: the generation
    // stamp already makes it inert, this keeps the state honest too.
    port.identity = { kind: "unproven" };
  }
}

/** The pin was revoked (ADR-0032 decision 3). RETAINS the ratchet record so a
 * same-key re-pair still refuses an old-baseline replay (finding 2); the
 * scope check keeps the retained record inert (deny baseline + closed
 * barrier) while unpinned, and writeStoredRecord's pinned-anchor preservation
 * rule (U1) is what makes the retention REAL rather than assumed: no unsigned
 * push - approved or not - can replace the retained record during the
 * unpinned window. Drops this connection's verified mark so no op runs
 * under a stale policy after the pin moved. NEVER clears cutover, and NEVER
 * clears the in-life compromise latch (only a NEW-key re-pair does, E2F-1).
 *
 * `revokedKeyId` is the keyId that was pinned, read by the caller BEFORE it
 * clears the pin store, and persisted here as the durable prior identity the
 * next onPinPinned decides novelty against (H1). `null` means no key was pinned:
 * there is nothing to record, and any existing durable prior is deliberately
 * LEFT intact rather than cleared - clearing it would strand the recovery path
 * exactly as the missing-durable-prior regression did. */
export async function onPinRevoked(revokedKeyId: string | null): Promise<void> {
  // Bump the generation epoch synchronously (E2F-2), so the second leg of an
  // ABA same-key revoke+re-pair is distinguishable from the pre-revoke pin.
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

// ---- Lane U's seam: the unpinned window-approval surface -------------------------

export interface UnpinnedRelaxation {
  /** The folded effective values (baseline + overlay) awaiting approval,
   * handed over as a frozen copy. The parsed document itself is deliberately
   * NOT part of this payload (U4): the approver's job is to present the
   * values this push would enforce, and handing it a live reference to
   * anything the commit later consumes would widen the seam for no need. */
  effective: PolicyValues;
  /** The stored effective it would relax (null = first document ever),
   * also a frozen copy. */
  storedEffective: PolicyValues | null;
}

export type UnpinnedRelaxationApprover = (relaxation: UnpinnedRelaxation) => Promise<boolean>;

let unpinnedApprover: UnpinnedRelaxationApprover | null = null;

/** Register the unpinned lane's approval surface (ADR-0032 decision 3): the
 * off-DOM confirmation window that holds an unpinned relaxation unapplied
 * until the user explicitly approves it. Lane U implements and registers it;
 * while none is registered, every unpinned relaxation - including the
 * first-ever document, which always rides this lane - is refused, fail closed.
 * Never consulted on a pinned extension (the no-downgrade rule). */
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

/** The unsigned push currently held at the Lane U approver, or null: its
 * baseline (b64), its overlay EXACTLY as parsed from the frame (as JSON text;
 * a byte-identical frame reproduces the same key order), and the attachment
 * it arrived on. Set around the approver await only. A frame is collapsed at
 * entry (U6) only when ALL THREE match - anything less is a distinct
 * candidate that must serialize on the frame chain (UF-1): a different
 * overlay is a TIGHTENING that must not be lost (the overlay only ever
 * restricts), and a different attachment is a reconnect's push-on-connect
 * that must run so the NEW connection can earn its own verified mark. */
let pendingApproval: {
  baselineB64: string;
  overlayJson: string;
  attachment: PortAttachment | null;
} | null = null;

/** Route one inbound policy/lang frame. The connection it arrived on is
 * captured synchronously: the verified mark must land on exactly that
 * attachment, so a reconnect that installs a fresh one mid-verification
 * stays unverified (its own connect push will open its barrier).
 *
 * RESIDUAL LAG, named (E2F-3, recorded in docs/security/threat-model.md's
 * "Host-owned policy (ADR-0032) residual ledger"): port.ts void-routes these frames (`void handlePolicyFrame(msg)`),
 * unsynchronized with the request queue - the same posture as the void-routed
 * kill frames. The frame chain and the request path share no counter, so
 * between a bad-signature push arriving and its signature verification
 * actually FAILING (a frameChain hop, two parses, a base64 decode, a pin
 * read, and an ECDSA verify later), requests already past the gate - plural;
 * nothing bounds them to one - can dispatch under the still-open barrier.
 * Two things bound this to a benign lag, not a hole:
 * - The COMPROMISE arm is closed hard: markPolicyCompromised sets the sticky
 *   in-life latch (E2F-1) SYNCHRONOUSLY the moment verification fails, before
 *   any further await, and the latch is read TWICE per request -
 *   resolvePolicyState folds it at the gate AND dispatch re-reads it at its
 *   own policy read - so a request must clear both reads before the failure
 *   lands, and no request that reaches either read AFTER verification fails
 *   can pass; a replayed genuine frame can never reopen the barrier.
 * - The requests that slip through ran under the stored effective policy
 *   (the ratcheted floor, never laxer than what the user last saw applied) -
 *   the policy the connection's own verified push was still advertising.
 * A synchronous verifying-hold (parking the request queue until the frame is
 * verified) is deliberately NOT built here - it is the identical trade-off the
 * void-routed kill frames already accepted. */
export function handlePolicyFrame(msg: unknown): Promise<void> {
  const attachment = port;
  // Collapse a TRULY IDENTICAL replay of the push currently held at the
  // approver (U6, keyed per UF-1): same baseline bytes, same overlay, same
  // attachment. The pending prompt's verdict covers exactly that candidate
  // (approval applies it; denial refuses it, and push-on-connect re-offers on
  // the next connection), so queueing another 120s prompt would only let a
  // hostile unpinned host occupy the confirmation FIFO. Anything less than a
  // full match serializes on the frame chain instead: a same-baseline push
  // with a DIFFERENT overlay is the host tightening mid-window (dropping it
  // would fail OPEN against that intent), and a push from a DIFFERENT
  // attachment is a reconnect's push-on-connect the new connection needs in
  // order to earn its own verified mark. RESIDUAL, named: pushes with
  // DISTINCT candidates still serialize one prompt each - the frame chain
  // bounds them to one at a time, and each denial is audited (U5), but a
  // hostile host can keep the FIFO busy for as long as the user keeps not
  // answering. Recorded in docs/security/threat-model.md under "Host-owned
  // policy (ADR-0032) residual ledger" (the confirmation-FIFO occupancy
  // entry), with its bounds.
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

/** A refusal changes nothing, and says so: the stored effective stays
 * enforced, the barrier stays closed, and the failure is surfaced rather than
 * smoothed over (ADR-0032 decision 4). The attack-shaped refusals (a rejected
 * policy CLAIM after crypto/ratchet reasoning) are also routed to the audit
 * ring as `policy_refused`; the benign shape/version-skew refusals are
 * console-only, so the ring stays a meaningful security trail. */
function refuse(why: string, opts: { audit?: boolean } = {}): void {
  console.warn("[bb] policy push refused:", why);
  if (opts.audit) auditEvent("policy_refused", { detail: why.slice(0, 512) });
}

/** A baseline signature failed against the pin (ADR-0031 posture): positive
 * evidence the signer does not hold the pinned key. Latch the sticky in-life
 * compromise flag SYNCHRONOUSLY (E2F-1) - before any await - so a replayed
 * genuine, byte-identical frame cannot ride the idempotent-replay path back to
 * a verified mark and reopen the barrier, even in the window before (or after
 * a FAILED) durable persist. Also synchronously drop THIS connection's
 * verified mark so the barrier closes immediately (finding 4), audit the
 * compromise, and latch the enrollment-side compromised mark. A failed persist
 * is fail-closed: the sticky latch and the dropped mark already shut the
 * barrier for this SW life, and the failure is surfaced loudly rather than
 * swallowed as best-effort.
 *
 * RESIDUAL, named (F1, recorded in docs/security/threat-model.md's
 * "Host-owned policy (ADR-0032) residual ledger"):
 * the E2F-1 sticky latch is IN MEMORY, so it cannot survive a failed
 * setCompromised persist AND a subsequent SW restart together. If the durable
 * mark never wrote (persist threw) and the SW then dies, the fresh SW starts
 * with compromisedThisLife=false and no durable mark, so a replayed genuine,
 * byte-identical frame verifies, ratchets as an idempotent replay, and reopens
 * the barrier. This residual is un-closable by an in-memory latch (that is what
 * "in memory" means). What bounds it:
 * (1) The barrier can only reopen to SOME genuine policy the pinned key signed
 *     at or above the stored revision - the attacker picks among the documents
 *     it captured, but cannot forge a fresh relaxation past the ratchet and the
 *     touched-set rule.
 * (2) Enclave re-attestation bounds it further ONLY when the user has opted
 *     into it: policy frames deliberately route BEFORE the gates (port.ts, and
 *     this module's header - decision 6 control-plane mode), ADR-0021 reconnects
 *     are not challenged by default (hostReverifyMs defaults to 0 = never
 *     re-verify), and the enrollment gate reads the DURABLE compromise mark -
 *     the very persist that failed in this residual's premise. With
 *     hostReverifyMs unset the residual stands on bound (1) alone.
 * Closing it fully needs a durable-write-before-proceed or a boot-time
 * re-attestation, not a wider in-memory latch - do NOT re-architect storage here.
 * Recorded in docs/security/threat-model.md under "Host-owned policy
 * (ADR-0032) residual ledger" (the compromise-mark persistence entry). */
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
  // The frame is R5-loose and its parse output RETAINS unknown keys: only the
  // named fields below may ever be read - never spread, iterate, or forward
  // the frame object.
  const { ok, baseline, sig, overlay, reason, error } = parsed.data;

  if (ok !== true || baseline === undefined) {
    // The Phase-4 migration trigger (ADR-0032 decision 8, D-P4-2): ONLY the
    // structured `reason:"absent"` - the host attests it has NO signed
    // baseline (it says nothing about receipts: the host derives the reason
    // from its policy store alone, so a routine re-push after our bag was
    // recorded still says absent; the durable send-once flag and the host's
    // first-bag-wins store make that re-offer a no-op) - may offer the
    // legacy bag, and the offer is further gated fail-closed inside (pinned
    // scope, fresh-nonce proof of the pin on THIS connection, the durable
    // send-once flag, pre-cutover posture). The frame schema already refused
    // any reason outside the enum, a reason on an ok:true frame, and an
    // ok:false frame without `error`; an old host that omits the field
    // entirely lands here as `undefined` and never triggers.
    if (reason === "absent") await offerLegacyBag(attachment);
    // The host reports no usable policy (or an ok:true frame arrived without
    // its baseline): nothing to verify, nothing changes, and this NEVER opens
    // the gate - a policy-capable peer gone silent or gone wrong reads as
    // "refuse".
    return refuse(`host provided no baseline${error ? ` (${error})` : ""}`);
  }

  let docBytes: Uint8Array;
  try {
    docBytes = base64Decode(baseline);
  } catch (e) {
    return refuse(`baseline is not canonical base64: ${e instanceof Error ? e.message : e}`);
  }

  // Snapshot the scope AND the generation epoch the push is evaluated under.
  // Captured HERE, re-checked at commit: a pin transition on enrollment's
  // separate queue between now and the write must not let this push land in the
  // wrong scope (finding 1), NOR resurrect a verified mark across an ABA
  // same-key revoke+re-pair that leaves the keyId equal (E2F-2). The pin OBJECT
  // is read once - its keyId is the scope identity, its pubkey is what the
  // signature is verified against (keyId = SHA-256(pubkey), so binding the
  // scope to the keyId binds it to the exact verifying key).
  const generationAtStart = pinGeneration;
  const pinAtStart = await getPin();
  const scopeAtStart: PolicyScope = pinAtStart
    ? { pinned: true, keyId: pinAtStart.keyId }
    : { pinned: false };
  if (pinAtStart) {
    if (sig === undefined) {
      // ADR-0032 decision 3, the no-downgrade rule between the lanes: a pinned
      // extension never accepts an unsigned baseline, from any frame, on any
      // platform, for any reason. A missing signature is a refusal, not crypto
      // evidence - nothing here proves who sent it.
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

  // The ratchet anchor is the ACTIVE (in-scope) stored record, resolved under
  // the snapshot scope. A corrupt store latches closed - a push cannot
  // silently "fix" it (that IS the finding-3 replay: an older baseline landing
  // as first-ever). awaitingBaseline/legacy carry no anchor (fresh ratchet).
  const state = await resolvePolicyState(scopeAtStart);
  if (state.kind === "compromised") {
    return refuse("stored policy state is corrupt; latched closed until re-pair", { audit: true });
  }
  const anchor = state.kind === "active" ? state.record : null;
  // The revision/touched ratchet binds only the PINNED scope: the signature is
  // what makes those fields mean anything (both live inside the signed bytes).
  // On the unpinned scope every field is attacker-writable, so enforcing the
  // pushed revision would hand any local forger a permanent denial lever: push
  // revision=MAX as a silent "restriction" and every later genuine unsigned
  // push is refused forever (unrecoverable without a pairing ceremony to reset
  // the scope). The unpinned lane's protections are the direction checks above
  // and the approval window below: replaying an old restricting document is
  // the harmless forged-restriction DoS decision 3 already concedes, and
  // replaying an old relaxing one costs the attacker a visible prompt -
  // exactly the ADR's stated bound. The anchor itself still matters unpinned:
  // it is what the direction/approval decisions compare against.
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
    // The unpinned lane (decision 3): a document that only restricts the
    // stored effective applies silently; a relaxation - and the first document
    // ever, which has no anchor and is by definition a relaxation candidate -
    // applies only on the user's explicit window approval. That surface is
    // Lane U's; until it registers the seam above, refuse, fail closed. The
    // approver await can be arbitrarily long (minutes); the commit recheck
    // below is what stops a pin that lands during that window from turning
    // this unsigned document into an enforced, barrier-opening policy. NOTE:
    // after a revoke, a RETAINED pinned-scope record is merely out of scope
    // here (anchor=null), not gone - an approved unsigned push then still
    // fails at writeStoredRecord's pinned-anchor preservation rule (U1), so
    // this lane cannot store anything until a re-pair disposes of that record.
    const needsApproval = !anchor || relaxedPolicyFields(effective, anchor.effective).length > 0;
    if (needsApproval) {
      // VALIDATE BEFORE PROMPT (UF-2): after a revoke, a RETAINED pinned-scope
      // record makes this push unstorable - writeStoredRecord's preservation
      // rule (U1) would refuse it at commit no matter what the user answers.
      // Consulting the approver first would burn a real approval gesture on a
      // push that can never apply, and the eventual write throw dies in
      // frameChain's catch unaudited. Refuse here instead, audited; the write
      // throw stays as the backstop for any interleave this read cannot see.
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
      // Latch the held candidate for the duration of the approver await (U6):
      // handlePolicyFrame collapses truly identical pushes (same baseline,
      // overlay, and attachment) at frame entry while this is set, so a
      // hostile host cannot stack N copies of one document into N sequential
      // occupations of the confirmation FIFO.
      pendingApproval = {
        baselineB64: baseline,
        overlayJson: JSON.stringify(overlay ?? null),
        attachment,
      };
      let approved: boolean;
      try {
        approved = await approver({
          // Frozen copies: the approver is Lane U's code, and the values it
          // sees must be exactly what this push commits - it cannot mutate the
          // object out from under the commit below (which recomputed none of
          // this).
          effective: freezePolicyValues(effective),
          storedEffective: anchor ? freezePolicyValues(anchor.effective) : null,
        }).catch(() => false);
      } finally {
        pendingApproval = null;
      }
      if (!approved) {
        // Audited (U5): one decline is a user choice, but repeated declines
        // are an attack signal - a hostile unpinned host grinding at the
        // approval window - and the ring is where that pattern shows.
        return refuse("unpinned relaxation not approved by the user", { audit: true });
      }
    }
  }

  // PRE-WRITE SCOPE + GENERATION RECHECK (finding 1, E2F-2). Re-read the
  // scope and compare the generation epoch AFTER the (possibly minutes-long)
  // approver await and before the writes: if the pin moved while this push was
  // in flight - a different scope (crucially including unpinned-at-snapshot
  // -> pinned-at-commit, which would otherwise commit an UNSIGNED document
  // under a just-pinned key and open the barrier, the no-downgrade violation),
  // OR an ABA same-key revoke+re-pair that left the keyId equal but bumped the
  // generation - drop the push, fail closed. A second recheck AFTER the writes
  // (below, F3) closes the narrower window of the writes' own awaits; the
  // read-time scope checks above are the backstop if a write ever still
  // slipped through.
  const scopeAtCommit = await currentScope();
  if (!scopesEqual(scopeAtCommit, scopeAtStart) || pinGeneration !== generationAtStart) {
    return refuse(
      "pin scope or generation changed while the push was in flight; dropping to stay fail-closed",
      { audit: true },
    );
  }

  // Arm cutover BEFORE the record write (fail-closed ordering, above). Arming
  // is monotonic (false->true, one-way) so a stale arm is harmless. Then write
  // the scope-stamped record.
  await armCutover();
  // Capture the reset epoch BEFORE the awaited prior-snapshot read: a reset that
  // completes DURING that read would otherwise leave the undo comparing equal
  // epochs and restoring an anchor the reset just deleted. Capturing early can
  // only turn a restore into a remove, which is the fail-closed direction.
  const resetGenerationAtWrite = ratchetResetGeneration;
  // Snapshot the record as it stands BEFORE our write, so a race detected AFTER
  // the write can be UNDONE by restoring exactly it (F3) - restoring rather than
  // dropping the anchor, which would reopen the old-baseline replay (finding 2).
  // The one case that deliberately removes instead is a ratchet RESET landing
  // mid-flight: the snapshot is then a DEAD anchor that must not come back (H4).
  // resolvePolicyState already refused a corrupt record above, so this is `valid`
  // (the active anchor) or `absent`.
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
  // COMMIT-END SCOPE + GENERATION RECHECK (F3). armCutover and writeStoredRecord
  // above are awaited, so an ABA revoke+re-pair on enrollment's separate queue
  // can still move the pin AFTER the pre-write recheck. Re-read the scope and
  // compare the generation ONE more time, right before stamping the mark: if
  // either moved, this record and its would-be verified mark are stale. The
  // stale mark is already inert (the gate rejects a generation mismatch), but
  // the stale RECORD could later resurrect as a ratchet anchor under a same-key
  // ABA - so undo the write (ownership-checked) and do NOT stamp the mark.
  const scopeAtEnd = await currentScope();
  if (!scopesEqual(scopeAtEnd, scopeAtStart) || pinGeneration !== generationAtStart) {
    // Nothing to undo when the write was suppressed as unchanged (H5): a blind
    // re-set would retrigger every storage.onChanged consumer. The `wrote` flag
    // is the PRIMARY guard here - exact and timing-independent, since a
    // suppressed write set nothing at all, so there is nothing to undo. The
    // ownership `at`-comparison in undoRecordWrite is only a BACKSTOP: it would
    // also refuse (a suppressed write kept the stored record's OLD `at`, which
    // differs from `committed`'s fresh one) EXCEPT in a same-millisecond
    // collision where the two `at`s coincide - which is exactly why the flag,
    // not the backstop, is what makes this correct. The undo is also wrapped so
    // it can NEVER swallow the refusal: an exception escaping here would skip
    // refuse() and its policy_refused audit entirely, since frameChain's catch
    // is silent (H4).
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
  // The mark carries the snapshot scope AND generation - both still equal the
  // commit values, so the mark is honest. Stamping the generation (E2F-2) means
  // a stale continuation from a prior generation cannot resurrect a verified
  // mark the dispatch gate would honor. ATTACHMENT RECHECK (UF-1): the mark
  // lands only when the attachment this frame arrived on is STILL the current
  // port attachment. A reconnect mid-flight makes the captured attachment a
  // dead object - stamping it would verify a connection that no longer exists
  // while the LIVE one earned nothing - so stamp no mark at all, fail closed:
  // the record itself is sound (in-scope, ratcheted) and stays applied, and
  // the new connection's own push-on-connect earns its own mark.
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

// ---- the legacy-settings send-once (ADR-0032 decision 8, Phase 4) ---------------
//
// The one frame this module sends: `legacy_settings { bag }`, the snapshotted
// legacy settings offered to a host that attests it has no policy store
// (`reason:"absent"`), so the app's first-run import screen can show them and
// the user can sign revision 1. The host only records it (pending_import.rs,
// first-bag-wins, never applied), sends no reply, and none is awaited.
//
// THE GATE, fail-closed on every ambiguity (decision 8 + the p4-host review
// refinement): the bag ships ONLY when ALL of
//   - trust storage is verifiably confined to extension contexts this SW
//     life (hardenStorageAccess, ADR-0027 #32): every fact below - the
//     compromise mark, the pin, the flag, the bag itself - is read from
//     storage a content script could otherwise have written. Policy frames
//     route BEFORE the enrollment gate (decision 6 control-plane mode), so
//     this path must await the restriction itself rather than assume the
//     gate already did;
//   - NEITHER compromise signal is set: the in-life policy latch
//     (compromisedThisLife) NOR the durable enclave mark (getCompromised) -
//     a failed presence or verify proof latches the DURABLE mark without
//     touching the in-life policy latch, and a proof stamped before that
//     failure must not outlive it;
//   - the durable send-once flag is unset (legacy-import.ts: once sent, sent
//     forever - no revoke, re-pair, or disposal resets it; a re-send is the
//     replant vector the host's consumed tombstone refuses, so the extension
//     refuses it symmetrically);
//   - the current scope is PINNED, and THIS connection carries a fresh-nonce
//     proof of possession of exactly that pinned key (AttachmentIdentity),
//     whose challenge went out under the CURRENT pin epoch:
//     a substituted host reporting `reason:"absent"` to harvest the bag can
//     neither produce the proof nor inherit one (proof and report are both
//     per-attachment; a reconnect starts clean). Decision 8's "a
//     policy-capable host has identified itself" is deliberately read as
//     this cryptographic identification, not as "sent a well-formed frame";
//   - the resolved policy state is `legacy` (pre-cutover): that is the only
//     state in which the bag IS the governing settings worth importing -
//     post-cutover, awaiting, or compromised states ship nothing;
//   - the connection is still the live one after every await.
//
// An `absent` report with no proof yet does not die: it latches
// `absentReported` on the attachment, and notePinProvenOnConnection completes
// the send when the proof lands later on the SAME connection (in practice:
// the opt-in hostReverifyMs re-verify, options' "Verify now", or the first
// presence-confirmed action). The next connect's push-on-connect re-offers
// either way, so a missed pairing costs latency, never the migration.

/** An opaque handle to the CURRENT connection, for callers that verify a
 * proof asynchronously: capture it when the challenge goes OUT, hand it back
 * with the verified result, and notePinProvenOnConnection stamps the proof
 * only if that exact connection is still the live one - proof earned on a
 * dead connection credits nobody. */
export function currentConnectionToken(): object | null {
  return port;
}

/** The pin epoch right now. Captured by evidence callers when their round
 * STARTS - enrollment at challenge send, presence at round claim (two awaits
 * before its challenge posts; that asymmetry fails closed, see
 * notePinProvenOnConnection) - and handed back with the verified proof:
 * notePinProvenOnConnection stamps THAT epoch, never the live one, so a
 * re-pair during the challenge window cannot promote old-epoch evidence. */
export function currentPinGeneration(): number {
  return pinGeneration;
}

/** Record a fresh-nonce, pin-verified proof of possession for the connection
 * `token` names (enrollment verify ceremony, presence round).
 * `generationAtChallenge` is the pin epoch the caller captured when its
 * round started (currentPinGeneration): enrollment captures it at
 * challenge-send time, presence at round CLAIM - two awaits before its
 * challenge actually posts. That asymmetry fails closed: an epoch move
 * landing between the presence claim and its challenge send only makes this
 * function discard evidence that was in fact earned under the current pin -
 * it can never smuggle old-epoch evidence in. A proof whose challenge
 * predates a pin move proves the OLD pin's holder, so a moved epoch refuses
 * the stamp outright - even a same-key revoke+re-pair that leaves the keyId
 * equal. No-op unless that connection is still the live attachment.
 * Completes a pending absent-report send, serialized on the frame chain so
 * it cannot interleave with a push (or a second send) in flight. */
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
  // Every fact below lives in extension storage: confirm it is confined to
  // extension contexts THIS SW life before believing any of it (#32). This
  // path is NOT behind the enrollment gate (policy frames route before it,
  // decision 6), so the restriction is awaited here, fail-closed on failure.
  if (!(await hardenStorageAccess()).ok) return;
  // The DURABLE enclave compromise mark, not just the in-life policy latch:
  // a failed presence or verify proof latches only the durable mark, and a
  // proof stamped on this connection BEFORE that failure must not ship the
  // bag after it.
  if (await getCompromised()) return;
  const scope = await currentScope();
  // Pinned, and the proof names exactly the currently pinned key. The
  // unpinned lane never sends: with no pin there is no mechanism that could
  // identify the peer, and fail-closed beats convenient (decision 8's
  // unpinned machines simply keep their legacy settings until pairing).
  if (!scope.pinned || scope.keyId !== proof.keyId) return;
  if (await getLegacySettingsSent()) return;
  // Pre-cutover only: `legacy` is the one state whose bag is the governing
  // settings. awaitingBaseline/active mean cutover happened (the bag is
  // history, not policy); compromised ships nothing to a suspect peer.
  const state = await resolvePolicyState(scope);
  if (state.kind !== "legacy") return;
  const bag = await readLegacySettingsBag();
  // The reads above awaited: re-check the connection and the pin epoch so a
  // reconnect or re-pair mid-flight cannot receive a bag gated on the OLD
  // connection's proof, AND both compromise marks - a durable mark landed by
  // a failing presence/verify proof during those awaits bumps neither the
  // generation nor the attachment, so only this commit-point recheck can see
  // it before the bag ships.
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
