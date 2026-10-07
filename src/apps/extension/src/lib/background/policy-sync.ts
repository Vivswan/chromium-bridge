// The extension side of host-owned policy: `policy_current` pushes are verified against the extension's OWN pinned
// key, ratcheted, stored as the effective policy behind a one-way cutover flag, and gate each connection through the
// dispatch barrier enrollment.ts consults. `lang_current` rides the separate language lane below.
//
// A push is consumed only in this order, and the frames carry no key identity the extension honors:
//   strict frame parse -> signature over the EXACT decoded bytes against the PINNED key -> strict PolicyDocSchema parse of those bytes
// A refusal changes nothing stored; only a signature failure drops a connection's verified mark and latches the SW life
// (markPolicyCompromised). The ratchet rules live at handlePolicyCurrent, the retained-record rule at writeStoredRecord.
//
// Every ratchet state is bound to a PolicyScope (the pinned keyId, or the unpinned lane): a record or verified mark
// whose scope no longer matches the current pin is inert, so a push that raced a re-pair, or an old baseline replayed
// after a same-key revoke+re-pair, cannot be enforced. resolvePolicyState folds the persisted facts into one arm.
//
// port.ts drives `collaborator` BEFORE the request parse and the kill and enrollment gates, so a killed bridge still
// consumes pushes; frames process strictly in arrival order. This module sends only `lang_set`, and only on a
// connection whose host already pushed `lang_current`.

import {
  KEY_ID_HEX,
  type PolicyInboundFrame,
  PolicyInboundFrameSchema,
  type StoredPolicyState,
  StoredPolicyStateSchema,
} from "@chromium-bridge/shared/enclave";
import {
  LangCurrentFrameSchema,
  type LangSetWire,
  PolicyCurrentFrameSchema,
} from "@chromium-bridge/shared/generated/envelope";
import { PolicyDocSchema, type PolicyValues } from "@chromium-bridge/shared/generated/policy";
import {
  foldPolicyOverlay,
  policyValuesEqual,
  policyValuesFrom,
  relaxedPolicyFields,
} from "@chromium-bridge/shared/policy-compare";
import { SettingsSchema, type UiLanguageValue } from "@chromium-bridge/shared/settings";
import { unreachable } from "@chromium-bridge/shared/util";
import pLimit from "p-limit";
import { browser } from "wxt/browser";
import { z } from "zod";
import { inLife } from "../shared/in-life";
import { readKey, readKeyOr, readKeys, type Stored } from "../shared/read-key";
import { auditEvent } from "./audit-log";
import type { Connection, PortCollaborator } from "./connection";
import { getPin, setCompromised } from "./enclave-pin";
import { base64Decode, verifyPolicySignatureAgainstPin } from "./enclave-verify";

const POLICY_STATE_KEY = "bridgePolicyState";
const POLICY_CUTOVER_KEY = "bridgePolicyCutover";

/** The keys an accepted push writes; cdp/registry.ts watches them to re-evaluate cdpMode and tear down live sessions. */
export const POLICY_STORAGE_KEYS = [POLICY_CUTOVER_KEY, POLICY_STATE_KEY] as const;
const POLICY_PRIOR_PIN_KEY = "bridgePolicyPriorPin";

// ---- in-life latches (SW-lifetime, in memory only) ----------------------------
//
// Each holds a fact a persisted read cannot: it survives the awaits within one service-worker life and resets on SW
// death, when the durable compromise mark, the durable prior pin, and the stored ratchet re-derive the posture.

/** Set SYNCHRONOUSLY by markPolicyCompromised before any await, so a failed setCompromised persist cannot leave a
 * barrier that a replayed byte-identical genuine frame would reopen. Cleared within a life only by onPinPinned's
 * new-key path. */
const compromisedThisLife = inLife(() => false);

/** Bumped synchronously by onPinRevoked and onPinPinned BEFORE their awaits, so an in-flight push detects a pin move
 * even when the keyId comes back equal (a same-key revoke+re-pair). The commit-end undo relies on onPinPinned's order:
 *   pinGeneration += 1 -> ratchetResetGeneration += 1 -> storage.remove(POLICY_STATE_KEY) */
const pinGeneration = inLife(() => 0);

/** This life's mirror of the prior pin identity, a fast path behind the DURABLE prior (POLICY_PRIOR_PIN_KEY), which
 * is consulted first. onPinPinned owns the novelty rules. */
const lastPinnedKeyId = inLife<string | null>(() => null);

/** Bumped only by onPinPinned's new-key reset. After a reset ran mid-push, restoring the pre-write record would
 * resurrect the anchor the reset deleted, so the commit-end undo removes instead. */
const ratchetResetGeneration = inLife(() => 0);

// ---- the ratchet scope --------------------------------------------------------

/** The identity a ratchet state is bound to. Two states share a ratchet only when their scopes are
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

/** The scope the CURRENT pin defines, read fresh at every trust decision: a pin transition runs on enrollment's
 * separate queue, not this module's frame lane, and must be observed the instant it lands. */
async function currentScope(): Promise<PolicyScope> {
  const pin = await getPin();
  return pin ? { pinned: true, keyId: pin.keyId } : { pinned: false };
}

/** A frozen shallow clone for the unpinned approver: it sees exactly what this push commits and cannot mutate it. */
function freezePolicyValues(values: PolicyValues): PolicyValues {
  const clone: PolicyValues = { ...values, disabledTools: [...values.disabledTools] };
  Object.freeze(clone.disabledTools);
  Object.freeze(clone);
  return clone;
}

// ---- port plumbing (mirrors presence.ts) --------------------------------------

/** What THIS connection has earned, a fresh record per onAttach so a reconnect inherits nothing. The verified arm
 * carries scope and generation so the barrier closes the instant the pin moves away from either. */
type ConnectionPolicy =
  | { kind: "awaiting" }
  | { kind: "verified"; scope: PolicyScope; generation: number };

/** The live connection and the latches that belong to it. Only the `lang_set` send below ever posts through it. */
interface LiveConnection {
  readonly conn: Connection;
  policy: ConnectionPolicy;
  /** The host has pushed a schema-valid `lang_current` on THIS connection: the never-speak-first gate for `lang_set`,
   * so an old host that would fatally forward a language frame never sees one. */
  langSeen: boolean;
  /** The adoption `lang_set` already went out on THIS connection, however many seq:0 pushes the host repeats. */
  langAdoptionOffered: boolean;
}

const live = inLife<LiveConnection | null>(() => null);

export const collaborator: PortCollaborator = {
  onAttach(conn) {
    live.value = {
      conn,
      policy: { kind: "awaiting" },
      langSeen: false,
      langAdoptionOffered: false,
    };
    // The apply cursor is per-connection too: a departed peer's {value, seq:MAX} must not suppress the genuine host's
    // lower seq on the next connection.
    lang.value = null;
  },
  onDetach() {
    live.value = null;
  },
  onFrame(msg) {
    if (!isPolicyFrame(msg)) return false;
    void handlePolicyFrame(msg);
    return true;
  },
};

// ---- lang_current: the shared-language lane --------------------------------------
//
// A storage.onChanged listener cannot tell a user's write from an applied push, so emission never hangs off storage
// events and a set-push-apply cycle emits exactly one `lang_set`:
//   APPLY     host -> extension   writes only the `uiLanguage` key (the i18n watcher swaps locales); never emits
//   CHOOSE    extension -> host   chooseLanguage, from the options picker's gesture only; the host's echo returns via APPLY
//   ADOPTION  extension -> host   seq:0 means the host value was never set; an explicitly-set local value is offered once
//
// The trust bar is PINNED: a hostile PAIRED host flipping the UI language is an accepted cosmetic nuisance.

const UI_LANGUAGE_KEY = "uiLanguage";

/** The last applied host push on the CURRENT connection; its `seq` is the apply cursor (only a strictly greater push
 * applies). In memory and reset by onAttach on purpose: the host re-pushes on every connect, and a persisted cursor
 * would read that equal-seq push as already applied and suppress the repair of a stale local pick. */
const lang = inLife<{ value: string; seq: number } | null>(() => null);

/** Tests only. */
export function getLangState(): { value: string; seq: number } | null {
  return lang.value;
}

/** The lane's trust bar: PINNED, read fresh at every decision. */
async function langLanePinned(): Promise<boolean> {
  return (await currentScope()).pinned;
}

// Its default never fires here: readKey classifies an absent record before parsing, and a frame value is a string.
const UiLanguageSchema = SettingsSchema.shape.uiLanguage;

/** The frame schema pins only the shape, so the enum check is the consumer's job: out-of-enum is refused and the
 * current value stands. */
function isSharedLanguage(value: string): value is UiLanguageValue {
  return UiLanguageSchema.safeParse(value).success;
}

/** The APPLY path plus the adoption offer. The ONLY emit here is the once-per-connection adoption send for seq:0;
 * it runs on the frame lane, so applies and sends never interleave. */
async function handleLangCurrent(msg: unknown, attachment: LiveConnection | null): Promise<void> {
  const parsed = LangCurrentFrameSchema.safeParse(msg);
  if (!parsed.success) {
    console.warn("[bb] dropping malformed lang_current frame");
    return;
  }
  // A schema-valid frame proves the peer handles the lane (never-speak-first); the VALUE is judged separately.
  if (attachment) attachment.langSeen = true;
  // Unpaired: the push is ignored entirely and the adoption latch stays unset, so a first pairing can still import.
  if (!(await langLanePinned())) return;
  const { value, seq } = parsed.data;
  if (seq === 0) {
    // seq 0 = never explicitly set host-side: nothing to apply, but the first-pairing adoption trigger.
    await maybeAdoptExtensionLanguage(attachment);
    return;
  }
  // Only a strictly newer push applies; an echo or replay has nothing to ride on.
  if (lang.value && seq <= lang.value.seq) return;
  // Refused WITHOUT advancing the cursor, so a later genuine push with the same seq still applies.
  if (!isSharedLanguage(value)) {
    console.warn("[bb] refusing lang_current outside the shared language enum");
    return;
  }
  // Skip the write when storage already agrees: the push-on-connect replay must not retrigger the i18n watcher.
  const stored = await readKey(UI_LANGUAGE_KEY, UiLanguageSchema);
  if (stored.state !== "valid" || stored.value !== value) {
    await browser.storage.local.set({ [UI_LANGUAGE_KEY]: value });
  }
  // onAttach resets the cursor off the frame lane: a dead connection's push must not re-commit over the new one.
  if (attachment !== live.value) return;
  // Committed only once the write held, so the host's same-seq replay can still repair stale storage.
  lang.value = { value, seq };
}

/** The one sanctioned non-gesture `lang_set`: seq:0 says the host value was never set, so an explicitly-set local
 * uiLanguage (raw key present and in-enum) is offered once per connection. Terminates by construction: the host's reply
 * push carries seq >= 1 and returns through the non-emitting apply path.
 *   host repeats seq:0  -> one offer per connection (langAdoptionOffered)
 *   reconnect           -> re-offers; a missed adoption costs latency, never the import */
async function maybeAdoptExtensionLanguage(attachment: LiveConnection | null): Promise<void> {
  if (!attachment || attachment !== live.value) return;
  if (attachment.langAdoptionOffered) return;
  // A real push already applied: the host HAS an explicit value, so a later seq:0 is noise.
  if (lang.value !== null) return;
  const stored = await readKey(UI_LANGUAGE_KEY, UiLanguageSchema);
  if (stored.state !== "valid") return;
  // Re-checked after the await: a reconnect mid-read must not ride the dead attachment's offer.
  if (attachment !== live.value) return;
  attachment.langAdoptionOffered = true;
  attachment.conn.post({ type: "lang_set", value: stored.value } satisfies LangSetWire);
}

/** The only gesture-driven `lang_set` (the options picker's `lang_choose`; its local write keeps the UI responsive
 * offline). Serialized on the frame lane and gated on PINNED plus `langSeen`; otherwise the choice stays local and
 * the host's next push-on-connect re-asserts its truth. Resolves with whether a frame was posted. */
export function chooseLanguage(value: UiLanguageValue): Promise<boolean> {
  const send = frames.value(async () => {
    const attachment = live.value;
    if (!attachment?.langSeen) return false;
    if (!(await langLanePinned())) return false;
    // The pinned read awaited: only the still-live attachment may emit.
    if (attachment !== live.value) return false;
    return attachment.conn.post({ type: "lang_set", value } satisfies LangSetWire);
  });
  void send.catch((e) => {
    console.warn("[bb] lang_set send failed", e);
  });
  return send;
}

// ---- the persisted reads (each caller's own collapse of the one reader's three outcomes) ----

/** `corrupt` (present but not exactly `true`) is tampering and must not read as armed or unarmed: it latches closed.
 * Written only as `true`; only onPinPinned's new-key path touches a corrupt flag, rewriting it to `true`. */
type CutoverRead = "unarmed" | "armed" | "corrupt";

const CutoverFlagSchema = z.literal(true);

function cutoverRead(stored: Stored<true>): CutoverRead {
  if (stored.state === "absent") return "unarmed";
  return stored.state === "valid" ? "armed" : "corrupt";
}

async function readCutover(): Promise<CutoverRead> {
  return cutoverRead(await readKey(POLICY_CUTOVER_KEY, CutoverFlagSchema));
}

/** Corrupt (present but failing the strict schema) is NEVER folded into absent: that would fail open. */
function readStoredRecord(): Promise<Stored<StoredPolicyState>> {
  return readKey(POLICY_STATE_KEY, StoredPolicyStateSchema);
}

/** The keyId pinned when the last revoke ran, written by onPinRevoked and consumed by the next onPinPinned. Durable
 * because the MV3 service worker commonly dies between revoke and re-pair; an in-memory prior would read every
 * re-pair as "prior unknown", and neither the compromise latch nor a corrupt cutover flag could recover.
 * It carries LESS trust than the pin store (a bare string, no pubkey to check), so only the keyId shape is validated:
 *   a different keyId-shaped string  -> the next re-pair reads as new; no worse than deleting bridgePolicyState
 *   anything else                    -> unknown (null), which fails closed to "not a new key"; recovery stalls until
 *                                       the next revoke overwrites it */
const PriorPinSchema = z.string().regex(KEY_ID_HEX);

function readPriorPin(): Promise<string | null> {
  return readKeyOr(POLICY_PRIOR_PIN_KEY, PriorPinSchema, null);
}

/** One storage get for both keys: resolvePolicyState folds them together, and two separate reads could tear across a
 * pin transition or a partial write and hand the fold an inconsistent pair. */
async function readPolicyStorage(): Promise<{
  cutover: CutoverRead;
  stored: Stored<StoredPolicyState>;
}> {
  const read = await readKeys({
    [POLICY_CUTOVER_KEY]: CutoverFlagSchema,
    [POLICY_STATE_KEY]: StoredPolicyStateSchema,
  });
  return { cutover: cutoverRead(read[POLICY_CUTOVER_KEY]), stored: read[POLICY_STATE_KEY] };
}

// ---- the resolved policy state (the no-invalid-states sum type) ----------------

/** The persisted policy state resolved against a scope: exactly one arm, no contradictory combination. */
type PolicyState =
  | { kind: "preCutover" }
  | { kind: "awaitingBaseline"; scope: PolicyScope }
  | { kind: "active"; scope: PolicyScope; record: StoredPolicyState }
  | { kind: "compromised" };

/** The one place the lifecycle invariants live; every consumer branches on the result instead of re-deriving flags. */
async function resolvePolicyState(scope: PolicyScope): Promise<PolicyState> {
  // The in-life latch dominates every persisted fact; its declaration names the replay it stops.
  if (compromisedThisLife.value) return { kind: "compromised" };
  const { cutover, stored } = await readPolicyStorage();
  if (cutover === "corrupt") return { kind: "compromised" };
  if (cutover === "unarmed") {
    // armCutover precedes the record write, so a record with no cutover is tampering: latch closed.
    return stored.state === "absent" ? { kind: "preCutover" } : { kind: "compromised" };
  }
  // Cutover armed:
  if (stored.state === "corrupt") return { kind: "compromised" };
  if (stored.state === "absent") return { kind: "awaitingBaseline", scope };
  const recordScope = scopeFromStored(stored.value.scope);
  // Out of scope: the old effective is NOT enforced. writeStoredRecord owns the retained-record rule.
  if (!scopesEqual(recordScope, scope)) return { kind: "awaitingBaseline", scope };
  return { kind: "active", scope: recordScope, record: stored.value };
}

// ---- writers ------------------------------------------------------------------

/** Write the ratchet record. Returns whether a write landed, so the commit-end undo can skip restoring a record it never
 * replaced: a blind undo `set` would retrigger every storage.onChanged consumer, breaking the setMirror discipline below. */
async function writeStoredRecord(next: StoredPolicyState): Promise<boolean> {
  const stored = await readStoredRecord();
  // resolvePolicyState is the primary guard; this is the torn-read backstop.
  if (stored.state === "corrupt") {
    throw new Error("refusing to overwrite a corrupt policy record");
  }
  // onPinRevoked RETAINS the pinned record as the same-key anti-replay anchor; while unpinned it is inert, not
  // disposable. Otherwise an unsigned push in the unpinned window could ride the user's approval over the anchor, and
  // an old, more-permissive signed baseline would replay as first-ever once the same key is re-paired.
  if (next.scope === null && stored.state === "valid" && stored.value.scope !== null) {
    throw new Error(
      "refusing to replace a retained pinned-scope policy record with an unsigned one",
    );
  }
  // Unchanged state writes nothing (the kill.ts setMirror discipline): a rewrite would retrigger every
  // storage.onChanged consumer on the push-on-connect replay.
  if (
    stored.state === "valid" &&
    stored.value.scope === next.scope &&
    stored.value.revision === next.revision &&
    stored.value.baselineB64 === next.baselineB64 &&
    policyValuesEqual(stored.value.effective, next.effective)
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
  prior: Stored<StoredPolicyState>,
  resetGenerationAtWrite: number,
): Promise<void> {
  const now = await readStoredRecord();
  if (now.state !== "valid" || !sameStoredRecord(now.value, written)) return;
  // Re-checked after the awaited read. The microtask gap before set() cannot be closed (browser.storage.local has no
  // transaction); a reset inside it degrades to a restore the transition's own removal supersedes, never an open barrier.
  if (ratchetResetGeneration.value !== resetGenerationAtWrite) {
    await browser.storage.local.remove(POLICY_STATE_KEY);
    return;
  }
  if (prior.state === "valid") {
    await browser.storage.local.set({ [POLICY_STATE_KEY]: prior.value });
    return;
  }
  if (prior.state === "absent") {
    await browser.storage.local.remove(POLICY_STATE_KEY);
    return;
  }
  throw new Error("refusing to undo a policy record write over a corrupt prior record");
}

/** Arm the one-way cutover, BEFORE the record write: an SW death between the two leaves armed + absent, which
 * resolves to awaitingBaseline (closed barrier), never an open barrier over an applied policy. */
async function armCutover(): Promise<void> {
  const cutover = await readCutover();
  if (cutover === "armed") return;
  // Laundering a tampered flag into `true` would erase the evidence resolvePolicyState latches on.
  if (cutover === "corrupt") {
    throw new Error("refusing to overwrite a corrupt cutover flag");
  }
  await browser.storage.local.set({ [POLICY_CUTOVER_KEY]: true });
  console.log("[bb] policy cutover armed: host policy governs from here on (one-way)");
}

/** Fail-closed on a corrupt flag: it reads as armed, so the barrier governs. */
export async function policyCutoverArmed(): Promise<boolean> {
  return (await readCutover()) !== "unarmed";
}

// ---- the dispatch barrier (consulted by enrollment.ts's gate) -------------------

export type PolicyGate = { allowed: true } | { allowed: false; reason: string };

const BARRIER_REASON =
  "policy barrier: no verified policy push has been accepted on this host connection under " +
  "the current pin, so every bridge request is refused. A policy-capable host " +
  "pushes its policy at connect; a host that stays silent or pushes junk keeps the bridge " +
  "refusing.";

const LATCHED_REASON =
  "policy state latched closed: the stored policy record or the cutover flag is corrupt " +
  "(tampering evidence). Every bridge request is refused until you revoke the pin and " +
  "re-pair (the same strict posture as the kill mirror: garbage where a record should be " +
  "is tampering evidence).";

const COMPROMISED_LIFE_REASON =
  "policy state latched closed: a policy baseline's signature did not verify against the pinned " +
  "key this session (host-substitution evidence). Every bridge request is refused for the rest of " +
  "this browser session; revoke the pin and re-pair with a fresh key to recover.";

/** The per-connection dispatch barrier. Post-cutover a request passes only after a push verified on the CURRENT
 * connection under the CURRENT scope and generation, so no op runs under a cached copy the host has since tightened
 * and a pin transition closes the barrier the instant it lands. Pre-cutover it is inert (the deny baseline governs). */
export async function policyDispatchGate(): Promise<PolicyGate> {
  // A signature failure this SW life refuses everything, whatever the cutover, pin, or record say.
  if (compromisedThisLife.value) return { allowed: false, reason: COMPROMISED_LIFE_REASON };
  const scope = await currentScope();
  const state = await resolvePolicyState(scope);
  if (state.kind === "preCutover") return { allowed: true };
  if (state.kind === "compromised") return { allowed: false, reason: LATCHED_REASON };
  // A mark from before a same-key re-pair carries the old generation and no longer opens the gate.
  if (
    state.kind === "active" &&
    live.value?.policy.kind === "verified" &&
    scopesEqual(live.value.policy.scope, scope) &&
    live.value.policy.generation === pinGeneration.value
  ) {
    return { allowed: true };
  }
  return { allowed: false, reason: BARRIER_REASON };
}

// ---- the read API (effective-policy.ts consumes this) ----------------------------

/** The persisted posture, typed so a BLOCKED state is not consumable as policy values: awaitingBaseline and compromised
 * carry a reason, never a PolicyValues, so no enforcement caller can mistake the deny baseline for an applicable policy.
 * effective-policy.ts folds `preCutover` with the deny baseline; every enforcement site consumes ITS wrapper, not this. */
export type PolicyPosture =
  | { kind: "preCutover" }
  | { kind: "active"; effective: PolicyValues }
  | { kind: "blocked"; reason: string };

const AWAITING_REASON =
  "policy cutover is armed but no in-scope verified policy baseline is stored: the deny " +
  "posture governs and every enforcement read refuses until a " +
  "baseline verifies under the current pin.";

export async function getPolicyPosture(): Promise<PolicyPosture> {
  const state = await resolvePolicyState(await currentScope());
  switch (state.kind) {
    case "preCutover":
      return { kind: "preCutover" };
    case "active":
      return { kind: "active", effective: state.record.effective };
    case "awaitingBaseline":
      return { kind: "blocked", reason: AWAITING_REASON };
    case "compromised":
      return {
        kind: "blocked",
        reason: compromisedThisLife.value ? COMPROMISED_LIFE_REASON : LATCHED_REASON,
      };
    default:
      return unreachable(state);
  }
}

/** The resolved state as tests and diagnostics pin it. Enforcement uses getPolicyPosture, never this. */
export type PolicySnapshot =
  | { kind: "preCutover" }
  | { kind: "awaitingBaseline" }
  | { kind: "active"; effective: PolicyValues }
  | { kind: "compromised" };

/** Tests and diagnostics only. */
export async function getPolicySnapshotForTests(): Promise<PolicySnapshot> {
  const state = await resolvePolicyState(await currentScope());
  switch (state.kind) {
    case "preCutover":
      return { kind: "preCutover" };
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

/** The valid persisted record or null. Tests and diagnostics only; enforcement goes through resolvePolicyState. */
export async function getStoredPolicyState(): Promise<StoredPolicyState | null> {
  const stored = await readStoredRecord();
  return stored.state === "valid" ? stored.value : null;
}

// ---- pin lifecycle hooks (called from enrollment.ts) ----------------------------

/** A key was (re-)pinned. Novelty is decided from the PRIOR PIN IDENTITY (the durable prior written at revoke, then
 * this life's mirror), never from the stored record's scope: a same-key re-pair whose record is absent or corrupt
 * must not read as a new key. Always drops this connection's verified mark and bumps the generation; never clears
 * cutover.
 *   prior known, different  -> ratchet reset, compromise latch cleared, corrupt cutover flag normalized
 *   prior known, equal      -> anchor retained, so an old permissive baseline cannot replay after revoke+re-pair
 *   prior unknown           -> fail closed to "not new": latch kept, ratchet retained */
export async function onPinPinned(newKeyId: string): Promise<void> {
  // Synchronously FIRST: a push in flight must observe the move even when the new keyId equals the old.
  pinGeneration.value += 1;
  // The durable prior survives the SW restart that so often falls between revoke and re-pair.
  const priorKeyId = (await readPriorPin()) ?? lastPinnedKeyId.value;
  const isNewKey = priorKeyId !== null && priorKeyId !== newKeyId;
  lastPinnedKeyId.value = newKeyId;
  if (isNewKey) {
    ratchetResetGeneration.value += 1;
    await browser.storage.local.remove(POLICY_STATE_KEY);
    // A NEW-key re-pair is fresh presence-verified evidence the substituted signer is gone: the ONLY in-life clear.
    compromisedThisLife.value = false;
    // Normalized to `true`, not cleared (LATCHED_REASON promises re-pair recovery and armCutover throws on corrupt),
    // so recovery lands in awaitingBaseline and the cutover stays one-way.
    if ((await readCutover()) === "corrupt") {
      await browser.storage.local.set({ [POLICY_CUTOVER_KEY]: true });
    }
  }
  // Consumed LAST so an SW death mid-reset cannot leave the prior consumed with the recovery half-done; every route
  // back here requires a full presence ceremony, so re-reading a stale prior is safe. An SW death between the reset
  // and this remove costs one extra revoke+re-pair, never a wrong novelty decision.
  await browser.storage.local.remove(POLICY_PRIOR_PIN_KEY);
  if (live.value) {
    live.value.policy = { kind: "awaiting" };
  }
}

/** The pin was revoked. RETAINS the ratchet record (writeStoredRecord owns why); never clears cutover or the in-life
 * compromise latch.
 *   revokedKeyId: string  -> persisted as the durable prior the next onPinPinned decides novelty against
 *   revokedKeyId: null    -> nothing was pinned; an existing durable prior is left intact, or recovery would strand */
export async function onPinRevoked(revokedKeyId: string | null): Promise<void> {
  // Synchronously, so the second leg of a same-key revoke+re-pair is distinguishable from the pre-revoke pin.
  pinGeneration.value += 1;
  if (revokedKeyId !== null) lastPinnedKeyId.value = revokedKeyId;
  if (live.value) {
    live.value.policy = { kind: "awaiting" };
  }
  if (revokedKeyId !== null) {
    await browser.storage.local.set({ [POLICY_PRIOR_PIN_KEY]: revokedKeyId });
  }
}

// ---- the unpinned window-approval seam --------------------------------------------

export interface UnpinnedRelaxation {
  /** The folded effective values awaiting approval, a frozen copy; the parsed document is deliberately not handed
   * over. */
  effective: PolicyValues;
  /** The stored effective it would relax (null = first document ever), a frozen copy. */
  storedEffective: PolicyValues | null;
}

export type UnpinnedRelaxationApprover = (relaxation: UnpinnedRelaxation) => Promise<boolean>;

const unpinnedApprover = inLife<UnpinnedRelaxationApprover | null>(() => null);

/** Register the unpinned lane's approval surface (policy-approval.ts). While none is registered every unpinned
 * relaxation, the first-ever document included, is refused. Never consulted on a pinned extension. */
export function setUnpinnedRelaxationApprover(approver: UnpinnedRelaxationApprover | null): void {
  unpinnedApprover.value = approver;
}

// ---- inbound frames --------------------------------------------------------------

/** Classification for the port demux: is this frame a policy/language push? */
export function isPolicyFrame(msg: unknown): msg is PolicyInboundFrame {
  return PolicyInboundFrameSchema.safeParse(msg).success;
}

// Frames are processed strictly in arrival order (the kill.ts lane): the accept path awaits crypto and storage, so
// two overlapping pushes could otherwise land their ratchet writes in the wrong order.
const frames = inLife(() => pLimit(1));

/** The unsigned push held at the approver. handlePolicyFrame collapses an inbound frame only when ALL THREE match: a
 * different overlay is a tightening that must not be lost, a different attachment is a reconnect that must earn its
 * own mark. */
const pendingApproval = inLife<{
  baselineB64: string;
  overlayJson: string;
  attachment: LiveConnection | null;
} | null>(() => null);

/** Route one inbound policy/lang frame. The attachment is captured synchronously so the verified mark lands on
 * exactly the connection the frame arrived on. port.ts void-routes these frames, so requests already past the gate
 * can dispatch while a bad-signature push is still verifying (docs/security/trust-boundaries.md, "Host-owned policy
 * residual ledger"):
 *   bad push arrives -> requests past the gate run under the stored effective -> signature fails -> latch set synchronously */
export function handlePolicyFrame(msg: unknown): Promise<void> {
  const attachment = live.value;
  // A TRULY IDENTICAL replay of the push held at the approver is dropped: the pending verdict covers it, and another
  // prompt would let a hostile unpinned host occupy the confirmation FIFO. Distinct candidates still cost one prompt
  // each (the residual ledger records that occupancy).
  if (pendingApproval.value !== null && attachment === pendingApproval.value.attachment) {
    const dup = PolicyCurrentFrameSchema.safeParse(msg);
    if (
      dup.success &&
      dup.data.ok === true &&
      dup.data.baseline === pendingApproval.value.baselineB64 &&
      JSON.stringify(dup.data.overlay ?? null) === pendingApproval.value.overlayJson
    ) {
      console.warn("[bb] dropping a policy push identical to one already awaiting approval");
      return Promise.resolve();
    }
  }
  return frames
    .value(() => routeOne(msg, attachment))
    .catch((e) => {
      console.warn("[bb] policy frame handling failed", e);
    });
}

async function routeOne(msg: unknown, attachment: LiveConnection | null): Promise<void> {
  const inbound = PolicyInboundFrameSchema.safeParse(msg);
  if (!inbound.success) return;
  if (inbound.data.type === "lang_current") {
    await handleLangCurrent(msg, attachment);
    return;
  }
  await handlePolicyCurrent(msg, attachment);
}

/** A refusal changes nothing: the stored effective stays enforced and the connection's verified mark is kept. Only
 * the attack-shaped refusals (a rejected CLAIM after crypto/ratchet reasoning) reach the audit ring; shape and
 * version-skew refusals are console-only, so the ring stays a security trail. */
function refuse(why: string, opts: { audit?: boolean } = {}): void {
  console.warn("[bb] policy push refused:", why);
  if (opts.audit) auditEvent("policy_refused", { detail: why.slice(0, 512) });
}

/** A signature failed against the pin: host-substitution evidence, never ordinary skew. compromisedThisLife owns
 * the latch's ordering; the in-memory residual is recorded in docs/security/trust-boundaries.md, "Host-owned policy
 * residual ledger". */
async function markPolicyCompromised(
  attachment: LiveConnection | null,
  reason: string,
): Promise<void> {
  compromisedThisLife.value = true;
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

async function handlePolicyCurrent(msg: unknown, attachment: LiveConnection | null): Promise<void> {
  const parsed = PolicyCurrentFrameSchema.safeParse(msg);
  if (!parsed.success) return refuse("malformed policy_current frame");
  // The frame schema is loose and its parse output RETAINS unknown keys: only the named fields below may be read; never
  // spread, iterate, or forward the frame object.
  const { ok, baseline, sig, overlay, error } = parsed.data;

  if (!ok) {
    // Nothing to verify and nothing changes; a policy-capable peer gone silent or wrong NEVER opens the gate.
    return refuse(`host provided no baseline${error ? ` (${error})` : ""}`);
  }

  let docBytes: Uint8Array;
  try {
    docBytes = base64Decode(baseline);
  } catch (e) {
    return refuse(`baseline is not canonical base64: ${e instanceof Error ? e.message : e}`);
  }

  // Snapshotted here and re-checked at commit: a pin transition on enrollment's separate queue must not let this push
  // land in the wrong scope. The pin OBJECT is read once: keyId = SHA-256(pubkey), so the scope binds the exact key.
  const generationAtStart = pinGeneration.value;
  const pinAtStart = await getPin();
  const scopeAtStart: PolicyScope = pinAtStart
    ? { pinned: true, keyId: pinAtStart.keyId }
    : { pinned: false };
  if (pinAtStart) {
    if (sig === undefined) {
      // The no-downgrade rule: a missing signature is a refusal, not crypto evidence; nothing proves who sent it.
      return refuse("unsigned baseline on a pinned extension", { audit: true });
    }
    const verdict = await verifyPolicySignatureAgainstPin(sig, docBytes, pinAtStart.pubkeyB64);
    if (!verdict.ok) return markPolicyCompromised(attachment, verdict.reason);
  }

  // The SAME bytes the signature covered; on an unpinned machine strict parsing is the entry point.
  let docJson: unknown;
  try {
    docJson = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(docBytes));
  } catch {
    return refuse("baseline bytes are not UTF-8 JSON");
  }
  const doc = PolicyDocSchema.safeParse(docJson);
  if (!doc.success) return refuse("baseline document failed the strict schema");
  const baselineValues = policyValuesFrom(doc.data);

  // The unsigned overlay may only restrict the baseline: its DIRECTION is recomputed from the generated table, field
  // by field, and one relaxing entry fails the whole push.
  const effective = foldPolicyOverlay(baselineValues, overlay ?? {});
  const overlayRelaxes = relaxedPolicyFields(effective, baselineValues);
  if (overlayRelaxes.length > 0) {
    return refuse(`overlay relaxes the baseline on: ${overlayRelaxes.join(", ")}`, { audit: true });
  }

  // The ratchet anchor is the ACTIVE stored record under the snapshot scope. A corrupt store latches closed: a push must
  // not silently "fix" it by landing an older baseline as first-ever. awaitingBaseline/preCutover carry no anchor.
  const state = await resolvePolicyState(scopeAtStart);
  if (state.kind === "compromised") {
    return refuse("stored policy state is corrupt; latched closed until re-pair", { audit: true });
  }
  const anchor = state.kind === "active" ? state.record : null;
  // The revision/touched ratchet binds only the PINNED scope: on the unpinned scope every field is attacker-writable,
  // so enforcing the revision would hand a local forger a permanent denial lever (push revision=MAX).
  if (anchor && scopeAtStart.pinned) {
    // Strictly higher, or byte-identical (the idempotent push-on-connect replay).
    if (doc.data.revision < anchor.revision) {
      return refuse(`replayed revision ${doc.data.revision} below stored ${anchor.revision}`, {
        audit: true,
      });
    }
    if (doc.data.revision === anchor.revision && baseline !== anchor.baselineB64) {
      return refuse("revision reuse with different document bytes", { audit: true });
    }
    // Anchored on the STORED effective, not the baseline: that refuses replaying the genuine current baseline with
    // its overlay stripped; the touched-set check refuses stretching a fresh signature into a blanket warrant.
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
    // The unpinned lane: a restriction applies silently; a relaxation (the first document included) applies only on
    // the user's approval and is refused while no approver is registered.
    const needsApproval = !anchor || relaxedPolicyFields(effective, anchor.effective).length > 0;
    if (needsApproval) {
      // A RETAINED pinned-scope record makes this push unstorable whatever the user answers: refuse audited, up front.
      const storedNow = await readStoredRecord();
      if (storedNow.state === "valid" && storedNow.value.scope !== null) {
        return refuse(
          "unsigned push cannot replace the retained pinned-scope anchor; re-pair to recover",
          { audit: true },
        );
      }
      const approver = unpinnedApprover.value;
      if (!approver) {
        return refuse("unpinned relaxation with no approval surface registered", { audit: true });
      }
      // Held for the approver await so handlePolicyFrame collapses identical replays (confirmation FIFO occupancy).
      pendingApproval.value = {
        baselineB64: baseline,
        overlayJson: JSON.stringify(overlay ?? null),
        attachment,
      };
      let approved: boolean;
      try {
        approved = await approver({
          // Frozen copies: the approver sees exactly what this push commits.
          effective: freezePolicyValues(effective),
          storedEffective: anchor ? freezePolicyValues(anchor.effective) : null,
        }).catch(() => false);
      } finally {
        pendingApproval.value = null;
      }
      if (!approved) {
        // Audited: repeated declines are the signal of a hostile unpinned host grinding at the approval window.
        return refuse("unpinned relaxation not approved by the user", { audit: true });
      }
    }
  }

  // Re-checked AFTER the possibly minutes-long approver await: unpinned-at-snapshot -> pinned-at-commit would commit
  // an UNSIGNED document under a just-pinned key. A second recheck after the writes covers their own awaits.
  const scopeAtCommit = await currentScope();
  if (!scopesEqual(scopeAtCommit, scopeAtStart) || pinGeneration.value !== generationAtStart) {
    return refuse(
      "pin scope or generation changed while the push was in flight; dropping to stay fail-closed",
      { audit: true },
    );
  }

  // Arm BEFORE the record write (armCutover owns the ordering); arming is one-way, so a stale arm is harmless.
  await armCutover();
  // Captured BEFORE the prior-snapshot read: a reset completing during it would leave the undo restoring a dead anchor.
  const resetGenerationAtWrite = ratchetResetGeneration.value;
  // The pre-write snapshot lets a race detected after the write restore exactly it (undoRecordWrite owns the cases).
  const priorRecord = await readStoredRecord();
  const committed: StoredPolicyState = {
    scope: scopeToStored(scopeAtStart),
    effective,
    // An unsigned document's revision is unauthenticated noise: stored as 0 so it can never enter a ratchet decision.
    revision: scopeAtStart.pinned ? doc.data.revision : 0,
    baselineB64: baseline,
    at: Date.now(),
  };
  const wrote = await writeStoredRecord(committed);
  // The awaits above let a same-key revoke+re-pair move the pin after the pre-write recheck. A stale mark is inert
  // (the gate rejects a generation mismatch), but a stale RECORD could resurrect as an anchor, so undo the write.
  const scopeAtEnd = await currentScope();
  if (!scopesEqual(scopeAtEnd, scopeAtStart) || pinGeneration.value !== generationAtStart) {
    // `wrote` is the primary guard (a suppressed write set nothing); undoRecordWrite's `at` comparison is the backstop.
    // Wrapped so an exception can never skip refuse() and its audit entry.
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
  // Stamped only while this frame's connection is STILL the live one: a dead connection earns nothing, and the live
  // one's own push earns its mark.
  if (attachment && attachment === live.value) {
    attachment.policy = { kind: "verified", scope: scopeAtStart, generation: generationAtStart };
  } else if (attachment) {
    console.warn(
      "[bb] policy push applied, but the host connection changed mid-flight; no verified mark " +
        "stamped - the new connection's own push opens its barrier",
    );
  }
  console.log("[bb] policy push applied: revision", doc.data.revision);
}

/** Tests only: everything an SW restart would reset. Stored policy state stays, the durable prior-pin identity
 * included; suites that need a clean store reset fakeBrowser storage. */
export function resetPolicySyncForTests(): void {
  live.reset();
  lang.reset();
  unpinnedApprover.reset();
  pendingApproval.reset();
  compromisedThisLife.reset();
  pinGeneration.reset();
  ratchetResetGeneration.reset();
  lastPinnedKeyId.reset();
  frames.reset();
}
