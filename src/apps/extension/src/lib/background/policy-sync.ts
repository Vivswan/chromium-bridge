// The extension half of ADR-0032 host-owned policy, Phase 3 consumption
// core: verification of `policy_current` pushes against the extension's OWN
// pinned key, the value ratchet, the stored effective policy, the one-way
// cutover flag, and the per-connection dispatch barrier the enrollment gate
// consults. `lang_current` is stored only (Phase 4 consumes it).
//
// Fail closed everywhere (ADR-0032 decisions 3 and 4):
// - a push is consumed only through: strict frame validation -> signature
//   over the EXACT decoded baseline bytes against the PINNED key (the
//   frames carry no key identity the extension honors) -> strict
//   PolicyDocSchema parse of those same bytes;
// - the ratchet: a revision <= the stored highest-seen is refused unless
//   the bytes are identical to the stored baseline (the idempotent
//   push-on-connect replay), and a push whose folded effective would relax
//   the STORED effective on any field is refused unless the document's
//   revision is strictly higher AND its signed `touched` set names every
//   relaxed field - which is exactly what refuses the overlay-strip replay;
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
// order. This module never sends a frame (the never-speak-first rule of
// decision 4; `policy_get` is Phase 4's business), and it deliberately does
// not consult the kill or enrollment gates: a killed bridge still processes
// policy pushes (control-plane mode, decision 6), which port.ts guarantees
// by routing these frames BEFORE the request parse and the gates.

import {
  foldPolicyOverlay,
  LangCurrentFrameSchema,
  POLICY_DEFAULTS,
  PolicyCurrentFrameSchema,
  type PolicyDoc,
  PolicyDocSchema,
  PolicyInboundFrameSchema,
  type PolicyValues,
  parseStoredPolicyValues,
  policyValuesEqual,
  policyValuesFromDoc,
  relaxedPolicyFields,
  type StoredPolicyState,
  StoredPolicyStateSchema,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { auditEvent } from "./audit-log";
import { getPin, setCompromised } from "./enclave-pin";
import { base64Decode, verifyPolicySignatureAgainstPin } from "./enclave-verify";

const POLICY_STATE_KEY = "bridgePolicyState";
const POLICY_CUTOVER_KEY = "bridgePolicyCutover";

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
 * `awaiting` attachment that inherits nothing. `Verified{scope}` (not a bare
 * boolean) is what lets the barrier close the instant the pin moves away from
 * the scope the mark was earned under. */
type AttachmentPolicy = { kind: "awaiting" } | { kind: "verified"; scope: PolicyScope };

/** One port attachment. `post` is held for the Phase 4 frames (policy_get,
 * lang_set); nothing in this phase ever posts. */
interface PortAttachment {
  post: PostFrame;
  policy: AttachmentPolicy;
}

let port: PortAttachment | null = null;

export function attachPort(post: PostFrame): void {
  port = { post, policy: { kind: "awaiting" } };
}

export function detachPort(): void {
  port = null;
}

// ---- lang_current (store-only until Phase 4) ----------------------------------

let lang: { value: string; seq: number } | null = null;

/** The last host language push this SW life (null = none seen). Phase 4
 * consumes it; nothing security-relevant may ever key on it (decision 7). */
export function getLangState(): { value: string; seq: number } | null {
  return lang;
}

function handleLangCurrent(msg: unknown): void {
  const parsed = LangCurrentFrameSchema.safeParse(msg);
  if (!parsed.success) {
    console.warn("[bb] dropping malformed lang_current frame");
    return;
  }
  // Sequence-suppressed (ADR-0032 decision 7): only a strictly newer push
  // applies; an echo or replay has nothing to ride on.
  if (lang && parsed.data.seq <= lang.seq) return;
  lang = { value: parsed.data.value, seq: parsed.data.seq };
}

// ---- the persisted reads (each discriminates its three outcomes) ---------------

/** The one-way cutover fact (ADR-0032 decision 8), read as three DISTINCT
 * outcomes. `corrupt` (present but not exactly `true`) is tampering and must
 * not be read as either armed or unarmed: it latches closed. Written only as
 * `true`, and never cleared - not even by a re-pair. */
type CutoverRead = "unarmed" | "armed" | "corrupt";

async function readCutover(): Promise<CutoverRead> {
  const { [POLICY_CUTOVER_KEY]: value } = await browser.storage.local.get(POLICY_CUTOVER_KEY);
  // `undefined` is the absent signal (storage cannot hold undefined); any
  // other non-`true` value is a tampered flag.
  if (value === undefined) return "unarmed";
  return value === true ? "armed" : "corrupt";
}

/** The stored ratchet record, read as three DISTINCT outcomes (finding 3):
 * `absent` (the storage key is missing), `valid`, or `corrupt` (present but
 * fails the strict schema). Corrupt is NEVER folded into absent - that is the
 * fail-open the kill mirror's STRICT precedent forbids. */
type StoredRead =
  | { kind: "absent" }
  | { kind: "corrupt" }
  | { kind: "valid"; record: StoredPolicyState };

async function readStoredRecord(): Promise<StoredRead> {
  const { [POLICY_STATE_KEY]: value } = await browser.storage.local.get(POLICY_STATE_KEY);
  // `undefined` is the absent signal (storage cannot hold undefined); any
  // stored value that fails the strict schema is corrupt, never absent.
  if (value === undefined) return { kind: "absent" };
  const parsed = StoredPolicyStateSchema.safeParse(value);
  if (!parsed.success) return { kind: "corrupt" };
  // The schema already parsed `effective` strictly; re-parse through the
  // canonical strict reader so any future divergence stays fail-closed.
  const effective = parseStoredPolicyValues(parsed.data.effective);
  if (!effective) return { kind: "corrupt" };
  return { kind: "valid", record: { ...parsed.data, effective } };
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
  const cutover = await readCutover();
  if (cutover === "corrupt") return { kind: "compromised" };
  const stored = await readStoredRecord();
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
  // enforced (deny baseline governs), and a fresh in-scope push starts a new
  // ratchet - which for a DIFFERENT key is exactly the intended reset.
  if (!scopesEqual(recordScope, scope)) return { kind: "awaitingBaseline", scope };
  return { kind: "active", scope: recordScope, record: stored.record };
}

// ---- writers ------------------------------------------------------------------

async function writeStoredRecord(next: StoredPolicyState): Promise<void> {
  const stored = await readStoredRecord();
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
    return;
  }
  await browser.storage.local.set({ [POLICY_STATE_KEY]: next });
}

/** Arm the one-way cutover (ADR-0032 decision 8). Set on the first accepted
 * push, cleared by nothing - not even a re-pair. Deliberately armed BEFORE
 * the record write on the accept path: if the SW dies between the two, the
 * resulting armed + absent-record state resolves to awaitingBaseline (deny
 * baseline + closed barrier = fail closed), never legacy-enforced-despite-an-
 * applied-policy. */
async function armCutover(): Promise<void> {
  if ((await readCutover()) === "armed") return;
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

/** The per-connection dispatch barrier (ADR-0032 decision 4). Post-cutover,
 * bridge requests are refused until a policy push has verified and applied on
 * the CURRENT host connection UNDER THE CURRENT SCOPE - so no op can race
 * ahead of the connect push and run under a cached copy the host has since
 * tightened, and a pin transition closes the barrier the instant it lands.
 * Pre-cutover the barrier is inert: the legacy local settings govern. A
 * corrupt store latches it closed regardless of the connection. */
export async function policyDispatchGate(): Promise<PolicyGate> {
  const scope = await currentScope();
  const state = await resolvePolicyState(scope);
  if (state.kind === "legacy") return { allowed: true };
  if (state.kind === "compromised") return { allowed: false, reason: LATCHED_REASON };
  // awaitingBaseline | active: the barrier opens only for an ACTIVE (in-scope)
  // record when THIS connection verified a push under the current scope.
  if (
    state.kind === "active" &&
    port?.policy.kind === "verified" &&
    scopesEqual(port.policy.scope, scope)
  ) {
    return { allowed: true };
  }
  return { allowed: false, reason: BARRIER_REASON };
}

// ---- the read API (Lane S consumes this) ----------------------------------------

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
   * instead; that switch is Lane S's. */
  effective: PolicyValues;
}

export async function getPolicySnapshot(): Promise<PolicySnapshot> {
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

/** A key was (re-)pinned (ADR-0032 decision 3). Resets the ratchet scope
 * UNLESS the new key matches the scope the stored record is already bound to:
 * a same-key re-pair RETAINS the anchor, which is what refuses an old
 * permissive baseline from replaying after a revoke+re-pair with zero fresh
 * presence (finding 2). A different key (or a corrupt/absent record) clears
 * it so the new scope starts fresh. Always drops this connection's verified
 * mark so the barrier re-verifies under the new pin. NEVER clears cutover:
 * post-reset the deny baseline plus the barrier govern until the first
 * baseline verifies under the new pin, never the legacy settings again. */
export async function onPinPinned(newKeyId: string): Promise<void> {
  const stored = await readStoredRecord();
  const sameScope =
    stored.kind === "valid" &&
    scopesEqual(scopeFromStored(stored.record.scope), { pinned: true, keyId: newKeyId });
  if (!sameScope) await browser.storage.local.remove(POLICY_STATE_KEY);
  if (port) port.policy = { kind: "awaiting" };
}

/** The pin was revoked (ADR-0032 decision 3). RETAINS the ratchet record so a
 * same-key re-pair still refuses an old-baseline replay (finding 2); the
 * scope check keeps the retained record inert (deny baseline + closed
 * barrier) while unpinned. Drops this connection's verified mark so no op runs
 * under a stale policy after the pin moved. NEVER clears cutover. */
export async function onPinRevoked(): Promise<void> {
  if (port) port.policy = { kind: "awaiting" };
}

// ---- Lane U's seam: the unpinned window-approval surface -------------------------

export interface UnpinnedRelaxation {
  /** The strict-parsed document awaiting approval. */
  doc: PolicyDoc;
  /** Its folded effective values (baseline + overlay). */
  effective: PolicyValues;
  /** The stored effective it would relax (null = first document ever). */
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

/** Route one inbound policy/lang frame. The connection it arrived on is
 * captured synchronously: the verified mark must land on exactly that
 * attachment, so a reconnect that installs a fresh one mid-verification
 * stays unverified (its own connect push will open its barrier). */
export function handlePolicyFrame(msg: unknown): Promise<void> {
  const attachment = port;
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
    handleLangCurrent(msg);
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
 * evidence the signer does not hold the pinned key. Synchronously drop THIS
 * connection's verified mark so the barrier closes immediately (finding 4),
 * audit the compromise, and latch the enrollment-side compromised mark. A
 * FAILED persist is treated as fail-closed - the barrier is already shut and
 * stays shut (a substituted host's every push keeps failing this check), and
 * the failure is surfaced loudly rather than swallowed as best-effort. */
async function markPolicyCompromised(
  attachment: PortAttachment | null,
  reason: string,
): Promise<void> {
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
      "[bb] FAIL-CLOSED: could not persist the policy compromise mark; " +
        "the dispatch barrier stays closed on this connection regardless",
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
  const { ok, baseline, sig, overlay, error } = parsed.data;

  if (ok !== true || baseline === undefined) {
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

  // Snapshot the scope the push is evaluated under. Captured HERE, re-checked
  // at commit: a pin transition on enrollment's separate queue between now and
  // the write must not let this push land in the wrong scope (finding 1). The
  // pin OBJECT is read once - its keyId is the scope identity, its pubkey is
  // what the signature is verified against (keyId = SHA-256(pubkey), so
  // binding the scope to the keyId binds it to the exact verifying key).
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
  if (anchor) {
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
    // this unsigned document into an enforced, barrier-opening policy.
    const needsApproval = !anchor || relaxedPolicyFields(effective, anchor.effective).length > 0;
    if (needsApproval) {
      const approver = unpinnedApprover;
      if (!approver) {
        return refuse("unpinned relaxation with no approval surface registered", { audit: true });
      }
      const approved = await approver({
        doc: doc.data,
        // Frozen copies: the approver is Lane U's code, and the values it sees
        // must be exactly what this push commits - it cannot mutate the object
        // out from under the commit below (which recomputed none of this).
        effective: freezePolicyValues(effective),
        storedEffective: anchor ? freezePolicyValues(anchor.effective) : null,
      }).catch(() => false);
      if (!approved) return refuse("unpinned relaxation not approved by the user");
    }
  }

  // COMMIT-TIME SCOPE RECHECK (finding 1). Re-read the scope: if the pin moved
  // while this push was in flight - crucially including unpinned-at-snapshot ->
  // pinned-at-commit, which would otherwise commit an UNSIGNED document under a
  // just-pinned key and open the barrier (the no-downgrade violation) - drop
  // the push, fail closed. The stamped scope makes the mismatch detectable;
  // the read-time scope checks above are the backstop if a write ever still
  // slipped through.
  const scopeAtCommit = await currentScope();
  if (!scopesEqual(scopeAtCommit, scopeAtStart)) {
    return refuse("pin scope changed while the push was in flight; dropping to stay fail-closed", {
      audit: true,
    });
  }

  // Arm cutover BEFORE the record write (fail-closed ordering, above). Then
  // write the scope-stamped record and mark THIS attachment verified under the
  // snapshot scope - which now equals the commit scope, so the mark is honest.
  await armCutover();
  await writeStoredRecord({
    scope: scopeToStored(scopeAtStart),
    effective,
    revision: doc.data.revision,
    baselineB64: baseline,
    at: Date.now(),
  });
  if (attachment) attachment.policy = { kind: "verified", scope: scopeAtStart };
  console.log("[bb] policy push applied: revision", doc.data.revision);
}

/** Tests only: forget the port, the language state, any registered approver,
 * and the frame chain. Stored policy state deliberately stays - suites that
 * need a clean store reset fakeBrowser storage. */
export function resetPolicySyncForTests(): void {
  port = null;
  lang = null;
  unpinnedApprover = null;
  frameChain = Promise.resolve();
}
