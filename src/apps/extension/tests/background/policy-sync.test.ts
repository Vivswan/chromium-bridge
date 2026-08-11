// ADR-0032 Phase 3: the extension's policy consumption core (policy-sync.ts).
// Pins the fail-closed matrix of decisions 3 and 4 over the golden vectors
// (Rust-signed baselines, replayed through the real WebCrypto verify -> strict
// parse -> ratchet -> storage path) plus crafted documents signed by an
// in-test key playing the pinned Enclave key:
// - accept: rev1 then rev2, idempotent byte-identical replay, restriction
//   overlays, touched-set-scoped relaxations;
// - refuse WITHOUT state change: ok:false, missing baseline, unsigned on a
//   pinned extension, flipped bytes, wrong pin (also marks compromised),
//   replayed lower revision, revision reuse with different bytes, the
//   overlay-strip replay, relaxations outside the signed touched set,
//   relaxing overlays;
// - the per-connection barrier: inert pre-cutover, refusing post-cutover
//   until THIS connection saw a verified push under the current scope;
//   reconnects never inherit;
// - the scope-stamped ratchet (findings 1 and 2): a record goes inert the
//   instant the pin scope no longer matches; a same-key re-pair retains the
//   anchor (refusing an old-baseline replay) while a different-key re-pair
//   resets it; an unpinned->pinned transition mid-approval is dropped at
//   commit (never enforcing an unsigned doc under a just-pinned key);
// - corrupt stored state / cutover flag LATCHES CLOSED, distinct from absent
//   (finding 3), and a fresh push cannot silently overwrite it;
// - compromise drops this connection's verified mark and stays fail-closed
//   even when the compromise persist itself fails (finding 4);
// - armCutover is armed BEFORE the record write, so an armed + absent store
//   denies rather than enforcing legacy;
// - refusals and the compromise mark route to the audit ring;
// - the unpinned lane fails closed while Lane U's approver seam is empty,
//   consults the approver on every relaxation (a rejecting OR throwing
//   approver refuses with no state write and no verified mark), collapses a
//   push held at the approver ONLY on a full match - same baseline, same
//   overlay, same attachment (U6/UF-1: a distinct overlay is a tightening
//   that must land; a reconnect's push must earn the NEW connection its own
//   mark) - and never enforces (or stores) the unauthenticated revision
//   field: a forged revision=MAX "restriction" cannot brick later unsigned
//   pushes, and pairing starts the signed ratchet on a fresh scope;
// - an approved unsigned push can never REPLACE a retained pinned-scope
//   record (U1): the revoke->approve->same-key-re-pair interleave cannot
//   launder away the anti-replay anchor and resurrect an old signed
//   baseline - refused BEFORE the prompt (UF-2, audited), with the write
//   throw as backstop.
// - the decision-8 legacy-settings send-once (Phase 4): only reason:"absent"
//   from a pinned peer with fresh-nonce proof on THIS connection (challenged
//   under the CURRENT pin epoch), on a pre-cutover extension with hardened
//   storage, with the durable flag unset, ships the exact 16-field bag -
//   exactly once, ever; every weaker shape (unproven, unpinned, wrong key,
//   damaged/unreadable/missing reason, tampered flag, reconnect, re-pair,
//   challenge-window re-pair, in-life OR durable compromise, unhardenable
//   storage, post-cutover) posts nothing.
// - the decision-7 language lane (Phase 4): an accepted lang_current writes
//   ONLY the uiLanguage key (sequence-suppressed, enum-refused without
//   advancing the cursor) and NEVER emits; the whole lane - apply, adoption,
//   gesture - is gated on the PINNED trust bar (while-paired scope, one
//   deliberate notch below the bag's pinned+proven); the seq-0 first-pairing
//   adoption offers an explicitly-set local value exactly once per
//   connection; the gesture path (chooseLanguage) is the only other lang_set
//   emitter, gated never-speak-first per connection and serialized on the
//   frame chain; the apply cursor is per-connection (a departed peer's huge
//   seq cannot wedge the genuine host) and commits only after the storage
//   write held; and a full set-push-apply cycle emits exactly ONE lang_set
//   (the ADR-mandated echo-loop test).
//
// The pin store is mocked (the fixture key is deny-listed as a real pin by
// design); everything below it - crypto, schemas, ratchet, storage - is real.
// Flagged for the isolated-browser suite (CHROME_BIN): that the ratchet and
// cutover actually survive real SW death, and the decision 4 in-flight rule
// under a real mid-confirmation push.

import {
  LEGACY_DEFAULTS,
  POLICY_DEFAULTS,
  POLICY_FIELDS,
  POLICY_REVISION_MAX,
  PolicyDocSchema,
  type PolicyValues,
  policyValuesFromDoc,
} from "@chromium-bridge/shared";
import { POLICY_GOLDEN_FIXTURE } from "@chromium-bridge/shared/testing";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";
import {
  base64Decode,
  base64Encode,
  buildPolicyMessage,
  computeKeyId,
} from "@/lib/background/enclave-verify";
import {
  attachPort,
  chooseLanguage,
  currentConnectionToken,
  currentPinGeneration,
  detachPort,
  getLangState,
  getPolicySnapshotForTests,
  getStoredPolicyState,
  handlePolicyFrame,
  isPolicyFrame,
  notePinProvenOnConnection,
  onPinPinned,
  onPinRevoked,
  policyCutoverArmed,
  policyDispatchGate,
  resetPolicySyncForTests,
  setUnpinnedRelaxationApprover,
} from "@/lib/background/policy-sync";
import { resetStorageHardeningForTests } from "@/lib/background/trusted-storage";

// The pin store is mocked: production deny-lists the golden-fixture key as a
// pin (its scalar is public repo data), which is exactly why the replay must
// inject it here. setCompromised is captured so the "crypto mismatch marks
// compromised" posture is assertable.
const pinState = vi.hoisted(() => ({
  pin: null as null | { keyId: string; pubkeyB64: string; pinnedAt: number },
  compromised: null as null | { reason: string; at: number },
  throwOnSetCompromised: false,
  /** Fires on every getPin read: lets a test land state changes INSIDE an
   * await window of the code under test (the mid-send compromise probe). */
  onGetPin: null as null | (() => void),
}));

vi.mock("@/lib/background/enclave-pin", () => ({
  getPin: () => {
    pinState.onGetPin?.();
    return Promise.resolve(pinState.pin);
  },
  getCompromised: () => Promise.resolve(pinState.compromised),
  setCompromised: (mark: { reason: string; at: number }) => {
    if (pinState.throwOnSetCompromised) return Promise.reject(new Error("trusted storage full"));
    pinState.compromised = mark;
    return Promise.resolve();
  },
}));

// The audit ring is spied, not exercised end to end: this suite asserts WHICH
// security events the consumer routes to the ring (the compromise mark and the
// attack-shaped refusals), which is the contract the task pins.
const auditCalls = vi.hoisted(() => ({ events: [] as { kind: string; fields: unknown }[] }));

vi.mock("@/lib/background/audit-log", () => ({
  auditEvent: (kind: string, fields: unknown) => {
    auditCalls.events.push({ kind, fields });
  },
}));

const fixture = POLICY_GOLDEN_FIXTURE;

function fixturePin(): { keyId: string; pubkeyB64: string; pinnedAt: number } {
  return { keyId: fixture.keyIdHex, pubkeyB64: fixture.pubkeyB64, pinnedAt: 1 };
}

/** A policy_current frame over golden vector `i` (0 = deny-baseline rev 1,
 * 1 = relaxed rev 2 with touched pageEvalEnabled/confirmGraceMs/disabledTools). */
function goldenFrame(i: 0 | 1, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const v = fixture.vectors[i];
  if (!v) throw new Error("missing golden vector");
  return { type: "policy_current", ok: true, baseline: v.docB64, sig: v.sigB64, ...extra };
}

/** The values a golden vector's document carries, derived from the fixture
 * bytes themselves so the expectations cannot drift from the vectors. */
function goldenValues(i: 0 | 1): PolicyValues {
  const v = fixture.vectors[i];
  if (!v) throw new Error("missing golden vector");
  const doc = PolicyDocSchema.parse(JSON.parse(new TextDecoder().decode(base64Decode(v.docB64))));
  return policyValuesFromDoc(doc);
}

// ---- in-test signer (plays the pinned Enclave key for crafted documents) -------

interface Signer {
  pubkeyB64: string;
  keyId: string;
  signDoc(docJson: object): Promise<{ baseline: string; sig: string }>;
}

async function makeSigner(): Promise<Signer> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubkeyB64 = base64Encode(raw);
  const keyId = await computeKeyId(raw);
  return {
    pubkeyB64,
    keyId,
    async signDoc(docJson: object) {
      const bytes = new TextEncoder().encode(JSON.stringify(docJson));
      const sig = new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          kp.privateKey,
          buildPolicyMessage(bytes) as BufferSource,
        ),
      );
      return { baseline: base64Encode(bytes), sig: base64Encode(sig) };
    },
  };
}

function docJson(
  revision: number,
  touched: string[],
  overrides: Partial<PolicyValues> = {},
): Record<string, unknown> {
  return {
    v: 1,
    revision,
    touched,
    ...POLICY_DEFAULTS,
    disabledTools: [...POLICY_DEFAULTS.disabledTools],
    ...overrides,
  };
}

/** An unsigned policy_current frame over a crafted document (the unpinned
 * lane's wire shape: baseline bytes, no signature). */
function unsignedFrame(doc: Record<string, unknown>): Record<string, unknown> {
  return {
    type: "policy_current",
    ok: true,
    baseline: base64Encode(new TextEncoder().encode(JSON.stringify(doc))),
  };
}

let posted: object[];

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
  // The send-once path awaits the #32 storage restriction before reading any
  // trust state; fakeBrowser has no setAccessLevel, so stub a success (the
  // enrollment suite's pattern) and forget the memoized verdict.
  resetStorageHardeningForTests();
  (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = () =>
    Promise.resolve();
  (fakeBrowser.storage.session as unknown as Record<string, unknown>).setAccessLevel = () =>
    Promise.resolve();
  pinState.pin = fixturePin();
  pinState.compromised = null;
  pinState.throwOnSetCompromised = false;
  pinState.onGetPin = null;
  auditCalls.events = [];
  posted = [];
  attachPort((frame) => {
    posted.push(frame);
    return true;
  });
});

async function push(frame: unknown): Promise<void> {
  await handlePolicyFrame(frame);
}

describe("frame classification", () => {
  test("matches the two push tags and nothing else", () => {
    expect(isPolicyFrame({ type: "policy_current", ok: true })).toBe(true);
    expect(isPolicyFrame({ type: "lang_current", value: "en", seq: 1 })).toBe(true);
    expect(isPolicyFrame({ type: "policy_get" })).toBe(false);
    expect(isPolicyFrame({ id: 1, op: "tab_list", args: {} })).toBe(false);
    expect(isPolicyFrame(null)).toBe(false);
    expect(isPolicyFrame("policy_current")).toBe(false);
  });
});

describe("golden-vector replay through the full accept path", () => {
  test("rev 1 (deny baseline) verifies, applies, arms the cutover, and opens this connection's barrier", async () => {
    expect((await policyDispatchGate()).allowed).toBe(true); // pre-cutover: inert
    await push(goldenFrame(0));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(1);
    expect(stored?.effective).toEqual(goldenValues(0));
    expect(await getPolicySnapshotForTests()).toEqual({
      kind: "active",
      effective: goldenValues(0),
    });
    expect((await policyDispatchGate()).allowed).toBe(true);
    // Never-speak-first: consuming pushes posts nothing.
    expect(posted).toEqual([]);
  });

  test("rev 2 (relaxation inside its signed touched set) applies over rev 1", async () => {
    await push(goldenFrame(0));
    await push(goldenFrame(1));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(2);
    expect(stored?.effective).toEqual(goldenValues(1));
    expect(stored?.effective.pageEvalEnabled).toBe(true);
    expect(stored?.effective.confirmGraceMs).toBe(120000);
    expect(stored?.effective.disabledTools).toEqual(["page_upload"]);
    expect(pinState.compromised).toBeNull();
  });

  test("rev 2 then rev 1: the replayed lower revision is refused by the ratchet", async () => {
    await push(goldenFrame(1));
    detachPort();
    attachPort(() => true); // a fresh connection must not inherit the mark
    await push(goldenFrame(0));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(2);
    expect(stored?.effective).toEqual(goldenValues(1));
    expect((await policyDispatchGate()).allowed).toBe(false);
    // A replay is stale genuine data, not crypto evidence about the signer.
    expect(pinState.compromised).toBeNull();
  });

  test("a byte-identical replay is idempotent: it re-opens the barrier without rewriting the store", async () => {
    await push(goldenFrame(0));
    const first = await getStoredPolicyState();
    detachPort();
    attachPort(() => true);
    expect((await policyDispatchGate()).allowed).toBe(false);
    await push(goldenFrame(0));
    expect((await policyDispatchGate()).allowed).toBe(true);
    // Unchanged-write suppression: same record, same `at`.
    expect(await getStoredPolicyState()).toEqual(first);
  });

  test("a flipped baseline byte fails the signature and changes nothing", async () => {
    await push(goldenFrame(0));
    const v = fixture.vectors[1];
    if (!v) throw new Error("missing golden vector");
    const bytes = base64Decode(v.docB64);
    bytes[40] = (bytes[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bytes), sig: v.sigB64 });
    const stored = await getStoredPolicyState();
    // The stored effective is retained, never reverted to defaults.
    expect(stored?.revision).toBe(1);
    expect(stored?.effective).toEqual(goldenValues(0));
    // A signature that does not verify against the pin is evidence about
    // the signer (ADR-0031 posture), not a mere refusal.
    expect(pinState.compromised?.reason).toContain("signature verification");
  });

  test("a genuine push against the WRONG pin is refused, marks compromised, and latches the gate (E2F-1)", async () => {
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 1 };
    await push(goldenFrame(0));
    expect(await getStoredPolicyState()).toBeNull();
    // E2F-1: a signature failure sets the sticky in-life compromise latch, so
    // the dispatch barrier refuses for the rest of this SW life even pre-cutover
    // (in production the durable mark also fails the enrollment gate closed).
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("host-substitution");
    // The snapshot reports the latched compromised arm - the honest sum, not
    // a defaults object a test could mistake for an applied policy.
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "compromised" });
    expect(pinState.compromised?.reason).toContain("signature verification");
  });

  test("an unsigned baseline on a pinned extension is refused outright (no window lane)", async () => {
    const v = fixture.vectors[0];
    if (!v) throw new Error("missing golden vector");
    setUnpinnedRelaxationApprover(() => Promise.resolve(true)); // must never be consulted
    await push({ type: "policy_current", ok: true, baseline: v.docB64 });
    expect(await getStoredPolicyState()).toBeNull();
    // A missing signature is a refusal, not crypto evidence.
    expect(pinState.compromised).toBeNull();
  });
});

describe("ok:false and malformed pushes never open the gate", () => {
  test("ok:false leaves the connection in the deny state post-cutover", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    await push({ type: "policy_current", ok: false, error: "store unreadable" });
    expect((await policyDispatchGate()).allowed).toBe(false);
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("ok:true without baseline bytes is refused", async () => {
    await push({ type: "policy_current", ok: true, sig: "AA==" });
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("an overlay field outside the catalogue fails the whole frame", async () => {
    await push(goldenFrame(0, { overlay: { pageEvalEnabled: false, sneaky: true } }));
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("an unknown top-level frame key cannot influence the accepted policy", async () => {
    // The frame wrapper is R5-loose, so the extra key parses THROUGH; the
    // consumer must read fields by name only and never fold the frame.
    await push(
      goldenFrame(0, {
        pageEvalEnabled: true,
        evil: { pageEvalEnabled: true },
      }),
    );
    const stored = await getStoredPolicyState();
    expect(stored?.effective).toEqual(goldenValues(0));
    expect(stored?.effective.pageEvalEnabled).toBe(false);
  });

  test("baseline bytes that are not the strict document are refused after a valid signature", async () => {
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const { baseline, sig } = await signer.signDoc({ v: 1, revision: 1, unknown: true });
    await push({ type: "policy_current", ok: true, baseline, sig });
    expect(await getStoredPolicyState()).toBeNull();
    expect(pinState.compromised).toBeNull(); // the signature held; the shape refused
  });
});

describe("overlay direction check (fail the WHOLE push)", () => {
  test("a restricting overlay folds into the stored effective", async () => {
    await push(
      goldenFrame(1, {
        overlay: { pageEvalEnabled: false, disabledTools: ["page_upload", "page_eval"] },
      }),
    );
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
    expect(stored?.effective.disabledTools).toEqual(["page_upload", "page_eval"]);
    expect(stored?.effective.confirmGraceMs).toBe(120000); // untouched baseline value kept
  });

  test("one relaxing overlay entry refuses the entire push, restrictions and all", async () => {
    await push(goldenFrame(1, { overlay: { pageEvalEnabled: false, confirmGraceMs: 130000 } }));
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("a zero hostReverifyMs overlay is a relaxation (zero-top), not a numeric decrease", async () => {
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const { baseline, sig } = await signer.signDoc(docJson(1, [], { hostReverifyMs: 60000 }));
    await push({ type: "policy_current", ok: true, baseline, sig, overlay: { hostReverifyMs: 0 } });
    expect(await getStoredPolicyState()).toBeNull();
  });
});

describe("the value ratchet (crafted signed documents)", () => {
  let signer: Signer;

  beforeEach(async () => {
    signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
  });

  async function signedFrame(
    doc: Record<string, unknown>,
    extra: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const { baseline, sig } = await signer.signDoc(doc);
    return { type: "policy_current", ok: true, baseline, sig, ...extra };
  }

  test("a higher-revision relaxation OUTSIDE its signed touched set is refused", async () => {
    await push(await signedFrame(docJson(1, [])));
    await push(await signedFrame(docJson(2, ["evalMask"], { cdpMode: true, evalMask: false })));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(1);
    expect(stored?.effective.cdpMode).toBe(false);
  });

  test("the same relaxation applies when the touched set names every relaxed field", async () => {
    await push(await signedFrame(docJson(1, [])));
    await push(
      await signedFrame(docJson(2, ["cdpMode", "evalMask"], { cdpMode: true, evalMask: false })),
    );
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(2);
    expect(stored?.effective.cdpMode).toBe(true);
    expect(stored?.effective.evalMask).toBe(false);
  });

  test("the overlay-strip replay is refused: genuine bytes, genuine signature, stripped restriction", async () => {
    const doc = docJson(3, ["pageEvalEnabled"], { pageEvalEnabled: true });
    await push(await signedFrame(doc, { overlay: { pageEvalEnabled: false } }));
    let stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
    // Same revision, same bytes, overlay gone: relaxes the stored effective
    // with no fresh revision - refused however genuine the signature is.
    await push(await signedFrame(doc));
    stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
  });

  test("revision reuse with DIFFERENT bytes is refused even when nothing relaxes", async () => {
    await push(await signedFrame(docJson(1, [])));
    await push(await signedFrame(docJson(1, [], { disabledTools: ["page_eval"] })));
    const stored = await getStoredPolicyState();
    expect(stored?.effective.disabledTools).toEqual([]);
  });

  test("a fresh restriction needs no touched entry and applies", async () => {
    await push(await signedFrame(docJson(1, [])));
    await push(await signedFrame(docJson(2, [], { disabledTools: ["page_eval"] })));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(2);
    expect(stored?.effective.disabledTools).toEqual(["page_eval"]);
  });

  test("the ratchet anchors on STORAGE, so it survives module-state loss (SW restart)", async () => {
    await push(await signedFrame(docJson(2, [])));
    resetPolicySyncForTests(); // the SW died; storage did not
    attachPort(() => true);
    await push(await signedFrame(docJson(1, [])));
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(2);
  });
});

describe("the dispatch barrier and the one-way cutover", () => {
  test("pre-cutover the barrier is inert even with no port at all", async () => {
    detachPort();
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("post-cutover a connection that saw no verified push is refused (stable reason)", async () => {
    await push(goldenFrame(0));
    detachPort();
    attachPort(() => true);
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("policy barrier");
    // And with the port down entirely, still refused.
    detachPort();
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("a killed bridge still processes pushes (this module consults no gates)", async () => {
    await fakeBrowser.storage.local.set({ bridgeKillMirror: { state: "killed", at: 1 } });
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("re-pair/pin-reset drops the verified mark but NEVER the cutover", async () => {
    await push(goldenFrame(1));
    expect((await policyDispatchGate()).allowed).toBe(true);
    // onPinRevoked RETAINS the ratchet record (finding 2: a same-key re-pair
    // must still refuse an old-baseline replay) and only drops this
    // connection's verified mark. The cutover flag survives.
    await onPinRevoked(fixture.keyIdHex);
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect(await policyCutoverArmed()).toBe(true);
    // The mark is dropped: deny + barrier until a fresh push on this connection.
    expect((await policyDispatchGate()).allowed).toBe(false);
    // A fresh verified push under the (still-mocked, same) pin re-opens.
    await push(goldenFrame(1));
    expect((await policyDispatchGate()).allowed).toBe(true);
    expect((await getStoredPolicyState())?.revision).toBe(2);
  });
});

describe("the scope-stamped ratchet (findings 1 and 2)", () => {
  test("a stored record goes inert the instant the pin scope no longer matches", async () => {
    await push(goldenFrame(1)); // active under the fixture-key scope
    expect((await policyDispatchGate()).allowed).toBe(true);
    // A different key is now pinned (a re-pair). The record's scope no longer
    // matches the current pin, so it is inert: deny baseline, barrier closed -
    // the old effective is never enforced under the new key.
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "awaitingBaseline" });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // Pinning the ORIGINAL key back re-activates the retained anchor (finding
    // 2): the record's scope matches again, so its ratchet governs once more.
    pinState.pin = fixturePin();
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect(await getPolicySnapshotForTests()).toEqual({
      kind: "active",
      effective: goldenValues(1),
    });
  });

  test("same-key re-pair retains the anchor, so an OLD lower-revision baseline replay is refused (finding 2)", async () => {
    // rev 2 lands, then the user revokes and re-pairs the SAME key.
    await push(goldenFrame(1));
    // Model the ACTUAL unpinned interval (E2F-6): pin=null between revoke and
    // re-pair. The retained record's scope no longer matches (unpinned), so it
    // goes inert - deny baseline, barrier closed - even though the anchor
    // survives in storage.
    pinState.pin = null;
    await onPinRevoked(fixture.keyIdHex); // record RETAINED across revoke
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "awaitingBaseline" });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // The SAME key is re-pinned: anchor kept, NOT cleared, scope matches again.
    pinState.pin = fixturePin();
    await onPinPinned(fixture.keyIdHex);
    expect((await getStoredPolicyState())?.revision).toBe(2);
    // A hostile host now replays the genuine, validly-signed rev-1 baseline on a
    // fresh connection. With the anchor gone this would apply as first-ever; with
    // it retained the revision ratchet refuses it, and the barrier stays closed.
    detachPort();
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect((await getStoredPolicyState())?.effective).toEqual(goldenValues(1));
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("U1: an APPROVED unsigned push during the unpinned window cannot destroy the retained pinned anchor", async () => {
    // rev 2 lands under the pinned fixture key, then the user revokes.
    await push(goldenFrame(1));
    pinState.pin = null;
    await onPinRevoked(fixture.keyIdHex);
    // THE ATTACK: during the unpinned window a hostile host pushes an
    // UNSIGNED "restriction" with an armed approver (the user would approve -
    // it looks harmless). Were the commit allowed to land, the scope-null
    // record would OVERWRITE the retained pinned-scope record - the
    // anti-replay anchor - and a same-key re-pair would then read
    // awaitingBaseline, letting an old signed baseline replay as first-ever
    // with zero fresh presence. (Since UF-2 the refusal fires BEFORE the
    // prompt; the writeStoredRecord throw remains the backstop, pinned by its
    // own test in the Lane U describe.)
    setUnpinnedRelaxationApprover(() => Promise.resolve(true));
    await push(unsignedFrame(docJson(1, [], { disabledTools: ["page_eval"] })));
    // Refused fail-closed: the pinned anchor survives byte-for-byte, nothing
    // was stored for the unpinned scope, and the barrier stays closed.
    const retained = await getStoredPolicyState();
    expect(retained?.scope).toBe(fixture.keyIdHex);
    expect(retained?.revision).toBe(2);
    expect(retained?.effective).toEqual(goldenValues(1));
    expect((await policyDispatchGate()).allowed).toBe(false);
    // The user re-pairs the SAME key: the anchor is back in scope...
    pinState.pin = fixturePin();
    await onPinPinned(fixture.keyIdHex);
    // ...so the old, more-permissive genuinely-signed rev-1 baseline replay
    // is REFUSED - the ratchet demands a strictly newer signed document, and
    // the barrier stays closed (fresh verification demanded).
    detachPort();
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect((await getStoredPolicyState())?.effective).toEqual(goldenValues(1));
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("UF-2: a post-revoke unsigned push is refused and audited BEFORE the approver is consulted", async () => {
    await push(goldenFrame(1));
    pinState.pin = null;
    await onPinRevoked(fixture.keyIdHex);
    const consulted = vi.fn(() => Promise.resolve(true));
    setUnpinnedRelaxationApprover(consulted);
    auditCalls.events = [];
    await push(unsignedFrame(docJson(1, [], { disabledTools: ["page_eval"] })));
    // Validate-before-prompt: the push can never commit (U1's preservation
    // rule), so the user is never asked to burn an approval gesture on it,
    // and the refusal reaches the audit ring instead of dying as a throw
    // swallowed by frameChain's silent catch.
    expect(consulted).not.toHaveBeenCalled();
    expect(
      auditCalls.events.some(
        (e) => e.kind === "policy_refused" && JSON.stringify(e.fields).includes("pinned-scope"),
      ),
    ).toBe(true);
    const retained = await getStoredPolicyState();
    expect(retained?.scope).toBe(fixture.keyIdHex);
    expect(retained?.revision).toBe(2);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("different-key re-pair resets the ratchet: onPinPinned clears the retained record", async () => {
    await push(goldenFrame(1));
    // The revoke records the fixture key as the DURABLE prior identity (H1);
    // key-novelty at the next pin is decided against it.
    await onPinRevoked(fixture.keyIdHex);
    const other = await makeSigner();
    // A DIFFERENT key is pinned: prior=fixture, new=other, so the retained
    // fixture-key record is cleared and the new scope starts fresh.
    await onPinPinned(other.keyId);
    expect(await getStoredPolicyState()).toBeNull();
    expect(await policyCutoverArmed()).toBe(true); // one-way, survives the reset
  });

  test("unpinned->pinned mid-approval: the unsigned push is dropped at commit, not enforced under the new pin (finding 1)", async () => {
    // The exact codex-u interleave: an unpinned relaxing push waits on the
    // (arbitrarily long) approver; pairing lands DURING that window. The
    // commit-time scope recheck must catch unpinned-at-snapshot ->
    // pinned-at-commit and REFUSE, or a just-pinned extension would enforce an
    // UNSIGNED document with the barrier open (the no-downgrade violation).
    pinState.pin = null; // unpinned at snapshot
    const v = fixture.vectors[0];
    if (!v) throw new Error("missing golden vector");
    setUnpinnedRelaxationApprover(async () => {
      // Pairing completes on the runtime-message path (a separate queue) while
      // the approver is awaited: the machine is now pinned.
      pinState.pin = fixturePin();
      return true;
    });
    // An UNSIGNED first-ever document rides the unpinned lane and needs approval.
    await push({ type: "policy_current", ok: true, baseline: v.docB64 });
    // Refused: nothing stored, cutover never armed, no verified mark.
    expect(await getStoredPolicyState()).toBeNull();
    expect(await policyCutoverArmed()).toBe(false);
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "legacy" });
    // A subsequent SIGNED rev-1 push under the now-pinned key applies cleanly -
    // it was not clobbered by a stale revision-0 write from the dropped push.
    setUnpinnedRelaxationApprover(null);
    detachPort();
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("an ABA same-key revoke+re-pair mid-verify is dropped by the generation epoch (E2F-2)", async () => {
    // rev 1 lands, active under the fixture key.
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    // A rev 2 push arrives. Mid-flight - modeled by firing on the
    // resolvePolicyState storage read - the user revokes and re-pairs the SAME
    // key. The keyId is unchanged, so the commit-time SCOPE recheck alone would
    // pass; only the generation epoch, bumped by each transition, catches the
    // ABA and drops the push (the verified-mark / no-downgrade invariant).
    let fired = false;
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
    };
    local.get = async (k) => {
      const keys = Array.isArray(k) ? k : [k];
      if (!fired && keys.includes("bridgePolicyState") && keys.includes("bridgePolicyCutover")) {
        fired = true;
        local.get = realGet as never; // the transitions below read storage too
        await onPinRevoked(fixture.keyIdHex); // gen bump 1
        await onPinPinned(fixture.keyIdHex); // same key: scope unchanged, gen bump 2
      }
      return realGet(k);
    };
    await push(goldenFrame(1));
    local.get = realGet as never;
    // Dropped at commit: the stored ratchet still shows rev 1, not rev 2, and
    // the connection holds no verified mark under the new generation.
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });
});

describe("policy consumption hardening (durable prior pin H1, F2 latch, F3/H4 undo, E2F-5)", () => {
  test("H1: the durable prior survives an SW restart, so a different-key re-pair still recovers a corrupt cutover flag", async () => {
    // THE REGRESSION: with the prior identity held only in memory, every re-pair
    // after an SW restart read as "prior unknown" -> never a new key -> the
    // normalize path never ran. Since armCutover THROWS on a corrupt flag and
    // nothing else in the codebase clears it, a tampered flag was permanently
    // unrecoverable and LATCHED_REASON's "revoke and re-pair" promise was false.
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: "yes" });
    expect(await policyDispatchGate()).toMatchObject({ allowed: false }); // latched
    // The user revokes. The revoke writes the durable prior identity.
    await onPinRevoked(fixture.keyIdHex);
    expect((await fakeBrowser.storage.local.get("bridgePolicyPriorPin")).bridgePolicyPriorPin).toBe(
      fixture.keyIdHex,
    );
    // THE SERVICE WORKER DIES between the revoke and the re-pair (the common MV3
    // case): every in-memory latch, epoch, and mirror is gone. Storage is not.
    resetPolicySyncForTests();
    attachPort(() => true);
    // The user re-pairs with a FRESH key. Novelty is decided against the durable
    // prior, so this is recognized as new and the corrupt flag is normalized.
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
    await onPinPinned(other.keyId);
    const raw = await fakeBrowser.storage.local.get("bridgePolicyCutover");
    expect(raw.bridgePolicyCutover).toBe(true); // exactly `true`: recovered, one-way preserved
    // The prior is CONSUMED, so a much later re-pair cannot re-decide against it.
    expect(
      (await fakeBrowser.storage.local.get("bridgePolicyPriorPin")).bridgePolicyPriorPin,
    ).toBeUndefined();
    // Recovery lands in awaitingBaseline: armed, no record, barrier closed.
    expect(await policyCutoverArmed()).toBe(true);
    expect(await getStoredPolicyState()).toBeNull();
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("H1: a SAME-key re-pair across an SW restart is still not new, so a corrupt flag stays latched", async () => {
    // The mirror image of the test above: the durable prior must DECIDE novelty,
    // not merely make every re-pair look new. Re-pinning the very key that was
    // revoked is not fresh evidence, so nothing is cleared or normalized.
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: "yes" });
    await onPinRevoked(fixture.keyIdHex);
    resetPolicySyncForTests();
    attachPort(() => true);
    await onPinPinned(fixture.keyIdHex);
    const raw = await fakeBrowser.storage.local.get("bridgePolicyCutover");
    expect(raw.bridgePolicyCutover).toBe("yes"); // untouched: still tampering evidence
    expect(await policyDispatchGate()).toMatchObject({ allowed: false });
  });

  test("H1: known-A -> revoke -> re-pair A retains the ratchet across an SW restart (finding 2)", async () => {
    // The anchor must survive the restart too, or the old-baseline replay that
    // finding 2 closed would reopen on every re-paired worker.
    await push(goldenFrame(1)); // rev 2 active under the fixture key
    await onPinRevoked(fixture.keyIdHex);
    resetPolicySyncForTests(); // the SW dies mid-ceremony
    attachPort(() => true);
    await onPinPinned(fixture.keyIdHex); // SAME key: not new, anchor retained
    expect((await getStoredPolicyState())?.revision).toBe(2);
    // The hostile host replays the genuine, validly-signed rev-1 baseline: the
    // retained anchor refuses it, and the barrier stays closed.
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("F2: a same-key re-pair keeps the compromise latch (no stored record); a different-key re-pair clears it", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    // Set the sticky latch: a flipped-byte baseline fails the fixture-key sig.
    const v = fixture.vectors[0];
    if (!v) throw new Error("missing golden vector");
    const bad = base64Decode(v.docB64);
    bad[40] = (bad[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bad), sig: v.sigB64 });
    expect(await getStoredPolicyState()).toBeNull(); // nothing stored
    let gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("host-substitution");
    // A SAME-key re-pair with NO stored record must NOT clear the latch. The F2
    // bug: the old sameScope check read the absent record as !sameScope and
    // wrongly cleared the latch (promised "cleared ONLY on a NEW-key re-pair").
    await onPinRevoked(fixture.keyIdHex);
    await onPinPinned(fixture.keyIdHex);
    gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("host-substitution");
    // A DIFFERENT-key re-pair IS genuine new evidence: it clears the latch, and
    // a fresh push signed by that key then opens the barrier.
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
    await onPinRevoked(fixture.keyIdHex);
    await onPinPinned(other.keyId);
    detachPort();
    attachPort(() => true);
    const { baseline, sig } = await other.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline, sig });
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("E2F-5: resolution reads the cutover flag and the record in a SINGLE two-key storage.get", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    const calls: (string | string[])[] = [];
    const local = fakeBrowser.storage.local as unknown as {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
    };
    local.get = (k) => {
      calls.push(k);
      return realGet(k);
    };
    await getPolicySnapshotForTests();
    local.get = realGet as never;
    // Exactly one get names BOTH policy keys together (no torn two-get read),
    // and neither key is fetched on its own.
    const twoKeyGets = calls.filter(
      (k) =>
        Array.isArray(k) && k.includes("bridgePolicyCutover") && k.includes("bridgePolicyState"),
    );
    expect(twoKeyGets).toHaveLength(1);
    const singleKeyGets = calls.filter(
      (k) => k === "bridgePolicyCutover" || k === "bridgePolicyState",
    );
    expect(singleKeyGets).toHaveLength(0);
  });

  test("F3: an ABA revoke+re-pair DURING the commit writes leaves no stale record and stamps no mark", async () => {
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const rev1 = await signer.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
    // A rev-2 push. Fire a SAME-key revoke+re-pair while the rev-2 RECORD write
    // is in flight - the window AFTER the pre-write recheck. The keyId is
    // unchanged, so only the generation epoch catches the ABA; the F3 end recheck
    // must UNDO the stale rev-2 write (restore rev 1) and stamp no mark.
    const rev2 = await signer.signDoc(docJson(2, []));
    const realSet = fakeBrowser.storage.local.set.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      set: (o: Record<string, unknown>) => Promise<void>;
    };
    let fired = false;
    local.set = async (obj) => {
      const rec = obj.bridgePolicyState as { revision?: number } | undefined;
      if (!fired && rec?.revision === 2) {
        fired = true;
        local.set = realSet as never;
        await realSet(obj); // the stale rev-2 record lands...
        await onPinRevoked(signer.keyId); // gen bump 1
        await onPinPinned(signer.keyId); // SAME key: no reset, scope unchanged, gen bump 2
        return;
      }
      return realSet(obj);
    };
    await push({ type: "policy_current", ok: true, baseline: rev2.baseline, sig: rev2.sig });
    local.set = realSet as never;
    // The stale rev-2 write was undone (restored to rev 1); the connection holds
    // no verified mark under the new generation, so the barrier is closed.
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("HC-3: a reset landing during the prior-snapshot read does not resurrect the dead anchor (epoch captured before the read)", async () => {
    // The undo restores the pre-write anchor - UNLESS a ratchet reset ran while
    // this push was in flight, in which case that anchor is dead and must be
    // removed. The discriminator is WHERE the reset epoch is captured: if it were
    // captured AFTER the awaited prior-snapshot read, a reset completing DURING
    // that read would leave the undo comparing equal epochs and restoring the
    // dead anchor. Captured BEFORE the read, the undo sees the epoch move and
    // removes. This hooks the single-key bridgePolicyState read so a GENUINE
    // new-key revoke+re-pair lands the instant it resolves.
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const rev1 = await signer.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    expect((await getStoredPolicyState())?.revision).toBe(1);
    const rev2 = await signer.signDoc(docJson(2, []));
    const other = await makeSigner();
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
    };
    let fired = false;
    local.get = async (k) => {
      const result = await realGet(k);
      const single = typeof k === "string" ? k : Array.isArray(k) && k.length === 1 ? k[0] : null;
      if (!fired && single === "bridgePolicyState") {
        fired = true;
        local.get = realGet as never;
        // A genuine new-key revoke+re-pair: bumps the reset epoch AND deletes the
        // rev-1 anchor, exactly the continuation the capture-before guards against.
        await onPinRevoked(signer.keyId);
        await onPinPinned(other.keyId);
        pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
      }
      return result;
    };
    await push({ type: "policy_current", ok: true, baseline: rev2.baseline, sig: rev2.sig });
    local.get = realGet as never;
    // The dead rev-1 anchor was removed, not restored: the record is absent and
    // the barrier is closed. (Captured after the read, this would read rev 1.)
    expect(await getStoredPolicyState()).toBeNull();
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("H4: an A->B->A transition during a stalled push does not resurrect the reset anchor", async () => {
    // Both new-key pins RESET the ratchet (they remove the record). If the undo
    // blindly restored its pre-write snapshot, the A/rev-1 anchor would come back
    // ACTIVE under scope A - silently defeating the reset and refusing legitimate
    // lower-revision A policies. The reset epoch makes the undo remove instead.
    const a = await makeSigner();
    const b = await makeSigner();
    pinState.pin = { keyId: a.keyId, pubkeyB64: a.pubkeyB64, pinnedAt: 1 };
    const rev1 = await a.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    expect((await getStoredPolicyState())?.revision).toBe(1);
    const rev2 = await a.signDoc(docJson(2, []));
    const realSet = fakeBrowser.storage.local.set.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      set: (o: Record<string, unknown>) => Promise<void>;
    };
    let fired = false;
    local.set = async (obj) => {
      const rec = obj.bridgePolicyState as { revision?: number } | undefined;
      if (!fired && rec?.revision === 2) {
        fired = true;
        local.set = realSet as never;
        // A -> B -> A, both legs a genuine new key, so both RESET the ratchet.
        await onPinRevoked(a.keyId);
        await onPinPinned(b.keyId);
        await onPinRevoked(b.keyId);
        await onPinPinned(a.keyId);
        pinState.pin = { keyId: a.keyId, pubkeyB64: a.pubkeyB64, pinnedAt: 3 };
        // ...and only THEN does the stalled push's own write land, so the record
        // is unambiguously ours and the ownership check alone would not save us.
        await realSet(obj);
        return;
      }
      return realSet(obj);
    };
    await push({ type: "policy_current", ok: true, baseline: rev2.baseline, sig: rev2.sig });
    local.set = realSet as never;
    // Neither the stale rev 2 nor the reset-away rev 1 survives: the scope starts
    // fresh, exactly as the two new-key re-pairs intended.
    expect(await getStoredPolicyState()).toBeNull();
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("H4: an undo that itself fails still refuses and audits the race", async () => {
    // The undo is best-effort; the REFUSAL is not. If the restore throws and the
    // exception escapes, frameChain's catch swallows it and the policy_refused
    // audit never fires - the race would go unrecorded.
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const rev1 = await signer.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    const rev2 = await signer.signDoc(docJson(2, []));
    auditCalls.events = [];
    const realSet = fakeBrowser.storage.local.set.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      set: (o: Record<string, unknown>) => Promise<void>;
    };
    let writes = 0;
    local.set = async (obj) => {
      const rec = obj.bridgePolicyState as { revision?: number } | undefined;
      if (rec === undefined) return realSet(obj);
      writes += 1;
      if (writes === 1) {
        await realSet(obj); // the stale rev-2 record lands
        await onPinRevoked(signer.keyId);
        await onPinPinned(signer.keyId); // same key: gen moves, no reset
        return;
      }
      throw new Error("storage unavailable"); // the undo's restore fails
    };
    await push({ type: "policy_current", ok: true, baseline: rev2.baseline, sig: rev2.sig });
    local.set = realSet as never;
    // The refusal and its audit fired despite the failed undo, and the barrier is
    // closed - the push never earned a verified mark.
    expect(auditCalls.events.some((e) => e.kind === "policy_refused")).toBe(true);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("a TAMPERED durable prior (valid-length garbage) does not clear the compromise latch", async () => {
    // The fail-OPEN the shapeless version had: any non-empty string read as a
    // known prior, so a tamperer could make the user's own SAME-key re-pair look
    // new and silently reset the ratchet, clear the latch, and launder a corrupt
    // cutover flag. Structural validation refuses a non-keyId-shaped string, and
    // "unknown" is fail-closed to not-new.
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    const v = fixture.vectors[0];
    if (!v) throw new Error("missing golden vector");
    const bad = base64Decode(v.docB64);
    bad[40] = (bad[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bad), sig: v.sigB64 });
    expect(await policyDispatchGate()).toMatchObject({ allowed: false }); // latch set
    // A tampered prior of the right LENGTH but the wrong alphabet.
    await fakeBrowser.storage.local.set({ bridgePolicyPriorPin: "z".repeat(64) });
    await onPinPinned(fixture.keyIdHex);
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("host-substitution"); // latch survived
  });

  test("classifyPriorPin: non-string and non-hex-string priors both read as unknown", async () => {
    // Both tamper directions land on "unknown" -> not new -> nothing is reset.
    // Exercised through onPinPinned, the only consumer.
    for (const tampered of [
      42,
      { keyId: "x" },
      ["a"],
      true,
      "",
      "not-hex",
      fixture.keyIdHex.toUpperCase(), // uppercase hex is not the keyId shape
      fixture.keyIdHex.slice(0, 63), // one char short
      `${fixture.keyIdHex}0`, // one char long
    ]) {
      fakeBrowser.reset();
      resetPolicySyncForTests();
      attachPort(() => true);
      // A corrupt cutover flag is the visible proof: only a NEW-key re-pair
      // normalizes it, so if the tampered prior were honoured as known this
      // different-key pin would repair the flag.
      await fakeBrowser.storage.local.set({
        bridgePolicyCutover: "yes",
        bridgePolicyPriorPin: tampered,
      });
      const other = await makeSigner();
      await onPinPinned(other.keyId);
      const raw = await fakeBrowser.storage.local.get("bridgePolicyCutover");
      expect(raw.bridgePolicyCutover).toBe("yes"); // untouched: read as not-new
    }
  });

  test("onPinRevoked(null) preserves an existing durable prior (a double revoke)", async () => {
    // A revoke with nothing pinned has no identity to record. It must NOT clear
    // the prior a real revoke already wrote, or the second revoke would strand
    // the very recovery the first one enabled.
    await onPinRevoked(fixture.keyIdHex);
    expect((await fakeBrowser.storage.local.get("bridgePolicyPriorPin")).bridgePolicyPriorPin).toBe(
      fixture.keyIdHex,
    );
    pinState.pin = null;
    await onPinRevoked(null); // nothing pinned this time
    expect((await fakeBrowser.storage.local.get("bridgePolicyPriorPin")).bridgePolicyPriorPin).toBe(
      fixture.keyIdHex,
    );
    // And the preserved prior still decides novelty correctly.
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: "yes" });
    await onPinPinned(other.keyId);
    expect((await fakeBrowser.storage.local.get("bridgePolicyCutover")).bridgePolicyCutover).toBe(
      true,
    );
  });

  test("H5: a raced idempotent replay writes nothing at all - no record write, no undo write", async () => {
    // The idempotent push-on-connect replay writes nothing (setMirror discipline).
    // If a pin transition races THAT push, the undo must not "restore" a record
    // it never replaced - a blind re-set would retrigger every onChanged consumer.
    // TWO independent guards produce this, and the test pins the OBSERVABLE
    // result rather than either one: the `wrote` flag skips the undo outright,
    // and the ownership check would also refuse it because `committed` carries a
    // fresh `at` that no suppressed write ever stored.
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const rev1 = await signer.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    const stored = await getStoredPolicyState();
    expect(stored?.revision).toBe(1);
    // Replay the identical frame on a fresh connection, and fire a same-key ABA
    // during the commit. The record write is suppressed as unchanged, so the
    // commit-end race must simply refuse and touch storage not at all.
    detachPort();
    attachPort(() => true);
    const realSet = fakeBrowser.storage.local.set.bind(fakeBrowser.storage.local);
    const realRemove = fakeBrowser.storage.local.remove.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      set: (o: Record<string, unknown>) => Promise<void>;
      remove: (k: string | string[]) => Promise<void>;
    };
    const recordWrites: string[] = [];
    local.set = async (obj) => {
      if ("bridgePolicyState" in obj) recordWrites.push("set");
      return realSet(obj);
    };
    local.remove = async (k) => {
      if (k === "bridgePolicyState") recordWrites.push("remove");
      return realRemove(k);
    };
    let fired = false;
    const realGet = fakeBrowser.storage.local.get.bind(fakeBrowser.storage.local);
    const localGet = fakeBrowser.storage.local as unknown as {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
    };
    localGet.get = async (k) => {
      const keys = Array.isArray(k) ? k : [k];
      if (!fired && keys.includes("bridgePolicyState") && keys.includes("bridgePolicyCutover")) {
        fired = true;
        localGet.get = realGet as never;
        await onPinRevoked(signer.keyId);
        await onPinPinned(signer.keyId); // same key: gen moves, no reset
      }
      return realGet(k);
    };
    await push({ type: "policy_current", ok: true, baseline: rev1.baseline, sig: rev1.sig });
    local.set = realSet as never;
    local.remove = realRemove as never;
    localGet.get = realGet as never;
    // No record write and no undo write happened at all, and the record stands.
    expect(recordWrites).toEqual([]);
    expect(await getStoredPolicyState()).toEqual(stored);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });
});

describe("the unpinned lane (Lane U seam)", () => {
  beforeEach(() => {
    pinState.pin = null;
  });

  test("with no approval surface registered, the first document is refused, fail closed", async () => {
    await push(goldenFrame(0));
    expect(await getStoredPolicyState()).toBeNull();
    expect((await policyDispatchGate()).allowed).toBe(true); // never armed
  });

  test("an approved relaxation applies; a denied one changes nothing", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(false));
    await push(goldenFrame(0));
    expect(await getStoredPolicyState()).toBeNull();
    setUnpinnedRelaxationApprover((relaxation) => {
      // The seam hands over ONLY the frozen value pair (U4): no live document
      // or other commit input rides along for the approver to hold or mutate.
      expect(Object.keys(relaxation).sort()).toEqual(["effective", "storedEffective"]);
      expect(relaxation.storedEffective).toBeNull();
      // The approver sees FROZEN copies: it cannot mutate the values this push
      // will commit (the commit recomputes none of them).
      expect(Object.isFrozen(relaxation.effective)).toBe(true);
      expect(Object.isFrozen(relaxation.effective.disabledTools)).toBe(true);
      return Promise.resolve(true);
    });
    await push(goldenFrame(0));
    // Unsigned accepts clamp the stored revision to 0: the document's revision
    // field is unauthenticated on this lane and must never seed a ratchet
    // anchor.
    expect((await getStoredPolicyState())?.revision).toBe(0);
    expect(await getPolicySnapshotForTests()).toEqual({
      kind: "active",
      effective: goldenValues(0),
    });
  });

  test("a pure restriction of the stored effective applies silently, no approver needed", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(true));
    await push(goldenFrame(1));
    setUnpinnedRelaxationApprover(null);
    await push(goldenFrame(1, { overlay: { pageEvalEnabled: false } }));
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
  });

  test("the unauthenticated revision never gates the unpinned lane: a lower-revision restriction still applies", async () => {
    const consulted = vi.fn(() => Promise.resolve(true));
    setUnpinnedRelaxationApprover(consulted);
    await push(goldenFrame(1)); // rev 2, relaxed - approved
    consulted.mockClear();
    // A pure restriction of the stored effective (defaults everywhere, the
    // vector's page_upload disable retained) carrying a LOWER revision:
    // applies silently - direction is the unpinned lane's gate, revision is
    // not - and the approver is not consulted for a restriction.
    await push(unsignedFrame(docJson(1, [], { disabledTools: ["page_upload"] })));
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
    expect(stored?.effective.disabledTools).toEqual(["page_upload"]);
    expect(stored?.revision).toBe(0);
    expect(consulted).not.toHaveBeenCalled();
  });

  test("a forged revision=MAX restriction cannot brick later unsigned pushes, and pairing starts a clean signed scope", async () => {
    const consulted = vi.fn(() => Promise.resolve(true));
    setUnpinnedRelaxationApprover(consulted);
    await push(unsignedFrame(docJson(1, [])));
    consulted.mockClear();
    // The forged "restriction" rides the free lane with the largest revision
    // the schema admits. It applies (harmless DoS, decision 3) but its
    // revision is clamped out of the stored record.
    await push(unsignedFrame(docJson(POLICY_REVISION_MAX, [], { disabledTools: ["page_eval"] })));
    expect((await getStoredPolicyState())?.revision).toBe(0);
    expect(consulted).not.toHaveBeenCalled();
    // A later genuine unsigned relaxation still reaches the window and
    // applies on approval - nothing was ratcheted shut.
    await push(unsignedFrame(docJson(1, [], { pageEvalEnabled: true })));
    expect(consulted).toHaveBeenCalledTimes(1);
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(true);
    expect(stored?.revision).toBe(0);
    // Pairing pins a key: the unsigned-era record is OUT OF SCOPE under it
    // (awaitingBaseline - no reset runs, and none is needed), so the signed
    // lane starts a fresh ratchet: the rev-1 golden baseline applies as-is,
    // untouched by the forged revision.
    pinState.pin = fixturePin();
    await onPinPinned(fixture.keyIdHex);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
  });

  test("a REJECTING approver refuses the push: no state write, no verified mark", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(true));
    await push(unsignedFrame(docJson(1, []))); // first doc approved: cutover armed
    // A fresh connection: awaiting until IT verifies a push.
    attachPort(() => true);
    const consulted = vi.fn(() => Promise.resolve(false));
    setUnpinnedRelaxationApprover(consulted);
    await push(unsignedFrame(docJson(2, [], { pageEvalEnabled: true })));
    expect(consulted).toHaveBeenCalledTimes(1);
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
    expect(stored?.revision).toBe(0);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("a THROWING approver reads as refusal (the .catch fallback): no state write, no verified mark", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(true));
    await push(unsignedFrame(docJson(1, []))); // first doc approved: cutover armed
    attachPort(() => true);
    // The window crashing, closing, or the confirm service dying mid-prompt
    // surfaces as a rejected promise; the seam's .catch(() => false) must read
    // it as a refusal, never as an approval or an unhandled rejection.
    const consulted = vi.fn(() => Promise.reject(new Error("approval window crashed")));
    setUnpinnedRelaxationApprover(consulted);
    await push(unsignedFrame(docJson(2, [], { pageEvalEnabled: true })));
    expect(consulted).toHaveBeenCalledTimes(1);
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
    expect(stored?.revision).toBe(0);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });

  test("a byte-identical push arriving while one is already held at the approver is collapsed (U6)", async () => {
    let release!: (approved: boolean) => void;
    const consulted = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          release = resolve;
        }),
    );
    setUnpinnedRelaxationApprover(consulted);
    const frame = unsignedFrame(docJson(1, [], { pageEvalEnabled: true }));
    const first = handlePolicyFrame(frame);
    await vi.waitFor(() => {
      if (consulted.mock.calls.length === 0) throw new Error("not held at the approver yet");
    });
    // THE FLOOD: byte-identical copies while the prompt is pending. Each is
    // dropped at frame entry - it occupies neither the frame chain nor the
    // confirmation FIFO with another 120s prompt; the pending verdict covers
    // these exact bytes.
    const dup1 = handlePolicyFrame(frame);
    const dup2 = handlePolicyFrame(frame);
    release(true);
    await Promise.all([first, dup1, dup2]);
    expect(consulted).toHaveBeenCalledTimes(1);
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(true);
    expect(stored?.revision).toBe(0);
    // The collapse window closes with the verdict: a LATER byte-identical
    // push is restricts-or-equal against the now-stored effective and applies
    // without a prompt (and a denied one would be re-offered on reconnect).
    await push(frame);
    expect(consulted).toHaveBeenCalledTimes(1);
  });

  test("UF-1: a same-baseline push with a DIFFERENT overlay is never collapsed - the tightening lands", async () => {
    let release!: (approved: boolean) => void;
    const consulted = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          release = resolve;
        }),
    );
    setUnpinnedRelaxationApprover(consulted);
    const doc = docJson(1, [], { pageEvalEnabled: true });
    const first = handlePolicyFrame(unsignedFrame(doc));
    await vi.waitFor(() => {
      if (consulted.mock.calls.length === 0) throw new Error("not held at the approver yet");
    });
    // The host tightens mid-window: SAME baseline bytes, RESTRICTING overlay.
    // A legitimately DISTINCT candidate - dropping it as a "duplicate" would
    // fail OPEN against the host's tightening intent (the approved, looser
    // push would govern until the next reconnect).
    const tightened = handlePolicyFrame({
      ...unsignedFrame(doc),
      overlay: { pageEvalEnabled: false },
    });
    release(true);
    await Promise.all([first, tightened]);
    // The tightening serialized behind the verdict and applied silently (a
    // restriction of the just-stored effective needs no prompt).
    expect(consulted).toHaveBeenCalledTimes(1);
    expect((await getStoredPolicyState())?.effective.pageEvalEnabled).toBe(false);
  });

  test("UF-1: a reconnect's byte-identical push-on-connect is never collapsed and earns the NEW connection its mark", async () => {
    let release!: (approved: boolean) => void;
    const consulted = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          release = resolve;
        }),
    );
    setUnpinnedRelaxationApprover(consulted);
    const frame = unsignedFrame(docJson(1, [], { pageEvalEnabled: true }));
    const first = handlePolicyFrame(frame);
    await vi.waitFor(() => {
      if (consulted.mock.calls.length === 0) throw new Error("not held at the approver yet");
    });
    // The port reconnects while the prompt is open; the new connection's
    // push-on-connect carries the same bytes. Collapsing it would strand the
    // NEW attachment barrier-closed until the host happened to re-push: the
    // held push's mark belongs to the dead attachment (and the commit-time
    // attachment recheck refuses to stamp it anywhere else).
    attachPort(() => true);
    const reconnectPush = handlePolicyFrame(frame);
    release(true);
    await Promise.all([first, reconnectPush]);
    // One prompt total: the reconnect replay is restricts-or-equal against
    // the now-stored effective, applying silently - on ITS OWN attachment,
    // which is exactly what opens the live connection's barrier.
    expect(consulted).toHaveBeenCalledTimes(1);
    expect((await getStoredPolicyState())?.effective.pageEvalEnabled).toBe(true);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("U1 backstop: a pinned-scope record landing mid-approval is still refused at the write", async () => {
    const v = fixture.vectors[1];
    if (!v) throw new Error("missing golden vector");
    setUnpinnedRelaxationApprover(async () => {
      // A pinned-scope record (and the cutover) land WHILE the prompt is open
      // - an interleave the UF-2 validate-before-prompt read cannot see. The
      // writeStoredRecord preservation rule is the backstop that still
      // refuses to trade the anchor away.
      await fakeBrowser.storage.local.set({
        bridgePolicyCutover: true,
        bridgePolicyState: {
          scope: fixture.keyIdHex,
          effective: goldenValues(1),
          revision: 2,
          baselineB64: v.docB64,
          at: 5,
        },
      });
      return true;
    });
    await push(unsignedFrame(docJson(1, [])));
    const stored = await getStoredPolicyState();
    expect(stored?.scope).toBe(fixture.keyIdHex);
    expect(stored?.revision).toBe(2);
    expect((await policyDispatchGate()).allowed).toBe(false);
  });
});

describe("lang_current: the shared-language lane (ADR-0032 decision 7, Phase 4)", () => {
  const storedUiLanguage = async (): Promise<unknown> =>
    (await fakeBrowser.storage.local.get("uiLanguage")).uiLanguage;
  const langSets = (): object[] =>
    posted.filter((f) => (f as { type?: string }).type === "lang_set");

  test("apply: an accepted push writes the uiLanguage key and NOTHING else, and never emits", async () => {
    const before = Object.keys(await fakeBrowser.storage.local.get(null));
    await push({ type: "lang_current", value: "zh_CN", seq: 2 });
    expect(getLangState()).toEqual({ value: "zh_CN", seq: 2 });
    expect(await storedUiLanguage()).toBe("zh_CN");
    const after = Object.keys(await fakeBrowser.storage.local.get(null));
    expect(after.sort()).toEqual([...before, "uiLanguage"].sort());
    // The apply path NEVER emits lang_set (the echo-loop rule).
    expect(langSets()).toHaveLength(0);
  });

  test("sequence-suppressed: an equal or lower seq never applies; malformed dropped", async () => {
    await push({ type: "lang_current", value: "zh_TW", seq: 2 });
    await push({ type: "lang_current", value: "en", seq: 2 });
    await push({ type: "lang_current", value: "zh_CN", seq: 1 });
    expect(getLangState()).toEqual({ value: "zh_TW", seq: 2 });
    expect(await storedUiLanguage()).toBe("zh_TW");
    await push({ type: "lang_current", value: "en", seq: 3 });
    expect(getLangState()).toEqual({ value: "en", seq: 3 });
    expect(await storedUiLanguage()).toBe("en");
    // Malformed frames change nothing.
    await push({ type: "lang_current", value: "en" });
    await push({ type: "lang_current", value: 7, seq: 9 });
    expect(getLangState()).toEqual({ value: "en", seq: 3 });
  });

  test("out-of-enum value refused WITHOUT advancing the seq cursor", async () => {
    await push({ type: "lang_current", value: "de", seq: 5 });
    expect(getLangState()).toBeNull();
    expect(await storedUiLanguage()).toBeUndefined();
    // The cursor did not advance, so a genuine push with the SAME seq applies.
    await push({ type: "lang_current", value: "zh_TW", seq: 5 });
    expect(getLangState()).toEqual({ value: "zh_TW", seq: 5 });
    expect(await storedUiLanguage()).toBe("zh_TW");
  });

  test("the equal-value write is skipped (no spurious storage event on the connect replay)", async () => {
    await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
    const set = vi.spyOn(fakeBrowser.storage.local, "set");
    await push({ type: "lang_current", value: "zh_CN", seq: 4 });
    expect(getLangState()).toEqual({ value: "zh_CN", seq: 4 });
    expect(set).not.toHaveBeenCalled();
    set.mockRestore();
  });

  test("a stale local uiLanguage is repaired by the connect push (host canonical, in-memory cursor)", async () => {
    // An offline local pick never reached the host; a fresh SW life starts
    // with an empty cursor, so the host's push-on-connect re-applies the
    // host truth instead of letting the stale local value fight it.
    await fakeBrowser.storage.local.set({ uiLanguage: "zh_TW" });
    await push({ type: "lang_current", value: "en", seq: 6 });
    expect(await storedUiLanguage()).toBe("en");
    expect(langSets()).toHaveLength(0);
  });

  test("seq 0 is no signal: applies nothing", async () => {
    await push({ type: "lang_current", value: "zh_CN", seq: 0 });
    expect(getLangState()).toBeNull();
    expect(await storedUiLanguage()).toBeUndefined();
  });

  test("a failed storage write leaves the cursor unmoved, so the same-seq replay repairs", async () => {
    const set = vi
      .spyOn(fakeBrowser.storage.local, "set")
      .mockRejectedValueOnce(new Error("quota"));
    await push({ type: "lang_current", value: "zh_CN", seq: 2 });
    expect(getLangState()).toBeNull();
    expect(await storedUiLanguage()).toBeUndefined();
    // The host's push-on-reconnect replay of the SAME seq now applies.
    await push({ type: "lang_current", value: "zh_CN", seq: 2 });
    expect(getLangState()).toEqual({ value: "zh_CN", seq: 2 });
    expect(await storedUiLanguage()).toBe("zh_CN");
    set.mockRestore();
  });

  test("a reconnect clears the cursor: a departed peer's huge seq cannot suppress the genuine host", async () => {
    // A paired-but-substituted host wedges the cursor at the JS-safe max...
    await push({ type: "lang_current", value: "en", seq: 9007199254740991 });
    expect(await storedUiLanguage()).toBe("en");
    // ...then disconnects. The genuine host's push-on-connect starts fresh.
    attachPort((frame) => {
      posted.push(frame);
      return true;
    });
    await push({ type: "lang_current", value: "zh_TW", seq: 1 });
    expect(getLangState()).toEqual({ value: "zh_TW", seq: 1 });
    expect(await storedUiLanguage()).toBe("zh_TW");
  });

  describe("the pinned trust bar (while-paired scope, decisions 2 and 7)", () => {
    test("unpinned: a host push never applies - the unpaired extension keeps its local value", async () => {
      pinState.pin = null;
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_TW" });
      await push({ type: "lang_current", value: "en", seq: 5 });
      expect(getLangState()).toBeNull();
      expect(await storedUiLanguage()).toBe("zh_TW");
      expect(langSets()).toHaveLength(0);
    });

    test("unpinned: seq 0 is ignored and does NOT burn the adoption latch", async () => {
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
      pinState.pin = null;
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(0);
      // The pin is established on the same connection: the next seq-0 push
      // imports the local value - "imported directly at first pairing".
      pinState.pin = fixturePin();
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toEqual([{ type: "lang_set", value: "zh_CN" }]);
    });

    test("unpinned: a gesture stays local even on a lang-capable connection", async () => {
      await push({ type: "lang_current", value: "en", seq: 1 });
      pinState.pin = null;
      expect(await chooseLanguage("zh_CN")).toBe(false);
      expect(langSets()).toHaveLength(0);
    });
  });

  describe("first-pairing adoption (seq 0, ADR :652-654)", () => {
    test("an explicitly-set local language is offered exactly ONCE across a full seq-0 -> reply cycle", async () => {
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toEqual([{ type: "lang_set", value: "zh_CN" }]);
      // A repeated seq-0 push (buggy or hostile host) does not re-offer.
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(1);
      // The host adopted and replies with seq 1: applied through the
      // NON-EMITTING apply path - the whole cycle emitted exactly one
      // lang_set (the ADR-mandated loop-absence property).
      await push({ type: "lang_current", value: "zh_CN", seq: 1 });
      expect(getLangState()).toEqual({ value: "zh_CN", seq: 1 });
      expect(await storedUiLanguage()).toBe("zh_CN");
      expect(langSets()).toHaveLength(1);
    });

    test("no explicitly-set local language (key absent): nothing is offered", async () => {
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(0);
    });

    test("a garbage stored uiLanguage is never adopted", async () => {
      await fakeBrowser.storage.local.set({ uiLanguage: "de" });
      await push({ type: "lang_current", value: "en", seq: 0 });
      await fakeBrowser.storage.local.set({ uiLanguage: 7 });
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(0);
    });

    test("seq 0 AFTER a real applied push is inconsistent noise, not an adoption trigger", async () => {
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_TW" });
      await push({ type: "lang_current", value: "zh_TW", seq: 3 });
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(0);
    });

    test("a reconnect re-offers (the legacy-bag posture: a missed adoption costs latency, never the import)", async () => {
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(1);
      attachPort((frame) => {
        posted.push(frame);
        return true;
      });
      await push({ type: "lang_current", value: "en", seq: 0 });
      expect(langSets()).toHaveLength(2);
    });
  });

  describe("chooseLanguage (the gesture path)", () => {
    test("never speaks first: refused until THIS connection saw a lang_current", async () => {
      expect(await chooseLanguage("zh_TW")).toBe(false);
      expect(langSets()).toHaveLength(0);
      await push({ type: "lang_current", value: "en", seq: 1 });
      expect(await chooseLanguage("zh_TW")).toBe(true);
      expect(langSets()).toEqual([{ type: "lang_set", value: "zh_TW" }]);
    });

    test("a reconnect inherits nothing: the new connection must push before a gesture emits", async () => {
      await push({ type: "lang_current", value: "en", seq: 1 });
      attachPort((frame) => {
        posted.push(frame);
        return true;
      });
      expect(await chooseLanguage("zh_CN")).toBe(false);
      expect(langSets()).toHaveLength(0);
    });

    test("detached port: the choice stays local", async () => {
      await push({ type: "lang_current", value: "en", seq: 1 });
      detachPort();
      expect(await chooseLanguage("zh_CN")).toBe(false);
      expect(langSets()).toHaveLength(0);
    });

    test("a gesture racing an in-flight push serializes on the frame chain: apply first, then emit", async () => {
      // Re-attach with a post that snapshots the cursor, so the emission
      // ordering is asserted from the emit itself, not inferred.
      const cursorAtPost: Array<{ value: string; seq: number } | null> = [];
      attachPort((frame) => {
        posted.push(frame);
        cursorAtPost.push(getLangState());
        return true;
      });
      // NOT awaited: the gesture lands while the push is still in flight.
      const pushed = handlePolicyFrame({ type: "lang_current", value: "en", seq: 1 });
      const chosen = chooseLanguage("zh_TW");
      const [, sent] = await Promise.all([pushed, chosen]);
      // The emit succeeded at all only because the chain ran the push FIRST
      // (langSeen was false when the gesture arrived), and the cursor
      // snapshot proves the apply had fully committed before the frame went
      // out - the serialization property the module docs lean on.
      expect(sent).toBe(true);
      expect(langSets()).toEqual([{ type: "lang_set", value: "zh_TW" }]);
      expect(cursorAtPost).toEqual([{ value: "en", seq: 1 }]);
      expect(await storedUiLanguage()).toBe("en");
    });

    test("a full set-push-apply cycle emits exactly ONE lang_set (the ADR-mandated echo-loop test)", async () => {
      // The host's push-on-connect.
      await push({ type: "lang_current", value: "en", seq: 1 });
      // The user's gesture (the picker wrote uiLanguage locally already).
      await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
      expect(await chooseLanguage("zh_CN")).toBe(true);
      expect(langSets()).toHaveLength(1);
      // The host accepted the set, bumped seq, and pushed the echo: the apply
      // path records the cursor and emits NOTHING - one lang_set, total.
      await push({ type: "lang_current", value: "zh_CN", seq: 2 });
      expect(getLangState()).toEqual({ value: "zh_CN", seq: 2 });
      expect(await storedUiLanguage()).toBe("zh_CN");
      expect(langSets()).toEqual([{ type: "lang_set", value: "zh_CN" }]);
    });
  });
});

describe("corrupt stored state latches closed (finding 3)", () => {
  // A corrupt record - a garbage object, or a valid-looking one missing the
  // scope stamp - is DISTINCT from an absent one and must NOT read as absent:
  // that was the fail-open where an older genuine baseline replayed as
  // first-ever while the barrier stayed open and the snapshot fell to
  // POLICY_DEFAULTS (which is NOT the restrictive pole on every field). It now
  // latches closed, the kill-mirror STRICT precedent.
  const CORRUPT = { effective: { pageEvalEnabled: true }, revision: 9, baselineB64: "x" };

  test("corrupt WITH the cutover armed: barrier latched, a fresh push cannot silently fix it", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true, bridgePolicyState: CORRUPT });
    // Latched closed: the snapshot reports cutover (fail-closed), and the gate
    // refuses regardless of any verified mark.
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "compromised" });
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("latched");
    // A genuine signed push is REFUSED while latched: a corrupt store cannot be
    // silently overwritten (that IS the finding-3 replay - an older baseline
    // landing as first-ever). Recovery is a re-pair, below.
    await push(goldenFrame(0));
    expect(await policyDispatchGate()).toMatchObject({ allowed: false });
    // A DIFFERENT-key re-pair clears the corrupt record and recovers. The revoke
    // records the fixture key as the durable prior, so `other` reads as new.
    const other = await makeSigner();
    await onPinRevoked(fixture.keyIdHex);
    await onPinPinned(other.keyId);
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("corrupt WITHOUT the cutover flag is tampering, not absent: it also latches closed", async () => {
    // A record only ever exists after armCutover, so a record present with no
    // cutover flag is an inconsistent/tampered store. The old behavior read
    // this as absent (deny baseline, fresh push accepted); it now fails closed.
    await fakeBrowser.storage.local.set({ bridgePolicyState: CORRUPT });
    expect(await getStoredPolicyState()).toBeNull(); // the raw accessor: corrupt reads null
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("latched");
  });

  test("a corrupt cutover flag (present but not `true`) latches closed", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: "yes" });
    expect(await policyCutoverArmed()).toBe(true); // fail-closed: not `unarmed`
    expect(await policyDispatchGate()).toMatchObject({ allowed: false });
  });
});

describe("compromise closes the connection (finding 4)", () => {
  test("a bad signature drops THIS connection's verified mark, closing the barrier immediately", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    // An earlier genuine push verified this connection (barrier open).
    await push(goldenFrame(0));
    expect((await policyDispatchGate()).allowed).toBe(true);
    // A later push on the SAME connection carries a baseline that fails the pin
    // signature: the verified mark must drop synchronously so the barrier
    // closes now, not only once the enrollment gate later reads the mark.
    const v = fixture.vectors[1];
    if (!v) throw new Error("missing golden vector");
    const bytes = base64Decode(v.docB64);
    bytes[40] = (bytes[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bytes), sig: v.sigB64 });
    expect((await policyDispatchGate()).allowed).toBe(false);
    expect(pinState.compromised?.reason).toContain("signature verification");
    expect(auditCalls.events.some((e) => e.kind === "policy_compromised")).toBe(true);
  });

  test("a failed compromise persist is fail-closed: the barrier still closes", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    await push(goldenFrame(0));
    expect((await policyDispatchGate()).allowed).toBe(true);
    // The compromise write throws (trusted storage full): the connection must
    // still be closed, never proceed as if the compromise was not observed.
    pinState.throwOnSetCompromised = true;
    const v = fixture.vectors[1];
    if (!v) throw new Error("missing golden vector");
    const bytes = base64Decode(v.docB64);
    bytes[40] = (bytes[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bytes), sig: v.sigB64 });
    expect(pinState.compromised).toBeNull(); // the persist failed...
    expect((await policyDispatchGate()).allowed).toBe(false); // ...but the barrier is shut
  });

  test("a failed-persist compromise stays sticky against a replayed genuine frame (E2F-1)", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    // A genuine push verifies this connection: barrier open, record stored.
    await push(goldenFrame(0));
    expect((await policyDispatchGate()).allowed).toBe(true);
    expect((await getStoredPolicyState())?.revision).toBe(1);
    // The host is substituted and sends a bad-signature push; the durable
    // compromise persist THROWS. The sticky in-life latch shuts the barrier.
    pinState.throwOnSetCompromised = true;
    const v = fixture.vectors[1];
    if (!v) throw new Error("missing golden vector");
    const bad = base64Decode(v.docB64);
    bad[40] = (bad[40] ?? 0) ^ 0x01;
    await push({ type: "policy_current", ok: true, baseline: base64Encode(bad), sig: v.sigB64 });
    expect(pinState.compromised).toBeNull(); // no durable mark landed
    expect((await policyDispatchGate()).allowed).toBe(false);
    // THE ATTACK: replay the earlier genuine, byte-identical frame. Its
    // signature verifies and the ratchet would accept it as an idempotent
    // replay - re-marking the attachment verified and reopening the barrier -
    // were it not for the sticky latch folding every resolve to compromised.
    pinState.throwOnSetCompromised = false; // even a working persist cannot help the attacker now
    await push(goldenFrame(0));
    expect((await policyDispatchGate()).allowed).toBe(false);
    // The stored record is untouched: the replay never committed a verified mark.
    expect((await getStoredPolicyState())?.revision).toBe(1);
    // Only a NEW-key re-pair clears the sticky latch (never a valid push). Pin a
    // fresh key and push a document signed by it: the gate opens, proving the
    // latch was lifted by the re-pair and by nothing else above.
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 2 };
    await onPinRevoked(fixture.keyIdHex); // records the durable prior identity
    await onPinPinned(other.keyId); // different key: clears the record and the latch
    detachPort();
    attachPort(() => true);
    const { baseline, sig } = await other.signDoc(docJson(1, []));
    await push({ type: "policy_current", ok: true, baseline, sig });
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });
});

describe("armCutover ordering is fail-closed", () => {
  test("cutover armed with no stored record (SW died between arm and write) denies, never legacy", async () => {
    // The accept path arms cutover BEFORE writing the record: a crash in the
    // gap leaves armed + absent, which resolves to awaitingBaseline - deny
    // baseline + closed barrier - never legacy-enforced-despite-a-policy.
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    expect(await getStoredPolicyState()).toBeNull();
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "awaitingBaseline" });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // Recovery is a fresh verified push, which starts the ratchet cleanly.
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
  });

  test("the write order is cutover-first, and a record-write failure leaves deny (E2F-6)", async () => {
    // Drive the real accept path and INTERCEPT the writes: assert the cutover
    // flag lands before the record, then fail the record write to reproduce the
    // "SW died between arm and write" shape from live code, not a seeded flag.
    const signer = await makeSigner();
    pinState.pin = { keyId: signer.keyId, pubkeyB64: signer.pubkeyB64, pinnedAt: 1 };
    const { baseline, sig } = await signer.signDoc(docJson(1, []));
    const realSet = fakeBrowser.storage.local.set.bind(fakeBrowser.storage.local);
    const local = fakeBrowser.storage.local as unknown as {
      set: (o: Record<string, unknown>) => Promise<void>;
    };
    const writes: string[] = [];
    local.set = (obj) => {
      const keys = Object.keys(obj);
      writes.push(...keys);
      // The record write fails; the cutover write already landed.
      if (keys.includes("bridgePolicyState")) return Promise.reject(new Error("write failed"));
      return realSet(obj);
    };
    await push({ type: "policy_current", ok: true, baseline, sig });
    local.set = realSet as never;
    // Cutover was armed FIRST; the record write came after (and failed).
    expect(writes[0]).toBe("bridgePolicyCutover");
    expect(writes).toContain("bridgePolicyState");
    // The resulting armed + absent-record state denies, never legacy, and no
    // verified mark was set (the commit threw before it).
    expect(await getStoredPolicyState()).toBeNull();
    expect(await policyCutoverArmed()).toBe(true);
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "awaitingBaseline" });
    expect((await policyDispatchGate()).allowed).toBe(false);
  });
});

describe("audit trail for refused pushes", () => {
  test("an attack-shaped refusal routes a policy_refused event; a benign one does not", async () => {
    await push(goldenFrame(0));
    auditCalls.events = [];
    // Overlay relaxes the baseline: an attack-shaped refusal, audited.
    await push(goldenFrame(1, { overlay: { pageEvalEnabled: false, confirmGraceMs: 130000 } }));
    expect(auditCalls.events.some((e) => e.kind === "policy_refused")).toBe(true);
    auditCalls.events = [];
    // A host that simply reports no baseline is benign version-skew: not audited.
    await push({ type: "policy_current", ok: false, error: "store unreadable" });
    expect(auditCalls.events).toEqual([]);
  });
});

describe("the legacy-settings send-once (ADR-0032 decision 8, Phase 4)", () => {
  const SENT_KEY = "legacySettingsSent";

  /** The absent-store push: the ONLY frame allowed to offer the bag. */
  function absentFrame(): Record<string, unknown> {
    return { type: "policy_current", ok: false, error: "no policy store", reason: "absent" };
  }

  /** Stamp fresh-nonce proof of `keyId` onto the CURRENT connection - what
   * enrollment's verify success and a presence round report in production
   * (both capture the token AND the pin epoch at challenge-send time). */
  function proveIdentity(keyId = fixture.keyIdHex): void {
    notePinProvenOnConnection(currentConnectionToken(), keyId, currentPinGeneration());
  }

  /** Await the frame chain (a queued evidence-completed send rides it). */
  async function flushFrameChain(): Promise<void> {
    await handlePolicyFrame({ not: "a frame" });
  }

  async function sentFlag(): Promise<unknown> {
    return (await fakeBrowser.storage.local.get(SENT_KEY))[SENT_KEY];
  }

  /** The exact bag the frame must carry: the 15 legacy policy fields plus
   * requireEnrollment (decision 8 keeps it as history), each at its LEGACY
   * default (legacy-settings.ts, byte-identical to the pre-migration
   * settings schema) unless overridden - and NOTHING else. */
  function expectedBag(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    const bag: Record<string, unknown> = {};
    for (const field of POLICY_FIELDS) bag[field] = LEGACY_DEFAULTS[field];
    bag.disabledTools = [...LEGACY_DEFAULTS.disabledTools];
    bag.requireEnrollment = LEGACY_DEFAULTS.requireEnrollment;
    return { ...bag, ...overrides };
  }

  test("reason:absent on a pinned, proven, pre-cutover connection sends the exact bag once and latches the flag", async () => {
    await fakeBrowser.storage.local.set({
      confirmGraceMs: 5000,
      disabledTools: ["page_upload"],
      requireEnrollment: false,
      // Browser-owned: must NOT ride along in the bag.
      allowAllSites: true,
      groupTabs: false,
      // Fails its own field schema: salvaged to the default, never raw bytes.
      hostReverifyMs: "garbage",
    });
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([
      {
        type: "legacy_settings",
        bag: expectedBag({
          confirmGraceMs: 5000,
          disabledTools: ["page_upload"],
          requireEnrollment: false,
        }),
      },
    ]);
    expect(await sentFlag()).toBe(true);
    expect(auditCalls.events.some((e) => e.kind === "legacy_settings_sent")).toBe(true);
    // The offer changes no policy state: no cutover, no record, gate inert.
    expect(await policyCutoverArmed()).toBe(false);
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("a second reason:absent posts nothing more", async () => {
    proveIdentity();
    await push(absentFrame());
    expect(posted).toHaveLength(1);
    await push(absentFrame());
    expect(posted).toHaveLength(1);
    expect(await sentFlag()).toBe(true);
  });

  test("the durable flag refuses the send on a fresh, proven connection (once, EVER)", async () => {
    await fakeBrowser.storage.local.set({ [SENT_KEY]: true });
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("ANY present flag value reads as sent: tampering suppresses, never re-sends", async () => {
    await fakeBrowser.storage.local.set({ [SENT_KEY]: { weird: 1 } });
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("a pinned but UNPROVEN connection never receives the bag", async () => {
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("an unpinned extension never sends, proof claim or not", async () => {
    pinState.pin = null;
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("proof of a key OTHER than the current pin never sends", async () => {
    proveIdentity("ab".repeat(32));
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("reason damaged / unreadable never trigger (the host is NOT store-less)", async () => {
    proveIdentity();
    await push({ type: "policy_current", ok: false, error: "store damaged", reason: "damaged" });
    await push({
      type: "policy_current",
      ok: false,
      error: "store unreadable",
      reason: "unreadable",
    });
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("an old host that omits reason entirely never triggers (fail closed)", async () => {
    proveIdentity();
    await push({ type: "policy_current", ok: false, error: "no baseline" });
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("a reason outside the enum fails the whole frame and never triggers", async () => {
    proveIdentity();
    await push({ type: "policy_current", ok: false, error: "x", reason: "gone" });
    // ok:false without error fails the ok-split refinement too.
    await push({ type: "policy_current", ok: false, reason: "absent" });
    expect(posted).toEqual([]);
  });

  test("an ok:true frame can never smuggle the absent signal (ok-split)", async () => {
    proveIdentity();
    await push(goldenFrame(0, { reason: "absent" }));
    expect(posted).toEqual([]);
    // And the malformed frame was refused wholesale: no policy state either.
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("proof arriving AFTER the absent report completes the send on the same connection", async () => {
    await push(absentFrame());
    expect(posted).toEqual([]);
    proveIdentity();
    await flushFrameChain();
    expect(posted).toEqual([{ type: "legacy_settings", bag: expectedBag() }]);
    expect(await sentFlag()).toBe(true);
  });

  test("proof earned on a PREVIOUS connection credits nothing after a reconnect", async () => {
    const staleToken = currentConnectionToken();
    detachPort();
    attachPort((frame) => {
      posted.push(frame);
      return true;
    });
    notePinProvenOnConnection(staleToken, fixture.keyIdHex, currentPinGeneration());
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("a reconnect drops the absent report: the new connection must be re-offered", async () => {
    await push(absentFrame()); // unproven: latched, not sent
    detachPort();
    attachPort((frame) => {
      posted.push(frame);
      return true;
    });
    proveIdentity(); // proven on the NEW connection, which saw no absent push
    await flushFrameChain();
    expect(posted).toEqual([]);
  });

  test("a re-pair between the proof and the absent push invalidates the proof (generation)", async () => {
    proveIdentity();
    await onPinRevoked(fixture.keyIdHex);
    await onPinPinned(fixture.keyIdHex); // same-key re-pair: epoch moved, proof reset
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("a post-cutover extension never sends: the bag is history, not policy", async () => {
    await push(goldenFrame(0)); // verifies, applies, arms the cutover
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("after an in-life compromise nothing is offered, proof or not", async () => {
    const v = fixture.vectors[0];
    if (!v) throw new Error("missing golden vector");
    const bytes = base64Decode(v.docB64);
    const flipped = new Uint8Array(bytes);
    flipped[0] = (flipped[0] ?? 0) ^ 0xff;
    await push({
      type: "policy_current",
      ok: true,
      baseline: base64Encode(flipped),
      sig: v.sigB64,
    });
    expect(pinState.compromised).not.toBeNull();
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
  });

  test("the DURABLE compromise mark blocks a send even when the proof predates it (failed presence proof)", async () => {
    // A proof lands first: the connection is proven, everything else clean.
    proveIdentity();
    // Then a presence (or verify) proof FAILS: that path latches only the
    // DURABLE enclave mark (setCompromised) - it never touches policy-sync's
    // in-life latch - so the stamped proof would otherwise survive.
    pinState.compromised = { reason: "presence proof failed verification: bad signature", at: 1 };
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("a durable compromise mark landing DURING the send's await window aborts before the post", async () => {
    proveIdentity();
    // The send gate's early durable-mark read passes (still null); the mark
    // then lands INSIDE the await window - here, during the currentScope pin
    // read - after the early checks, before the post. setCompromised bumps
    // neither the generation nor the attachment, so only the commit-point
    // compromise recheck can catch it.
    pinState.onGetPin = () => {
      pinState.compromised = { reason: "presence proof failed mid-send", at: 1 };
    };
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("a proof challenged under the OLD pin epoch cannot be laundered into the new one", async () => {
    // The challenge goes out: token and pin epoch captured, as enrollment
    // and presence do at challenge-send time.
    const token = currentConnectionToken();
    const generationAtChallenge = currentPinGeneration();
    // A same-key revoke+re-pair completes while the (minutes-long) challenge
    // is outstanding: same keyId, new epoch.
    await onPinRevoked(fixture.keyIdHex);
    await onPinPinned(fixture.keyIdHex);
    // The proof verifies now and reports the CAPTURED epoch: it proves the
    // old pin's holder, so it must credit nothing in the new epoch.
    notePinProvenOnConnection(token, fixture.keyIdHex, generationAtChallenge);
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("an unhardenable storage refuses the send (fail closed, #32)", async () => {
    resetStorageHardeningForTests();
    (fakeBrowser.storage.local as unknown as Record<string, unknown>).setAccessLevel = () =>
      Promise.reject(new Error("setAccessLevel unavailable"));
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
  });

  test("a failed post leaves the flag unset so a later occasion retries", async () => {
    let postOk = false;
    detachPort();
    attachPort((frame) => {
      if (!postOk) return false;
      posted.push(frame);
      return true;
    });
    proveIdentity();
    await push(absentFrame());
    expect(posted).toEqual([]);
    expect(await sentFlag()).toBeUndefined();
    postOk = true;
    await push(absentFrame());
    expect(posted).toEqual([{ type: "legacy_settings", bag: expectedBag() }]);
    expect(await sentFlag()).toBe(true);
  });

  test("revoke + new-key re-pair never resets the flag (no replant, mirroring the host tombstone)", async () => {
    proveIdentity();
    await push(absentFrame());
    expect(posted).toHaveLength(1);
    await onPinRevoked(fixture.keyIdHex);
    const newKeyId = "cd".repeat(32);
    pinState.pin = { keyId: newKeyId, pubkeyB64: fixture.pubkeyB64, pinnedAt: 2 };
    await onPinPinned(newKeyId);
    detachPort();
    attachPort((frame) => {
      posted.push(frame);
      return true;
    });
    notePinProvenOnConnection(currentConnectionToken(), newKeyId, currentPinGeneration());
    await push(absentFrame());
    expect(posted).toHaveLength(1);
    expect(await sentFlag()).toBe(true);
  });
});
