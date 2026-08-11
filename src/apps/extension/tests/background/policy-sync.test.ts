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
// - the unpinned lane fails closed while Lane U's approver seam is empty.
//
// The pin store is mocked (the fixture key is deny-listed as a real pin by
// design); everything below it - crypto, schemas, ratchet, storage - is real.
// Flagged for the isolated-browser suite (CHROME_BIN): that the ratchet and
// cutover actually survive real SW death, and the decision 4 in-flight rule
// under a real mid-confirmation push.

import {
  POLICY_DEFAULTS,
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
  detachPort,
  getLangState,
  getPolicySnapshot,
  getStoredPolicyState,
  handlePolicyFrame,
  isPolicyFrame,
  onPinPinned,
  onPinRevoked,
  policyCutoverArmed,
  policyDispatchGate,
  resetPolicySyncForTests,
  setUnpinnedRelaxationApprover,
} from "@/lib/background/policy-sync";

// The pin store is mocked: production deny-lists the golden-fixture key as a
// pin (its scalar is public repo data), which is exactly why the replay must
// inject it here. setCompromised is captured so the "crypto mismatch marks
// compromised" posture is assertable.
const pinState = vi.hoisted(() => ({
  pin: null as null | { keyId: string; pubkeyB64: string; pinnedAt: number },
  compromised: null as null | { reason: string; at: number },
  throwOnSetCompromised: false,
}));

vi.mock("@/lib/background/enclave-pin", () => ({
  getPin: () => Promise.resolve(pinState.pin),
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

let posted: object[];

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
  pinState.pin = fixturePin();
  pinState.compromised = null;
  pinState.throwOnSetCompromised = false;
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
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: goldenValues(0) });
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

  test("a genuine push against the WRONG pin is refused AND marks compromised", async () => {
    const other = await makeSigner();
    pinState.pin = { keyId: other.keyId, pubkeyB64: other.pubkeyB64, pinnedAt: 1 };
    await push(goldenFrame(0));
    expect(await getStoredPolicyState()).toBeNull();
    expect((await policyDispatchGate()).allowed).toBe(true); // still pre-cutover...
    expect(await getPolicySnapshot()).toEqual({
      cutover: false,
      effective: POLICY_DEFAULTS,
    });
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
    await onPinRevoked();
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
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: POLICY_DEFAULTS });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // Pinning the ORIGINAL key back re-activates the retained anchor (finding
    // 2): the record's scope matches again, so its ratchet governs once more.
    pinState.pin = fixturePin();
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: goldenValues(1) });
  });

  test("same-key re-pair retains the anchor, so an OLD lower-revision baseline replay is refused (finding 2)", async () => {
    // rev 2 lands, then the user revokes and re-pairs the SAME key.
    await push(goldenFrame(1));
    await onPinRevoked(); // record RETAINED across revoke
    await onPinPinned(fixture.keyIdHex); // same key: anchor kept, NOT cleared
    expect((await getStoredPolicyState())?.revision).toBe(2);
    // A hostile host now replays the genuine, validly-signed rev-1 baseline.
    // With the anchor gone this would apply as first-ever; with it retained
    // the revision ratchet refuses it.
    detachPort();
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect((await getStoredPolicyState())?.effective).toEqual(goldenValues(1));
  });

  test("different-key re-pair resets the ratchet: onPinPinned clears the retained record", async () => {
    await push(goldenFrame(1));
    await onPinRevoked();
    const other = await makeSigner();
    // A DIFFERENT key is pinned: the retained fixture-key record is cleared so
    // the new scope starts fresh (the intended reset).
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
    expect(await getPolicySnapshot()).toEqual({ cutover: false, effective: POLICY_DEFAULTS });
    // A subsequent SIGNED rev-1 push under the now-pinned key applies cleanly -
    // it was not clobbered by a stale revision-0 write from the dropped push.
    setUnpinnedRelaxationApprover(null);
    detachPort();
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
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

  test("an approved relaxation applies and ratchets; a denied one changes nothing", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(false));
    await push(goldenFrame(0));
    expect(await getStoredPolicyState()).toBeNull();
    setUnpinnedRelaxationApprover((relaxation) => {
      expect(relaxation.doc.revision).toBe(1);
      expect(relaxation.storedEffective).toBeNull();
      // The approver sees FROZEN copies: it cannot mutate the values this push
      // will commit (the commit recomputes none of them).
      expect(Object.isFrozen(relaxation.effective)).toBe(true);
      expect(Object.isFrozen(relaxation.effective.disabledTools)).toBe(true);
      return Promise.resolve(true);
    });
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: goldenValues(0) });
  });

  test("a pure restriction of the stored effective applies silently, no approver needed", async () => {
    setUnpinnedRelaxationApprover(() => Promise.resolve(true));
    await push(goldenFrame(1));
    setUnpinnedRelaxationApprover(null);
    await push(goldenFrame(1, { overlay: { pageEvalEnabled: false } }));
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(false);
  });

  test("the ratchet still binds the unpinned lane: a lower revision is refused before any approval", async () => {
    const consulted = vi.fn(() => Promise.resolve(true));
    setUnpinnedRelaxationApprover(consulted);
    await push(goldenFrame(1));
    consulted.mockClear();
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(2);
    expect(consulted).not.toHaveBeenCalled();
  });
});

describe("lang_current (store-only until Phase 4)", () => {
  test("stores {value, seq}, sequence-suppressed, malformed dropped", async () => {
    expect(getLangState()).toBeNull();
    await push({ type: "lang_current", value: "de", seq: 2 });
    expect(getLangState()).toEqual({ value: "de", seq: 2 });
    // An equal or lower sequence never applies (echo suppression).
    await push({ type: "lang_current", value: "en", seq: 2 });
    await push({ type: "lang_current", value: "zh", seq: 1 });
    expect(getLangState()).toEqual({ value: "de", seq: 2 });
    await push({ type: "lang_current", value: "en", seq: 3 });
    expect(getLangState()).toEqual({ value: "en", seq: 3 });
    // Malformed frames change nothing.
    await push({ type: "lang_current", value: "en" });
    await push({ type: "lang_current", value: 7, seq: 9 });
    expect(getLangState()).toEqual({ value: "en", seq: 3 });
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
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: POLICY_DEFAULTS });
    const gate = await policyDispatchGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("latched");
    // A genuine signed push is REFUSED while latched: a corrupt store cannot be
    // silently overwritten (that IS the finding-3 replay - an older baseline
    // landing as first-ever). Recovery is a re-pair, below.
    await push(goldenFrame(0));
    expect(await policyDispatchGate()).toMatchObject({ allowed: false });
    // A DIFFERENT-key re-pair clears the corrupt record and recovers.
    const other = await makeSigner();
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
});

describe("armCutover ordering is fail-closed", () => {
  test("cutover armed with no stored record (SW died between arm and write) denies, never legacy", async () => {
    // The accept path arms cutover BEFORE writing the record: a crash in the
    // gap leaves armed + absent, which resolves to awaitingBaseline - deny
    // baseline + closed barrier - never legacy-enforced-despite-a-policy.
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    expect(await getStoredPolicyState()).toBeNull();
    expect(await getPolicySnapshot()).toEqual({ cutover: true, effective: POLICY_DEFAULTS });
    expect((await policyDispatchGate()).allowed).toBe(false);
    // Recovery is a fresh verified push, which starts the ratchet cleanly.
    attachPort(() => true);
    await push(goldenFrame(0));
    expect((await getStoredPolicyState())?.revision).toBe(1);
    expect((await policyDispatchGate()).allowed).toBe(true);
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
