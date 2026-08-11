// Lane U of ADR-0032 Phase 3: the unpinned window-approval surface
// (policy-approval.ts), driven END TO END through the real confirmation
// service with a fake provider (the service.test.ts idiom - no browser
// window) and the real policy-sync accept path over the golden vectors.
// What CANNOT be tested here: the actual extension window rendering and the
// no-page-can-reach-it property; both belong to the isolated-browser suite
// (CHROME_BIN). Verdicts are delivered through service.resolveConfirm - the
// exact function the router's sender-gated confirm_resolve arm calls
// (messages.ts pins the confirm-window-only gating in its own tests).

import { type ConfirmPayload, POLICY_FIELDS } from "@chromium-bridge/shared";
import { POLICY_GOLDEN_FIXTURE } from "@chromium-bridge/shared/testing";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import type { Presentation } from "@/lib/background/confirm/service";
import {
  denyAllConfirmations,
  installConfirmationProvider,
  resetPanicForTests,
  resolveConfirm,
} from "@/lib/background/confirm/service";
import { registerUnpinnedRelaxationApprover } from "@/lib/background/policy-approval";
import {
  attachPort,
  getPolicySnapshotForTests,
  getStoredPolicyState,
  handlePolicyFrame,
  resetPolicySyncForTests,
} from "@/lib/background/policy-sync";

// The pin store is mocked exactly as in policy-sync.test.ts: null plays the
// unpinned machine, the golden-fixture key plays a pinned one.
const pinState = vi.hoisted(() => ({
  pin: null as null | { keyId: string; pubkeyB64: string; pinnedAt: number },
}));

vi.mock("@/lib/background/enclave-pin", () => ({
  getPin: () => Promise.resolve(pinState.pin),
  setCompromised: () => Promise.resolve(),
}));

const fixture = POLICY_GOLDEN_FIXTURE;

/** An unsigned frame over golden vector `i` (0 = deny-baseline rev 1,
 * 1 = relaxed rev 2), the unpinned machine's wire shape. */
function unsignedFrame(i: 0 | 1, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const v = fixture.vectors[i];
  if (!v) throw new Error("missing golden vector");
  return { type: "policy_current", ok: true, baseline: v.docB64, ...extra };
}

interface FakePresentation extends Presentation {
  payload: ConfirmPayload;
}

let presented: FakePresentation[];

function installFakeWindow(): void {
  installConfirmationProvider({
    present(payload) {
      let deny!: () => void;
      const verdict = new Promise<boolean>((resolve) => {
        deny = () => resolve(false);
      });
      const p: FakePresentation = { payload, verdict, dismiss: deny };
      presented.push(p);
      return p;
    },
  });
}

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
  pinState.pin = null;
  presented = [];
  installFakeWindow();
  registerUnpinnedRelaxationApprover();
  attachPort(() => true);
});

afterEach(() => {
  // Drain anything a failed assertion left pending, so the service's shared
  // FIFO can never wedge the next test's confirmation behind a stale one.
  denyAllConfirmations();
  resetPanicForTests();
});

/** Push a frame and answer the NEW confirmation it raises through the
 * router's resolve path. Returns the payload the window was shown. */
async function pushAndAnswer(frame: unknown, approve: boolean): Promise<ConfirmPayload> {
  const seen = presented.length;
  const done = handlePolicyFrame(frame);
  await vi.waitFor(() => {
    if (presented.length <= seen) throw new Error("no confirmation presented yet");
  });
  const payload = presented[presented.length - 1]?.payload;
  if (!payload) throw new Error("no presented payload");
  expect(resolveConfirm(payload.id, approve)).toEqual({ ok: true });
  await done;
  return payload;
}

describe("the unpinned relaxation approval surface", () => {
  test("a relaxing push is held for one window approval; approving applies it", async () => {
    // Adopt the deny baseline first: the first-ever document also rides the
    // window, and its detail is the FULL value set, `field = value` per line
    // (U2) - never a relaxation diff against a fabricated anchor. In
    // particular the fields whose PERMISSIVE pole coincides with
    // POLICY_DEFAULTS (hostReverifyMs 0 = never re-verify, disabledTools [])
    // are shown with their values instead of vanishing from an empty diff.
    const first = await pushAndAnswer(unsignedFrame(0), true);
    expect(first.kind).toBe("policy_relax");
    const stored0 = await getStoredPolicyState();
    expect(first.detail).toBe(
      POLICY_FIELDS.map((f) => `${f} = ${JSON.stringify(stored0?.effective[f])}`).join("\n"),
    );
    expect(first.detail).toContain("hostReverifyMs = 0");
    expect(first.detail).toContain("disabledTools = []");
    expect(first.origin).toBe("");
    // The union confines `hardware` to the eval/upload arms: a policy_relax
    // payload cannot even carry the field.
    expect("hardware" in first).toBe(false);
    expect(await getPolicySnapshotForTests()).toMatchObject({ kind: "active" });

    // The relaxed rev-2 vector: the detail names EXACTLY the fields that
    // relax the stored effective, wire names in catalogue order (the
    // disabledTools change in the same vector is a restriction - absent).
    const second = await pushAndAnswer(unsignedFrame(1), true);
    expect(second.kind).toBe("policy_relax");
    expect(second.detail).toBe("pageEvalEnabled\nconfirmGraceMs");
    const stored = await getStoredPolicyState();
    expect(stored?.effective.pageEvalEnabled).toBe(true);
    expect(stored?.effective.confirmGraceMs).toBe(120000);
  });

  test("declining in the window refuses the push: no state change, no cutover", async () => {
    await pushAndAnswer(unsignedFrame(0), false);
    expect(await getStoredPolicyState()).toBeNull();
    expect(await getPolicySnapshotForTests()).toEqual({ kind: "legacy" });
  });

  test("one approval per push, never blanket: the next relaxing push prompts again", async () => {
    await pushAndAnswer(unsignedFrame(0), true);
    await pushAndAnswer(unsignedFrame(1), true);
    expect(presented).toHaveLength(2);
    // A byte-identical replay of the applied document is restricts-or-equal
    // against the stored effective: idempotent, no third prompt.
    await handlePolicyFrame(unsignedFrame(1));
    expect(presented).toHaveLength(2);
  });

  test("a restricting push applies free, without consulting the window", async () => {
    await pushAndAnswer(unsignedFrame(1), true);
    await handlePolicyFrame(unsignedFrame(1, { overlay: { pageEvalEnabled: false } }));
    expect(presented).toHaveLength(1); // only the initial adoption prompted
    expect((await getStoredPolicyState())?.effective.pageEvalEnabled).toBe(false);
  });

  test("on a PINNED extension the approver is never consulted: unsigned pushes stay refused", async () => {
    pinState.pin = { keyId: fixture.keyIdHex, pubkeyB64: fixture.pubkeyB64, pinnedAt: 1 };
    await handlePolicyFrame(unsignedFrame(0));
    await handlePolicyFrame(unsignedFrame(1));
    expect(presented).toHaveLength(0);
    expect(await getStoredPolicyState()).toBeNull();
  });

  test("with the approver unregistered, a relaxing push is refused before any surface exists", async () => {
    resetPolicySyncForTests(); // drops the registered approver (and the port)
    attachPort(() => true);
    await handlePolicyFrame(unsignedFrame(0));
    expect(presented).toHaveLength(0);
    expect(await getStoredPolicyState()).toBeNull();
  });
});
