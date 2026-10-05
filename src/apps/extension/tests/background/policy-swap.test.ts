// Every enforcement call site reads the per-decision policy snapshot. Each
// site gets one post-cutover DENY and one post-cutover GRANT test, so a test
// can only pass if the site reads the applied policy rather than the deny
// baseline or a permissive constant.
//
// Sites covered here: dispatch (disabledTools, cdpMode), confirm/gate
// (confirmHighRiskClick, confirmGraceMs, clickToastTimeoutMs,
// pageEvalEnabled via TOOL_GRANTS, confirmPageEval, evalToastTimeoutMs),
// upload (fileUploadEnabled, clickToastTimeoutMs), dialog
// (handleDialogEnabled), tabs (confirmTabClose, clickToastTimeoutMs),
// precise (warnPreciseSnapshot), egress (evalMask), the presence routing
// verdict (touchIdConfirm). enrollment's hostReverifyMs rides the ceremony harness
// in enrollment.test.ts instead.
//
// Plus the in-flight snapshot rule at vitest granularity: a policy swap
// landing mid-confirmation does not alter the in-flight decision's grace.
// What only the CHROME_BIN isolated-browser suite can verify remains a REAL
// mid-confirmation policy push surviving SW timing; flagged, not attempted.

import { type ConfirmPayload, isHardwareGated } from "@chromium-bridge/shared/confirm";
import type { BridgeReq } from "@chromium-bridge/shared/envelope";
import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/policy.gen";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { preflightPageOp, resetClickGraceWindow } from "@/lib/background/confirm/gate";
import {
  currentPanicEpoch,
  installConfirmationProvider,
  installPresenceProvider,
  resolveConfirm,
} from "@/lib/background/confirm/service";
import { handleDialog } from "@/lib/background/dialog";
import { dispatch } from "@/lib/background/dispatch";
import { getEffectivePolicy } from "@/lib/background/effective-policy";
import { maskOpResult } from "@/lib/background/egress";
import type { PageBackend } from "@/lib/background/page-backend";
import {
  getPolicySnapshotForTests,
  policyDispatchGate,
  resetPolicySyncForTests,
} from "@/lib/background/policy-sync";
import { snapshotPrecise } from "@/lib/background/precise";
import type { ResolvedTab } from "@/lib/background/tabs";
import { tabClose } from "@/lib/background/tabs";
import { pageUpload } from "@/lib/background/upload";
import type { ClickProbe } from "@/lib/dom/page-api";
import { allowGate } from "./allow-gate";

// The page-backend seam, mocked to observe WHICH mode dispatch selected
// (the cdpMode site) without dragging real backends in.
const backendSeam = vi.hoisted(() => ({ cdpCalls: [] as boolean[] }));
vi.mock("@/lib/background/page-backend", () => ({
  selectBackend: (cdpMode: boolean) => {
    backendSeam.cdpCalls.push(cdpMode);
    return {
      probeClick: () =>
        Promise.resolve({ tagName: "DIV", role: "", type: "", hasHref: false, name: "" }),
      run: () => Promise.resolve({ ok: true }),
    };
  },
}));

// The pin store, mocked so the routing tests can stamp a pinned scope without a ceremony.
const pinSeam = vi.hoisted(() => ({
  pin: null as null | { keyId: string; pubkeyB64: string; pinnedAt: number },
}));
vi.mock("@/lib/background/enclave-pin", () => ({
  getPin: () => Promise.resolve(pinSeam.pin),
  getCompromised: () => Promise.resolve(null),
  setCompromised: () => Promise.resolve(),
}));

// precise.ts resolves toast strings SW-side; the locale machinery is not
// under test.
vi.mock("@/lib/i18n", () => ({
  initI18n: () => Promise.resolve(),
  t: (key: string) => key,
}));

function policyValues(overrides: Partial<PolicyValues> = {}): PolicyValues {
  return { ...POLICY_DEFAULTS, disabledTools: [], ...overrides };
}

// The decision-start read a real caller performs, unwrapped: these suites
// arm an ACTIVE record (or stay pre-cutover), so a blocked posture here is a
// test bug, not a case under test.
async function freshValues(): Promise<PolicyValues> {
  const policy = await getEffectivePolicy();
  if (policy.state === "blocked") throw new Error(policy.reason);
  return policy.values;
}

async function armCutover(
  effective?: Partial<PolicyValues>,
  revision = 1,
  scope: string | null = null,
): Promise<void> {
  await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
  if (effective) {
    await fakeBrowser.storage.local.set({
      bridgePolicyState: {
        // The stored record is ACTIVE only in scope (the ratchet is bound to
        // the pin): null is the unpinned lane (these suites mostly run
        // unpinned); the presence tests pin a key and stamp its id here.
        scope,
        effective: policyValues(effective),
        revision,
        baselineB64: "ZG9j",
        at: revision,
      },
    });
  }
}

const SUBMIT: ClickProbe = {
  tagName: "BUTTON",
  role: "button",
  type: "submit",
  hasHref: false,
  name: "Pay",
};

function fakeBackend(probe: ClickProbe): PageBackend {
  return {
    probeClick: () => Promise.resolve(probe),
    run: () => Promise.resolve({}),
  };
}

// Auto-answering provider (the gate.test.ts pattern): records what was
// asked and answers through the router path.
function autoProvider(approve: boolean) {
  const asked: ConfirmPayload[] = [];
  installConfirmationProvider({
    present(payload) {
      asked.push(payload);
      queueMicrotask(() => resolveConfirm(payload.id, approve));
      return { verdict: new Promise<boolean>(() => {}), dismiss() {} };
    },
  });
  return asked;
}

// The fake browser starts with no focused window, so the active-tab query
// the page tools run finds nothing until a focused window holds the tab.
async function makeTab(url = "https://example.com/x") {
  await fakeBrowser.storage.local.set({ allowAllSites: true });
  await fakeBrowser.windows.create({ focused: true });
  const tab = await fakeBrowser.tabs.create({ url, active: true });
  if (tab.id == null) throw new Error("fake tab has no id");
  return tab as typeof tab & { id: number };
}

beforeEach(() => {
  fakeBrowser.reset();
  resetPolicySyncForTests();
  resetClickGraceWindow();
  backendSeam.cdpCalls.length = 0;
  pinSeam.pin = null;
});

// ---- dispatch.ts: disabledTools and cdpMode --------------------------------------

describe("dispatch reads disabledTools from the snapshot", () => {
  test("deny: a policy-disabled tool is refused", async () => {
    await armCutover({ disabledTools: ["tab_list"] });
    await expect(
      dispatch({ id: 1, op: "tab_list", args: {} } as BridgeReq, allowGate),
    ).resolves.toEqual({
      outcome: "error",
      error: new Error("tool disabled in settings: tab_list"),
    });
  });

  test("grant: a policy-enabled tool runs", async () => {
    await armCutover({ disabledTools: [] });
    await expect(
      dispatch({ id: 1, op: "tab_list", args: {} } as BridgeReq, allowGate),
    ).resolves.toEqual({
      outcome: "ok",
      data: expect.any(Array),
    });
  });
});

describe("dispatch reads cdpMode from the snapshot", () => {
  test("grant: policy cdpMode=true selects the CDP backend", async () => {
    await makeTab();
    await armCutover({ cdpMode: true });
    await dispatch({ id: 1, op: "page_snapshot", args: {} } as BridgeReq, allowGate);
    expect(backendSeam.cdpCalls).toEqual([true]);
  });

  test("deny: policy cdpMode=false selects the content-script backend", async () => {
    await makeTab();
    await armCutover({ cdpMode: false });
    await dispatch({ id: 1, op: "page_snapshot", args: {} } as BridgeReq, allowGate);
    expect(backendSeam.cdpCalls).toEqual([false]);
  });
});

// ---- confirm/gate.ts --------------------------------------------------------------

const TAB = { id: 7, url: "https://example.com/x", title: "Example" } as ResolvedTab;

describe("the gate reads its six policy fields from the snapshot", () => {
  test("pageEvalEnabled deny: an ACTIVE policy false refuses", async () => {
    const asked = autoProvider(true);
    // With NO stored record the posture is blocked and the decision cannot
    // even start (pinned in the barrier describe below); the gate-level deny
    // needs an ACTIVE record carrying the deny value.
    await armCutover({ pageEvalEnabled: false });
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).rejects.toThrow("page_eval disabled in settings");
    expect(asked.length).toBe(0);
  });

  test("pageEvalEnabled grant: policy true runs", async () => {
    autoProvider(true);
    await armCutover({ pageEvalEnabled: true, confirmPageEval: false });
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).resolves.toEqual({});
  });

  test("confirmPageEval deny: the policy confirmation is enforced", async () => {
    const asked = autoProvider(false);
    await armCutover({ pageEvalEnabled: true, confirmPageEval: true });
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).rejects.toThrow("user denied page_eval");
    expect(asked.length).toBe(1);
  });

  test("confirmPageEval grant: the policy opt-out skips the prompt", async () => {
    const asked = autoProvider(false);
    await armCutover({ pageEvalEnabled: true, confirmPageEval: false });
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).resolves.toEqual({});
    expect(asked.length).toBe(0);
  });

  test("confirmHighRiskClick deny: the policy confirmation is enforced", async () => {
    const asked = autoProvider(false);
    await armCutover({ confirmHighRiskClick: true });
    await expect(
      preflightPageOp(
        "page_click",
        { selector: "#x" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).rejects.toThrow("user denied");
    expect(asked.length).toBe(1);
  });

  test("confirmHighRiskClick grant: the policy opt-out skips the gate", async () => {
    const asked = autoProvider(false);
    await armCutover({ confirmHighRiskClick: false });
    await expect(
      preflightPageOp(
        "page_click",
        { selector: "#x" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).resolves.toBeTruthy();
    expect(asked.length).toBe(0);
  });

  test("confirmGraceMs deny: policy 0 reconfirms every click", async () => {
    const asked = autoProvider(true);
    await armCutover({ confirmGraceMs: 0 });
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect(asked.length).toBe(2);
  });

  test("confirmGraceMs grant: the policy window suppresses the re-prompt", async () => {
    const asked = autoProvider(true);
    await armCutover({ confirmGraceMs: 60_000 });
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    await preflightPageOp(
      "page_click",
      { selector: "#y" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect(asked.length).toBe(1);
  });

  test("clickToastTimeoutMs comes from the snapshot: grant (longer) and deny (shorter) than the baseline", async () => {
    const asked = autoProvider(true);
    // Grant direction: policy 111s vs the baseline 30s.
    await armCutover({ clickToastTimeoutMs: 111_000, confirmGraceMs: 0 });
    let before = Date.now();
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect((asked[0]?.deadline ?? 0) - before).toBeGreaterThanOrEqual(111_000);
    // Deny direction: policy 500ms vs the baseline 30s (the provider answers on a
    // microtask, well inside the auto-deny timer).
    await armCutover({ clickToastTimeoutMs: 500, confirmGraceMs: 0 }, 2);
    before = Date.now();
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect((asked[1]?.deadline ?? 0) - before).toBeLessThan(30_000);
  });

  test("evalToastTimeoutMs comes from the snapshot: grant (longer) and deny (shorter) than the baseline", async () => {
    const asked = autoProvider(true);
    await armCutover({ pageEvalEnabled: true, evalToastTimeoutMs: 222_000 });
    let before = Date.now();
    await preflightPageOp(
      "page_eval",
      { code: "1" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect((asked[0]?.deadline ?? 0) - before).toBeGreaterThanOrEqual(222_000);
    await armCutover({ pageEvalEnabled: true, evalToastTimeoutMs: 500 }, 2);
    before = Date.now();
    await preflightPageOp(
      "page_eval",
      { code: "1" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect((asked[1]?.deadline ?? 0) - before).toBeLessThan(45_000);
  });
});

// ---- the in-flight rule: a decision never re-reads live policy -------------------

describe("per-decision snapshot isolation: a decision never re-reads live policy", () => {
  test("a policy swap mid-confirmation does not alter the in-flight decision's grace", async () => {
    await armCutover({ confirmGraceMs: 60_000 });
    const asked: ConfirmPayload[] = [];
    installConfirmationProvider({
      present(payload) {
        asked.push(payload);
        queueMicrotask(async () => {
          // The mid-decision policy change: grace tightened to 0 while the
          // confirmation toast is open.
          await armCutover({ confirmGraceMs: 0 }, 2);
          resolveConfirm(payload.id, true);
        });
        return { verdict: new Promise<boolean>(() => {}), dismiss() {} };
      },
    });
    await preflightPageOp(
      "page_click",
      { selector: "#x" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect(asked.length).toBe(1);
    // Widen the grace back for the SECOND decision's own snapshot, so the
    // assertion isolates what the FIRST decision recorded: had the
    // mid-flight swap leaked into it, its window would have been recorded
    // zero-length and this second click would re-ask.
    await armCutover({ confirmGraceMs: 60_000 }, 3);
    await preflightPageOp(
      "page_click",
      { selector: "#y" },
      TAB,
      fakeBackend(SUBMIT),
      await freshValues(),
      currentPanicEpoch(),
    );
    expect(asked.length).toBe(1);
  });
});

// ---- upload.ts ----------------------------------------------------------------------

describe("pageUpload reads fileUploadEnabled and its timeout from the snapshot", () => {
  test("deny: policy false refuses", async () => {
    await armCutover({ fileUploadEnabled: false });
    await expect(
      pageUpload({ selector: "#f", path: "/tmp/x" }, await freshValues(), currentPanicEpoch()),
    ).rejects.toThrow("page_upload is disabled");
  });

  test("grant: policy true passes the gate", async () => {
    await armCutover({ fileUploadEnabled: true });
    // The missing selector fails AFTER the gate: proof the gate read policy.
    await expect(
      pageUpload({ path: "/tmp/x" }, await freshValues(), currentPanicEpoch()),
    ).rejects.toThrow("page_upload needs `selector`");
  });

  test("the upload confirmation timeout comes from the snapshot", async () => {
    const asked = autoProvider(false);
    await makeTab();
    await armCutover({ fileUploadEnabled: true, clickToastTimeoutMs: 111_000 });
    const before = Date.now();
    await expect(
      pageUpload({ selector: "#f", path: "/tmp/x" }, await freshValues(), currentPanicEpoch()),
    ).rejects.toThrow("user denied page_upload");
    expect((asked[0]?.deadline ?? 0) - before).toBeGreaterThanOrEqual(111_000);
  });
});

// ---- dialog.ts ----------------------------------------------------------------------

describe("handleDialog reads handleDialogEnabled from the snapshot", () => {
  test("deny: policy false refuses", async () => {
    await armCutover({ handleDialogEnabled: false });
    await expect(handleDialog({ action: "accept" }, await freshValues())).rejects.toThrow(
      "page_handle_dialog is disabled",
    );
  });

  test("grant: policy true passes the gate", async () => {
    await armCutover({ handleDialogEnabled: true });
    // The invalid action fails AFTER the gate: proof the gate read policy.
    await expect(handleDialog({ action: "bogus" }, await freshValues())).rejects.toThrow(
      'page_handle_dialog needs action "accept" or "dismiss"',
    );
  });
});

// ---- tabs.ts ------------------------------------------------------------------------

describe("tabClose reads confirmTabClose and its timeout from the snapshot", () => {
  test("deny: the policy confirmation is enforced (with the policy timeout)", async () => {
    const asked = autoProvider(false);
    const tab = await makeTab();
    await armCutover({ confirmTabClose: true, clickToastTimeoutMs: 111_000 });
    const before = Date.now();
    await expect(tabClose(tab.id, await freshValues(), currentPanicEpoch())).rejects.toThrow(
      "user denied tab_close",
    );
    expect(asked.length).toBe(1);
    expect((asked[0]?.deadline ?? 0) - before).toBeGreaterThanOrEqual(111_000);
  });

  test("grant: the policy opt-out closes unprompted", async () => {
    const asked = autoProvider(false);
    const tab = await makeTab();
    // fakeBrowser's tabs.remove trips over its own window bookkeeping; the
    // removal is not what is under test, the skipped confirmation is.
    const remove = vi.spyOn(browser.tabs, "remove").mockResolvedValue(undefined);
    await armCutover({ confirmTabClose: false });
    await expect(tabClose(tab.id, await freshValues(), currentPanicEpoch())).resolves.toEqual({
      closed: tab.id,
    });
    expect(asked.length).toBe(0);
    expect(remove).toHaveBeenCalledWith(tab.id);
  });
});

// ---- precise.ts ---------------------------------------------------------------------

describe("snapshotPrecise reads warnPreciseSnapshot from the snapshot", () => {
  function installDebuggerSpy(): ReturnType<typeof vi.fn> {
    const attach = vi.fn(() => Promise.reject(new Error("attach-sentinel")));
    (browser as unknown as { debugger: unknown }).debugger = { attach };
    return attach;
  }

  test("deny: the policy warning toast is consulted (and a cancel honored)", async () => {
    await makeTab();
    await armCutover({ warnPreciseSnapshot: true });
    const attach = installDebuggerSpy();
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async (_tabId, msg) => {
      if ((msg as { op?: string }).op === "ping") return { ok: true, data: { pong: true } };
      return { ok: true, data: { cancelled: true } }; // the user cancels
    });
    await expect(snapshotPrecise({}, await freshValues())).resolves.toEqual({
      cancelled: true,
    });
    expect(attach).not.toHaveBeenCalled();
  });

  test("grant: the policy opt-out skips the toast", async () => {
    await makeTab();
    await armCutover({ warnPreciseSnapshot: false });
    installDebuggerSpy();
    const toasts: unknown[] = [];
    vi.spyOn(browser.tabs, "sendMessage").mockImplementation(async (_tabId, msg) => {
      if ((msg as { op?: string }).op === "ping") return { ok: true, data: { pong: true } };
      toasts.push(msg);
      return { ok: true, data: { cancelled: false } };
    });
    // Proceeds straight to the CDP attach (the sentinel), no toast shown.
    await expect(snapshotPrecise({}, await freshValues())).rejects.toThrow("attach-sentinel");
    expect(toasts).toEqual([]);
  });
});

// ---- egress.ts ----------------------------------------------------------------------

describe("egress masking reads evalMask from the snapshot", () => {
  const SECRET = "bearer: sk-live-abcdef1234567890";

  test("deny: the policy mask applies", async () => {
    await armCutover({ evalMask: true });
    const out = (await maskOpResult("page_eval", SECRET, await freshValues())) as string;
    expect(out).not.toBe(SECRET);
    expect(out).toContain("••••");
  });

  test("grant: the policy opt-out passes the value through", async () => {
    await armCutover({ evalMask: false });
    await expect(maskOpResult("page_eval", SECRET, await freshValues())).resolves.toBe(SECRET);
  });
});

// ---- the presence routing verdict in the request ----------------------------------------

describe("presence routing is decided from the per-request snapshot", () => {
  // A real 64-hex keyId: the stored record's scope must both satisfy the
  // strict schema and match the pinned scope for the record to be ACTIVE.
  const KEY_ID = "0".repeat(64);

  function presenceStub(): ConfirmPayload[] {
    const shown: ConfirmPayload[] = [];
    installPresenceProvider({
      present(payload) {
        shown.push(payload);
        return { verdict: Promise.resolve(false), dismiss() {} };
      },
    });
    return shown;
  }

  test("deny: policy touchIdConfirm=false keeps the window path", async () => {
    pinSeam.pin = { keyId: KEY_ID, pubkeyB64: "p", pinnedAt: 1 };
    const hw = presenceStub();
    const asked = autoProvider(false);
    await armCutover({ pageEvalEnabled: true, touchIdConfirm: false }, 1, KEY_ID);
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).rejects.toThrow("user denied page_eval");
    expect(hw.length).toBe(0);
    expect(asked.length).toBe(1);
    expect(asked[0] !== undefined && isHardwareGated(asked[0])).toBe(false);
  });

  test("grant: policy touchIdConfirm=true routes to the installed presence provider", async () => {
    pinSeam.pin = { keyId: KEY_ID, pubkeyB64: "p", pinnedAt: 1 };
    const hw = presenceStub();
    const asked = autoProvider(false);
    await armCutover({ pageEvalEnabled: true, touchIdConfirm: true }, 1, KEY_ID);
    await expect(
      preflightPageOp(
        "page_eval",
        { code: "1" },
        TAB,
        fakeBackend(SUBMIT),
        await freshValues(),
        currentPanicEpoch(),
      ),
    ).rejects.toThrow("user denied page_eval");
    expect(asked.length).toBe(0);
    expect(hw.length).toBe(1);
    expect(hw[0] !== undefined && isHardwareGated(hw[0])).toBe(true);
  });
});

// ---- blocked postures are un-consumable AND barred ----------------------------------

describe("a blocked posture is not consumable as values and the barrier refuses it", () => {
  // A blocked arm carries no values anywhere: the raw snapshot reports only the arm, the state-typed
  // effective policy has no `values` key, and the dispatch barrier refuses the same states. Pin all
  // three, in both arms.
  test("awaitingBaseline (cutover armed, no record): blocked + refusal; the raw accessor reports the arm honestly", async () => {
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true });
    // Exact shape, not toMatchObject: the blocked arm must carry NO
    // .values key at all - the leak is closed structurally, not by callers
    // declining to read it.
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "blocked",
      reason: expect.any(String),
    });
    await expect(policyDispatchGate()).resolves.toEqual({
      allowed: false,
      reason: expect.any(String),
    });
    await expect(getPolicySnapshotForTests()).resolves.toEqual({ kind: "awaitingBaseline" });
  });

  test("compromised (corrupt record): blocked + refusal; the raw accessor reports the arm honestly", async () => {
    await fakeBrowser.storage.local.set({
      bridgePolicyCutover: true,
      bridgePolicyState: { tampered: true },
    });
    // Exact shape, not toMatchObject: the blocked arm must carry NO
    // .values key at all - the leak is closed structurally, not by callers
    // declining to read it.
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "blocked",
      reason: expect.any(String),
    });
    await expect(policyDispatchGate()).resolves.toEqual({
      allowed: false,
      reason: expect.any(String),
    });
    await expect(getPolicySnapshotForTests()).resolves.toEqual({ kind: "compromised" });
  });

  test("active in-scope record: the stored effective is served", async () => {
    await armCutover({ confirmGraceMs: 12_345 });
    await expect(getEffectivePolicy()).resolves.toEqual({
      state: "active",
      values: policyValues({ confirmGraceMs: 12_345 }),
    });
  });

  test("dispatch refuses from its OWN single read when blocked (the barrier race)", async () => {
    // The enrollment gate's barrier check and dispatch's snapshot are
    // separate awaits on the request path: a compromise latching between
    // them must be refused by the snapshot read itself, never run under the
    // deny-baseline defaults (whose empty disabledTools is permissive).
    await fakeBrowser.storage.local.set({ bridgePolicyCutover: true }); // blocked
    await expect(
      dispatch({ id: 1, op: "tab_list", args: {} } as BridgeReq, allowGate),
    ).resolves.toEqual({
      outcome: "error",
      error: expect.objectContaining({
        message: expect.stringContaining("no in-scope verified policy baseline"),
      }),
    });
  });
});
