// The cancel leg of the bridge contract as the extension sees it (dispatch.ts): the server's `cancel` signal
// for an id the extension holds ends that request as `cancelled`, which port.ts posts nothing for, whether the
// cancel lands while the request waits for admission, before its op, or while the op runs (its late result or
// late failure is discarded).

import type { BridgeReq } from "@chromium-bridge/shared/envelope";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

// Hand-held stages, so a test chooses when the request moves past each: the policy read is the pipeline's first
// await, tab_list is a service-worker op (released as a result or as a failure), and the active-tab resolve is
// the page pipeline's first stage, with the allowlist check spied behind it. Hoisted because the vi.mock
// factories run before this module.
const held = vi.hoisted(() => {
  let releasePolicy: () => void = () => {};
  let settleTabs: (outcome: "result" | "failure") => void = () => {};
  let releaseTab: () => void = () => {};
  const policyRead = vi.fn(
    () =>
      new Promise<{ state: "active"; values: Record<string, unknown> }>((resolve) => {
        releasePolicy = () =>
          resolve({ state: "active", values: { disabledTools: [], cdpMode: false } });
      }),
  );
  const tabList = vi.fn(
    () =>
      new Promise<unknown[]>((resolve, reject) => {
        settleTabs = (outcome) =>
          outcome === "result"
            ? resolve([{ id: 1, url: "https://example.com/" }])
            : reject(new Error("tabs.query failed late"));
      }),
  );
  const activeTab = vi.fn(
    () =>
      new Promise<{ id: number; url: string }>((resolve) => {
        releaseTab = () => resolve({ id: 1, url: "https://example.com/" });
      }),
  );
  let releaseAllowlist: () => void = () => {};
  const ensureAllowed = vi.fn(
    () =>
      new Promise<void>((resolve) => {
        releaseAllowlist = () => resolve();
      }),
  );
  // The stage after the allowlist: a stub, so a page op that runs on is seen here and goes no further.
  const preflight = vi.fn(() => Promise.reject(new Error("preflight stub")));
  return {
    policyRead,
    tabList,
    activeTab,
    ensureAllowed,
    preflight,
    releasePolicy: () => releasePolicy(),
    settleTabs: (outcome: "result" | "failure") => settleTabs(outcome),
    releaseTab: () => releaseTab(),
    releaseAllowlist: () => releaseAllowlist(),
  };
});
vi.mock("@/lib/background/effective-policy", () => ({ getEffectivePolicy: held.policyRead }));
vi.mock("@/lib/background/tabs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/background/tabs")>()),
  tabList: held.tabList,
  activeTab: held.activeTab,
}));
vi.mock("@/lib/background/allowlist-store", () => ({ ensureAllowed: held.ensureAllowed }));
vi.mock("@/lib/background/confirm/gate", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/background/confirm/gate")>()),
  preflightPageOp: held.preflight,
}));

import { type AdmissionGate, collaborator, dispatch } from "@/lib/background/dispatch";
import { allowGate } from "./allow-gate";

const {
  policyRead,
  tabList,
  ensureAllowed,
  preflight,
  releasePolicy,
  settleTabs,
  releaseTab,
  releaseAllowlist,
} = held;

const tabListReq = (id: number | string): BridgeReq =>
  ({ id, op: "tab_list", args: {} }) as BridgeReq;

const cancel = (id: number | string) => collaborator.onFrame?.({ type: "cancel", id });

/** Let the pipeline reach its next await. */
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** A gate that admits only when the test says, the way enrollmentGate's serialized read can hold a request. */
function heldGate(): { gate: AdmissionGate; admit: () => void } {
  let admit: () => void = () => {};
  const gate: AdmissionGate = (onAllowed) =>
    new Promise((resolve) => {
      admit = () => {
        onAllowed();
        resolve({ allowed: true });
      };
    });
  return { gate, admit: () => admit() };
}

beforeEach(() => {
  fakeBrowser.reset();
  vi.clearAllMocks();
});

describe("the cancel signal", () => {
  test("a request answers ok when nothing cancels it (control for the cases below)", async () => {
    const settled = dispatch(tabListReq(1), allowGate);
    releasePolicy();
    await tick();
    settleTabs("result");
    await expect(settled).resolves.toEqual({
      outcome: "ok",
      data: [{ id: 1, url: "https://example.com/" }],
    });
    expect(tabList).toHaveBeenCalledTimes(1);
  });

  test("a cancel while the request waits for admission ends it cancelled and the op never runs", async () => {
    const { gate, admit } = heldGate();
    const settled = dispatch(tabListReq(2), gate);
    expect(cancel(2)).toBe(true);
    admit();
    // The held stages are released so a dispatch that wrongly ran on would complete and reach the
    // assertions below instead of hanging the test.
    releasePolicy();
    await tick();
    settleTabs("result");
    await expect(settled).resolves.toEqual({ outcome: "cancelled" });
    expect(policyRead).not.toHaveBeenCalled();
    expect(tabList).not.toHaveBeenCalled();
  });

  test("a cancel before the op's stage ends the request cancelled and the op never runs", async () => {
    const settled = dispatch(tabListReq(3), allowGate);
    await tick();
    expect(cancel(3)).toBe(true);
    releasePolicy();
    await tick();
    settleTabs("result");
    await expect(settled).resolves.toEqual({ outcome: "cancelled" });
    expect(tabList).not.toHaveBeenCalled();
  });

  test("a cancel while the tab resolves never reaches the allowlist check (and its approval prompt)", async () => {
    const settled = dispatch({ id: 8, op: "page_snapshot", args: {} } as BridgeReq, allowGate);
    releasePolicy();
    await tick();
    expect(cancel(8)).toBe(true);
    releaseTab();
    await expect(settled).resolves.toEqual({ outcome: "cancelled" });
    expect(ensureAllowed).not.toHaveBeenCalled();
  });

  test("the allowlist stage is reached when nothing cancels a page op (control for the case above)", async () => {
    const settled = dispatch({ id: 10, op: "page_snapshot", args: {} } as BridgeReq, allowGate);
    releasePolicy();
    await tick();
    releaseTab();
    await tick();
    releaseAllowlist();
    await expect(settled).resolves.toEqual({
      outcome: "error",
      error: new Error("preflight stub"),
    });
    expect(ensureAllowed).toHaveBeenCalledTimes(1);
    expect(preflight).toHaveBeenCalledTimes(1);
  });

  test("a cancel while the allowlist check runs never reaches the confirmation preflight", async () => {
    const settled = dispatch({ id: 11, op: "page_snapshot", args: {} } as BridgeReq, allowGate);
    releasePolicy();
    await tick();
    releaseTab();
    await tick();
    expect(ensureAllowed).toHaveBeenCalledTimes(1);
    expect(cancel(11)).toBe(true);
    releaseAllowlist();
    await expect(settled).resolves.toEqual({ outcome: "cancelled" });
    expect(preflight).not.toHaveBeenCalled();
  });

  test.each([
    { late: "result" as const, name: "late result" },
    { late: "failure" as const, name: "late failure" },
  ])("a cancel while the op runs discards its $name", async ({ late }) => {
    const settled = dispatch(tabListReq(4), allowGate);
    releasePolicy();
    await tick();
    expect(tabList).toHaveBeenCalledTimes(1);
    expect(cancel(4)).toBe(true);
    settleTabs(late);
    await expect(settled).resolves.toEqual({ outcome: "cancelled" });
  });

  test("a refused gate without a cancel answers error, and never starts the pipeline", async () => {
    const refuse: AdmissionGate = () => Promise.resolve({ allowed: false, reason: "unpaired" });
    await expect(dispatch(tabListReq(5), refuse)).resolves.toEqual({
      outcome: "error",
      error: new Error("unpaired"),
    });
    expect(policyRead).not.toHaveBeenCalled();
  });

  test.each([
    { name: "rejects", gate: (() => Promise.reject(new Error("store gone"))) as AdmissionGate },
    {
      name: "throws before returning",
      gate: (() => {
        throw new Error("store gone");
      }) as AdmissionGate,
    },
  ])("a gate that $name answers error instead of rejecting the dispatch", async ({ gate }) => {
    await expect(dispatch(tabListReq(9), gate)).resolves.toEqual({
      outcome: "error",
      error: new Error("enrollment gate error: Error: store gone"),
    });
    expect(policyRead).not.toHaveBeenCalled();
  });

  test("a refused request without a cancel answers error", async () => {
    policyRead.mockImplementationOnce(() =>
      Promise.resolve({ state: "blocked", reason: "refused for the test" } as never),
    );
    await expect(dispatch(tabListReq(6), allowGate)).resolves.toEqual({
      outcome: "error",
      error: new Error("refused for the test"),
    });
  });

  // With request 7 in flight at its op, each frame is offered to the collaborator: only a well-formed cancel
  // naming 7 may abort it. A malformed cancel is claimed (a cancel has no reply) but changes nothing; the
  // frames the collaborator does not own are left for the next collaborator or the request parse.
  test.each([
    { name: "a cancel for another id", frame: { type: "cancel", id: 99 }, claimed: true },
    { name: "a cancel with no id", frame: { type: "cancel" }, claimed: true },
    { name: "a cancel with an extra field", frame: { type: "cancel", id: 7, x: 1 }, claimed: true },
    { name: "a control frame", frame: { type: "kill_status_result", ok: true }, claimed: false },
    { name: "a bridge request", frame: { id: 7, op: "tab_list", args: {} }, claimed: false },
    { name: "a non-object", frame: "cancel", claimed: false },
  ])(
    "$name is claimed=$claimed and leaves the in-flight request to complete",
    async ({ frame, claimed }) => {
      const settled = dispatch(tabListReq(7), allowGate);
      releasePolicy();
      await tick();
      expect(collaborator.onFrame?.(frame)).toBe(claimed);
      settleTabs("result");
      await expect(settled).resolves.toEqual({
        outcome: "ok",
        data: [{ id: 1, url: "https://example.com/" }],
      });
    },
  );
});
