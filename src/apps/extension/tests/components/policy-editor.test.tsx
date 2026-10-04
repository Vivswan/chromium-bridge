// The policy editor's direction gating over the SW contract, the fact the generated catalogue states but no
// render proves: a control whose only move tightens the enforced policy is live and posts exactly that
// one-entry overlay, a control whose move would relax it is disabled with the needs-presence note, and the
// pre-cutover, blocked, and refused states render without any field control.

import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/policy.gen";
import type { PolicyPosture } from "@chromium-bridge/shared/runtime-msg";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

// A hand-written enforced policy: two grants on, one tool disabled, every window at its default.
const EFFECTIVE: PolicyValues = {
  ...POLICY_DEFAULTS,
  pageEvalEnabled: true,
  fileUploadEnabled: true,
  disabledTools: ["page_upload"],
};

let sent: Array<Record<string, unknown>>;
let posture: PolicyPosture;
let restrictReply: { ok: true } | { ok: false; error: string };

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  posture = { kind: "active", effective: EFFECTIVE };
  restrictReply = { ok: true };
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  // The field labels ride the confirm.pf_<field> keys, whose mixed case the bundle format dictates.
  const FIELD_LABELS = {
    cdpMode: "Route page operations through CDP",
    fileUploadEnabled: "Allow page_upload (local files)",
    pageEvalEnabled: "Allow page_eval (arbitrary JavaScript)",
    confirmPageEval: "Confirm every page_eval",
    hostReverifyMs: "Periodic re-verification interval",
    confirmGraceMs: "Re-confirm grace window",
    disabledTools: "Disabled tools",
  };
  const EN = {
    policy_desc: { message: "What the host lets clients do in this browser." },
    policy_loading: { message: "Loading..." },
    policy_error: { message: "Could not read the policy: $1" },
    policy_none_title: { message: "No host policy applied yet" },
    policy_none_desc: { message: "This browser enforces its built-in deny baseline." },
    policy_blocked_title: { message: "Policy enforcement is blocked" },
    policy_needs_presence: { message: "Loosening needs a presence tap" },
    policy_apply: { message: "Apply" },
    policy_apply_failed: { message: "Could not apply the restriction: $1" },
    policy_ms_unit: { message: "ms" },
    policy_ms_note: { message: "A shorter window is the tighter setting." },
    policy_zero_top_note: { message: "0 means never re-verify." },
    policy_tools_none: { message: "No tools disabled" },
    policy_disable_tool: { message: "Disable" },
    policy_pick_tool: { message: "Choose a tool" },
    policy_effective_note: { message: "Values shown are what this browser enforces now." },
    ...Object.fromEntries(
      Object.entries(FIELD_LABELS).map(([field, message]) => [`confirm_pf_${field}`, { message }]),
    ),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as Record<string, unknown> & { type: string };
    sent.push(m);
    if (m.type === "get_policy") return { ok: true, posture };
    return restrictReply;
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { PolicyEditor } = await import("@/entrypoints/options/PolicyEditor");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  return render(<PolicyEditor />);
}

const restrictions = () => sent.filter((m) => m.type === "restrict_policy");

describe("PolicyEditor direction gating", () => {
  test("a grant that is on can be switched off (tightening posts that one entry); its opposite stays disabled", async () => {
    await mount();
    const pageEval = await screen.findByRole("switch", {
      name: "Allow page_eval (arbitrary JavaScript)",
    });
    expect(pageEval).toBeEnabled();
    await userEvent.click(pageEval);
    await waitFor(() =>
      expect(restrictions()).toEqual([
        { type: "restrict_policy", overlay: { pageEvalEnabled: false } },
      ]),
    );
    // cdpMode is off and permissive at true: its only move relaxes.
    const cdp = screen.getByRole("switch", { name: "Route page operations through CDP" });
    expect(cdp).toBeDisabled();
    // confirmPageEval is on and permissive at false: switching it off would skip a confirmation.
    expect(screen.getByRole("switch", { name: "Confirm every page_eval" })).toBeDisabled();
    expect(screen.getAllByText("Loosening needs a presence tap").length).toBeGreaterThan(0);
  });

  test("a window applies only when shorter; hostReverifyMs 0 is the loosest, so any positive interval applies", async () => {
    await mount();
    const grace = await screen.findByLabelText("Re-confirm grace window");
    const applyFor = (input: HTMLElement) =>
      (input.closest(".flex.items-start") as HTMLElement).querySelector("button") as HTMLElement;
    await userEvent.clear(grace);
    await userEvent.type(grace, "90000");
    expect(applyFor(grace)).toBeDisabled();
    // A blank draft once read as Number("") = 0, a tightening the user never typed.
    await userEvent.clear(grace);
    expect(applyFor(grace)).toBeDisabled();
    await userEvent.type(grace, "30000");
    expect(applyFor(grace)).toBeEnabled();
    await userEvent.click(applyFor(grace));
    await waitFor(() =>
      expect(restrictions()).toEqual([
        { type: "restrict_policy", overlay: { confirmGraceMs: 30000 } },
      ]),
    );
    const reverify = screen.getByLabelText("Periodic re-verification interval");
    await userEvent.clear(reverify);
    await userEvent.type(reverify, "60000");
    expect(applyFor(reverify)).toBeEnabled();
  });

  test("a refused restriction shows the host's error and posts nothing else", async () => {
    restrictReply = { ok: false, error: "the overlay would relax the current effective policy" };
    await mount();
    await userEvent.click(
      await screen.findByRole("switch", { name: "Allow page_upload (local files)" }),
    );
    await screen.findByText(
      "Could not apply the restriction: the overlay would relax the current effective policy",
    );
    expect(restrictions()).toHaveLength(1);
  });

  test("a pin revocation (enclavePin cleared, policy record kept) re-reads the posture and drops the controls", async () => {
    // The editor once refreshed only on the two policy keys, so revoking the pairing from the same
    // page (which blocks the posture while leaving bridgePolicyState in place) kept an editable policy on screen.
    await mount();
    await screen.findByRole("switch", { name: "Allow page_eval (arbitrary JavaScript)" });
    posture = { kind: "blocked", reason: "policy barrier closed" };
    await fakeBrowser.storage.local.set({ enclavePin: null });
    await screen.findByText("policy barrier closed");
    expect(screen.queryAllByRole("switch")).toHaveLength(0);
  });

  test.each([
    {
      name: "pre-cutover",
      posture: { kind: "preCutover" } as PolicyPosture,
      text: "No host policy applied yet",
    },
    {
      name: "blocked",
      posture: { kind: "blocked", reason: "policy barrier closed" } as PolicyPosture,
      text: "policy barrier closed",
    },
  ])("$name renders its state and no field control", async ({ posture: p, text }) => {
    posture = p;
    await mount();
    await screen.findByText(text);
    expect(screen.queryAllByRole("switch")).toHaveLength(0);
    expect(screen.queryByRole("button", { name: "Apply" })).toBeNull();
  });
});
