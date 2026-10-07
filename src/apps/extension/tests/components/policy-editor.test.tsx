// The policy editor's two lanes over the SW contract and a stood-in WebAuthn client, the fact the generated
// catalogue states but no render proves: a control whose move tightens posts exactly that one-entry restriction,
// a control whose move relaxes posts the same overlay as a grant and signs the host's request, the history rows
// roll back through the lane the host decides, and the blocked state renders without any field control.

import type { PresenceRequestFrame } from "@chromium-bridge/shared/generated/envelope";
import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/generated/policy";
import type { PolicyPosture } from "@chromium-bridge/shared/runtime-msg";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { assertedCredential, type FakeWebAuthn, installFakeWebAuthn } from "./fake-webauthn";

// A hand-written enforced policy: two grants on, one tool disabled, every window at its default.
const EFFECTIVE: PolicyValues = {
  ...POLICY_DEFAULTS,
  pageEvalEnabled: true,
  fileUploadEnabled: true,
  disabledTools: ["page_upload"],
};

const REQUEST: PresenceRequestFrame = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "set policy: cdpMode=on",
  allowed_credential_ids: ["Y3JlZC1h"],
};

type Reply = Record<string, unknown>;

/** The fields a history row marks as changing on roll-back, in the order shown. */
function marked(row: HTMLElement): string[] {
  return Array.from(row.querySelectorAll("mark"), (m) => m.textContent ?? "");
}

let sent: Reply[];
let replies: Record<string, () => Reply | Promise<Reply>>;
let posture: PolicyPosture;
let webauthn: FakeWebAuthn;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  posture = { kind: "active", effective: EFFECTIVE };
  replies = {
    get_policy: () => ({ ok: true, posture }),
    get_policy_history: () => ({ ok: true, entries: [] }),
    restrict_policy: () => ({ ok: true }),
    grant_policy: () => ({ ok: true, request: REQUEST }),
    rollback_policy: () => ({ ok: true, request: null }),
    webauthn_presence_assert: () => ({ ok: true }),
  };
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = "test-ext-id";
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
    policy_grant_confirm: { message: "Confirm the change" },
    policy_grant_failed: { message: "Change refused: $1" },
    policy_enable_tool: { message: "Re-enable $1" },
    policy_ms_unit: { message: "ms" },
    policy_ms_note: { message: "A shorter window is the tighter setting." },
    policy_zero_top_note: { message: "0 means never re-verify." },
    policy_tools_none: { message: "No tools disabled" },
    policy_disable_tool: { message: "Disable" },
    policy_pick_tool: { message: "Choose a tool" },
    policy_effective_note: { message: "Values shown are what this browser enforces now." },
    policy_history_title: { message: "Previous revisions" },
    policy_history_refresh: { message: "Refresh history" },
    policy_history_desc: { message: "history desc" },
    policy_history_empty: { message: "No superseded revisions yet." },
    policy_history_error: { message: "Could not read the policy history: $1" },
    policy_history_row: { message: "Revision $1, superseded $2" },
    policy_history_signed: { message: "signed" },
    policy_history_unsigned: { message: "unsigned" },
    policy_history_overlay: { message: "with restrictions" },
    policy_history_differs: { message: "would change on roll-back" },
    policy_history_same: { message: "Same as now" },
    policy_history_damaged: { message: "Unreadable entry, superseded $1" },
    policy_rollback: { message: "Roll back" },
    presence_asking: { message: "asking" },
    presence_tapping: { message: "tapping" },
    presence_confirming: { message: "confirming" },
    presence_window_title: { message: "no authenticator enrolled here" },
    presence_window_desc: { message: "software confirmation" },
    webauthn_reason_prompt_dismissed: { message: "<dismissed sentence>" },
    common_cancel: { message: "Cancel" },
    ...Object.fromEntries(
      Object.entries(FIELD_LABELS).map(([field, message]) => [`confirm_pf_${field}`, { message }]),
    ),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as Reply & { type: string };
    sent.push(m);
    const reply = replies[m.type];
    if (!reply) throw new Error(`no reply for ${m.type}`);
    return reply();
  });
  webauthn = installFakeWebAuthn();
  webauthn.getResponse = () => assertedCredential("Y3JlZC1h");
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

const ASSERT = {
  type: "webauthn_presence_assert",
  nonce: REQUEST.nonce,
  credential_id: "Y3JlZC1h",
  authenticator_data: "YXV0aC1kYXRh",
  client_data_json: "Y2xpZW50LWRhdGEtZ2V0",
  signature: "c2lnbmF0dXJl",
};

const applyFor = (input: HTMLElement) =>
  (input.closest(".flex.items-start") as HTMLElement).querySelector("button") as HTMLElement;

const writes = () =>
  sent.filter((m) =>
    ["restrict_policy", "grant_policy", "rollback_policy"].includes(String(m.type)),
  );
const asserts = () => sent.filter((m) => m.type === "webauthn_presence_assert");

describe("PolicyEditor lanes", () => {
  test("a grant that is on switches off as a restriction; one that is off switches on as a grant signed by this browser's tap", async () => {
    await mount();
    const pageEval = await screen.findByRole("switch", {
      name: "Allow page_eval (arbitrary JavaScript)",
    });
    await userEvent.click(pageEval);
    await waitFor(() =>
      expect(writes()).toEqual([{ type: "restrict_policy", overlay: { pageEvalEnabled: false } }]),
    );
    expect(asserts()).toEqual([]);
    // cdpMode is off and permissive at true: its only move relaxes, so it rides the grant lane.
    const cdp = screen.getByRole("switch", { name: "Route page operations through CDP" });
    expect(cdp).toBeEnabled();
    expect(screen.getAllByText("Loosening needs a presence tap").length).toBeGreaterThan(0);
    await userEvent.click(cdp);
    await waitFor(() =>
      expect(writes()).toEqual([
        { type: "restrict_policy", overlay: { pageEvalEnabled: false } },
        { type: "grant_policy", overlay: { cdpMode: true } },
      ]),
    );
    await waitFor(() => expect(asserts()).toEqual([ASSERT]));
    expect(screen.queryByText(/Change refused/)).toBeNull();
  });

  test("a window applies as a restriction when shorter and as a grant when longer; a blank draft applies nothing", async () => {
    await mount();
    const grace = await screen.findByLabelText("Re-confirm grace window");
    // A blank draft once read as Number("") = 0, a tightening the user never typed.
    await userEvent.clear(grace);
    expect(applyFor(grace)).toBeDisabled();
    await userEvent.type(grace, "30000");
    await userEvent.click(applyFor(grace));
    await waitFor(() =>
      expect(writes()).toEqual([{ type: "restrict_policy", overlay: { confirmGraceMs: 30000 } }]),
    );
    await userEvent.clear(grace);
    await userEvent.type(grace, "90000");
    expect(screen.getAllByText("Loosening needs a presence tap").length).toBeGreaterThan(0);
    await userEvent.click(applyFor(grace));
    await waitFor(() =>
      expect(writes()[1]).toEqual({ type: "grant_policy", overlay: { confirmGraceMs: 90000 } }),
    );
  });

  test("while a submitted window awaits the host, every control is disabled and the draft stays the submitted value", async () => {
    // The input stayed editable while its submitted value awaited authorization, so the editor could show
    // 30000 while the tap authorized 90000. One pending flag covers the whole editor, history included.
    replies.get_policy_history = () => ({
      ok: true,
      entries: [
        {
          id: "a1",
          signed: true,
          overlay_active: false,
          superseded_unix: 1_700_000_000,
          held: { revision: 2, effective: EFFECTIVE },
        },
      ],
    });
    let answer!: (reply: Reply) => void;
    replies.grant_policy = () =>
      new Promise<Reply>((resolve) => {
        answer = resolve;
      });
    await mount();
    const grace = await screen.findByLabelText("Re-confirm grace window");
    await screen.findByRole("button", { name: "Roll back" });
    await userEvent.clear(grace);
    await userEvent.type(grace, "90000");
    await userEvent.click(applyFor(grace));
    await screen.findByText("asking");
    expect(grace).toBeDisabled();
    expect(grace).toHaveValue(90000);
    const controls = () => [
      ...screen.getAllByRole("switch"),
      ...screen.getAllByRole("button"),
      ...screen.getAllByRole("spinbutton"),
      screen.getByRole("combobox"),
    ];
    for (const control of controls()) expect(control).toBeDisabled();
    // The tool picker is a composite control that does not inherit the fieldset's state: pending must keep
    // it shut, and it must open once the act settles (the control for this assertion).
    await userEvent.click(screen.getByRole("combobox"));
    expect(screen.queryByRole("listbox")).toBeNull();
    answer({ ok: true, request: REQUEST });
    await waitFor(() => expect(asserts()).toEqual([ASSERT]));
    await waitFor(() => expect(grace).toBeEnabled());
    // The fixture's effective value never moves, so the 90000 draft still differs and its Apply is on. The
    // other row's Apply (an unchanged draft) and Disable (no pick) are off on their own.
    expect(applyFor(grace)).toBeEnabled();
    for (const control of controls()) {
      if (!["Apply", "Disable"].includes(control.textContent ?? "")) expect(control).toBeEnabled();
    }
    await userEvent.click(screen.getByRole("combobox"));
    await screen.findByRole("listbox");
  });

  test("re-enabling a disabled tool posts the whole remaining set as a grant", async () => {
    await mount();
    await userEvent.click(await screen.findByRole("button", { name: "Re-enable page_upload" }));
    await waitFor(() =>
      expect(writes()).toEqual([{ type: "grant_policy", overlay: { disabledTools: [] } }]),
    );
  });

  test.each([
    {
      name: "a refused restriction",
      arrange: () => {
        replies.restrict_policy = () => ({
          ok: false,
          error: "the overlay would relax the current effective policy",
        });
      },
      control: "Allow page_upload (local files)",
      text: "Could not apply the restriction: the overlay would relax the current effective policy",
    },
    {
      name: "a grant the host refuses before any request, in the CLI's words",
      arrange: () => {
        replies.grant_policy = () => ({
          ok: false,
          error:
            "no host key on this machine; a policy grant is a signed baseline and refuses without one (pair first)",
        });
      },
      control: "Route page operations through CDP",
      text: "Change refused: no host key on this machine; a policy grant is a signed baseline and refuses without one (pair first)",
    },
    {
      name: "a dismissed authenticator prompt",
      arrange: () => {
        webauthn.getResponse = () => {
          throw new DOMException("The operation was cancelled", "NotAllowedError");
        };
      },
      control: "Route page operations through CDP",
      text: "Change refused: <dismissed sentence>",
    },
  ])("$name shows its sentence and posts one write", async ({ arrange, control, text }) => {
    arrange();
    await mount();
    await userEvent.click(await screen.findByRole("switch", { name: control }));
    await screen.findByText(text);
    expect(writes()).toHaveLength(1);
  });

  test("history rows roll back through the lane the host decides; a damaged row offers no roll-back", async () => {
    replies.get_policy_history = () => ({
      ok: true,
      entries: [
        {
          id: "a1",
          signed: true,
          overlay_active: true,
          superseded_unix: 1_700_000_000,
          held: { revision: 2, effective: EFFECTIVE },
        },
        { id: "b2", signed: false, overlay_active: false, superseded_unix: 1_700_000_100 },
      ],
    });
    await mount();
    await screen.findByText(/^Revision 2, superseded /);
    await screen.findByText(/^Unreadable entry, superseded /);
    expect(screen.getByText("signed, with restrictions")).toBeInTheDocument();
    expect(screen.getByText("Same as now")).toBeInTheDocument();
    expect(marked(screen.getAllByRole("listitem")[0] as HTMLElement)).toEqual([]);
    const rollbacks = screen.getAllByRole("button", { name: "Roll back" });
    expect(rollbacks).toHaveLength(1);
    // Applied free: no request, and the ring is re-read.
    await userEvent.click(rollbacks[0] as HTMLElement);
    await waitFor(() =>
      expect(writes()).toEqual([
        {
          type: "rollback_policy",
          revision: 2,
          entry: { id: "a1" },
        },
      ]),
    );
    await waitFor(() =>
      expect(sent.filter((m) => m.type === "get_policy_history")).toHaveLength(2),
    );
    expect(asserts()).toEqual([]);
    // A write from another surface moves nothing in storage, so the ring is re-read on demand.
    await userEvent.click(screen.getByRole("button", { name: "Refresh history" }));
    await waitFor(() =>
      expect(sent.filter((m) => m.type === "get_policy_history")).toHaveLength(3),
    );
    // Relaxing: the host's request is signed here.
    replies.rollback_policy = () => ({
      ok: true,
      request: { ...REQUEST, action: "roll policy back to revision 2: pageEvalEnabled=on" },
    });
    await userEvent.click(screen.getByRole("button", { name: "Roll back" }));
    await waitFor(() => expect(asserts()).toEqual([ASSERT]));
  });

  test("two rows at one revision read apart by the policy each held, and roll back by the row, not the revision", async () => {
    // Every restriction while revision 4 was current pushed a ring entry at revision 4; the host refuses
    // "revision 4" as ambiguous, so the page names the row it listed. The two rows once rendered identically
    // ("signed", the same second) while their buttons posted different ids; each now shows the whole policy it
    // held, the line `policy history` prints, with the fields a roll-back would change marked.
    replies.get_policy_history = () => ({
      ok: true,
      entries: [
        {
          id: "c3",
          signed: true,
          overlay_active: true,
          superseded_unix: 1_700_000_000,
          held: { revision: 4, effective: { ...EFFECTIVE, pageEvalEnabled: false } },
        },
        {
          id: "d4",
          signed: true,
          overlay_active: true,
          superseded_unix: 1_700_000_000,
          held: {
            revision: 4,
            effective: { ...EFFECTIVE, cdpMode: true, pageEvalEnabled: false, disabledTools: [] },
          },
        },
      ],
    });
    await mount();
    const rollbacks = await screen.findAllByRole("button", { name: "Roll back" });
    expect(rollbacks).toHaveLength(2);
    expect(screen.getAllByText("signed, with restrictions")).toHaveLength(2);
    const rows = screen.getAllByRole("listitem") as HTMLElement[];
    expect(rows[0]).toHaveTextContent(
      "effective=cdpMode=off,fileUploadEnabled=on,handleDialogEnabled=off,pageEvalEnabled=off," +
        "confirmHighRiskClick=on,confirmPageEval=on,presenceConfirm=on,confirmTabClose=on," +
        "warnPreciseSnapshot=on,evalMask=on,hostReverifyMs=0,confirmGraceMs=60000," +
        "clickToastTimeoutMs=30000,evalToastTimeoutMs=45000,disabledTools=[page_upload]",
    );
    expect(marked(rows[0] as HTMLElement)).toEqual(["pageEvalEnabled=off"]);
    expect(rows[1]).toHaveTextContent("effective=cdpMode=on,fileUploadEnabled=on,");
    expect(marked(rows[1] as HTMLElement)).toEqual([
      "cdpMode=on",
      "pageEvalEnabled=off",
      "disabledTools=[]",
    ]);
    expect(screen.queryByText("Same as now")).toBeNull();
    await userEvent.click(rollbacks[1] as HTMLElement);
    await waitFor(() =>
      expect(writes()).toEqual([
        {
          type: "rollback_policy",
          revision: 4,
          entry: { id: "d4" },
        },
      ]),
    );
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

  test("pre-cutover renders its note and the deny baseline's controls, and every edit signs the first baseline", async () => {
    // `policy restrict` has nothing to restrict before a baseline exists, so a tightening move is a grant too.
    posture = { kind: "preCutover" };
    await mount();
    await screen.findByText("No host policy applied yet");
    expect(screen.queryByText("Values shown are what this browser enforces now.")).toBeNull();
    await userEvent.click(
      screen.getByRole("switch", { name: "Route page operations through CDP" }),
    );
    const grace = screen.getByLabelText("Re-confirm grace window");
    await userEvent.clear(grace);
    await userEvent.type(grace, "1000");
    await userEvent.click(applyFor(grace));
    await waitFor(() =>
      expect(writes()).toEqual([
        { type: "grant_policy", overlay: { cdpMode: true } },
        { type: "grant_policy", overlay: { confirmGraceMs: 1000 } },
      ]),
    );
  });

  test("the refusal of one lane clears when the other lane's write starts", async () => {
    webauthn.getResponse = () => {
      throw new DOMException("The operation was cancelled", "NotAllowedError");
    };
    await mount();
    await userEvent.click(
      await screen.findByRole("switch", { name: "Route page operations through CDP" }),
    );
    await screen.findByText("Change refused: <dismissed sentence>");
    await userEvent.click(
      screen.getByRole("switch", { name: "Allow page_eval (arbitrary JavaScript)" }),
    );
    await waitFor(() =>
      expect(screen.queryByText("Change refused: <dismissed sentence>")).toBeNull(),
    );
  });

  test("blocked renders its reason and no field control", async () => {
    posture = { kind: "blocked", reason: "policy barrier closed" };
    await mount();
    await screen.findByText("policy barrier closed");
    expect(screen.queryAllByRole("switch")).toHaveLength(0);
    expect(screen.queryByRole("button", { name: "Apply" })).toBeNull();
  });
});
