// The confirmation window UI: the security-relevant behaviors. Allow arms only
// after a delay (stray input cannot approve), Escape denies, a settled/stale
// request shows the "gone" state. Rendered with fakeBrowser stubbing the
// confirm_ready/confirm_resolve round trip.

import type { ConfirmPayload } from "@chromium-bridge/shared/confirm";
import type { PolicyFieldName } from "@chromium-bridge/shared/generated/policy";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { requestOptions } from "@/lib/shared/webauthn-ceremony";
import { assertedCredential, installFakeWebAuthn } from "./fake-webauthn";

const PAYLOAD: ConfirmPayload = {
  id: "confirm_1",
  kind: "eval",
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return document.cookie;",
  deadline: Date.now() + 45000,
};

let sent: Array<{ type: string; approved?: boolean }>;

// The flattened form of the locale bundle's `confirm.pf_<field>` label, one per policy field.
const policyFieldLabel = (field: PolicyFieldName) => `confirm_pf_${field}` as const;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  window.history.replaceState({}, "", "/confirm.html?id=confirm_1");
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  const EN = {
    confirm_title: { message: "Chromium Bridge" },
    confirm_allow: { message: "Allow" },
    confirm_deny: { message: "Deny" },
    confirm_gone: { message: "This confirmation is no longer pending." },
    confirm_countdown: { message: "Denies automatically in $1s" },
    confirm_q_eval: { message: "Run this JavaScript on the page?" },
    confirm_warn_eval: { message: "This code runs in the page with your session." },
    confirm_kill_note: { message: "Denies this request and cuts every client off every browser." },
    kill_engage: { message: "Engage kill switch" },
    confirm_h_policy_relax: { message: "Loosen this browser's bridge policy?" },
    confirm_warn_policy_relax: { message: "Nothing proves who sent this policy." },
    confirm_policy_relax_none: {
      message: "The changes in this policy could not be itemized.",
    },
    [policyFieldLabel("pageEvalEnabled")]: { message: "Allow page_eval (arbitrary JavaScript)" },
    [policyFieldLabel("confirmGraceMs")]: { message: "Re-confirm grace window" },
    confirm_gate_strip_label: { message: "Which gate is held" },
    confirm_gate_client: { message: "client" },
    confirm_gate_host: { message: "host" },
    confirm_gate_host_held: { message: "host gate" },
    confirm_gate_browser_held: { message: "browser gate" },
    confirm_approve_authenticator: { message: "Approve with this device's authenticator" },
    confirm_approve_software: { message: "Allow (software confirmation)" },
    confirm_answer_refused: { message: "The answer was not accepted: $1" },
    webauthn_reason_software_confirmation_not_allowed: { message: "<no downgrade sentence>" },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: string; approved?: boolean };
    sent.push(m);
    if (m.type === "confirm_ready") return { ok: true, payload: PAYLOAD };
    return { ok: true };
  });
  vi.stubGlobal("close", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function mount() {
  const { ConfirmApp } = await import("@/entrypoints/confirm/ConfirmApp");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  return render(<ConfirmApp />);
}

describe("ConfirmApp", () => {
  test("renders the payload and shows the eval warning", async () => {
    await mount();
    expect(await screen.findByText("return document.cookie;")).toBeInTheDocument();
    expect(screen.getByText("https://example.com")).toBeInTheDocument();
    // The eval warning is shown for the eval kind.
    expect(screen.getByText(/runs in the page with your session/i)).toBeInTheDocument();
  });

  test("Allow is disabled until it arms, then approves", async () => {
    const user = userEvent.setup();
    await mount();
    const allow = await screen.findByRole("button", { name: /allow/i });
    expect(allow).toBeDisabled(); // stray input cannot approve
    await waitFor(() => expect(allow).toBeEnabled(), { timeout: 2000 });
    await user.click(allow);
    expect(sent).toContainEqual({ type: "confirm_resolve", id: "confirm_1", approved: true });
  });

  test("Deny is immediately available and denies", async () => {
    const user = userEvent.setup();
    await mount();
    const deny = await screen.findByRole("button", { name: /deny/i });
    await user.click(deny);
    expect(sent).toContainEqual({ type: "confirm_resolve", id: "confirm_1", approved: false });
  });

  test("Escape denies", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText("return document.cookie;");
    await user.keyboard("{Escape}");
    expect(sent).toContainEqual({ type: "confirm_resolve", id: "confirm_1", approved: false });
  });

  test("a stale request (no payload) shows the gone state and cannot approve", async () => {
    vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
      sent.push(msg as { type: string });
      return { ok: true, payload: null };
    });
    await mount();
    expect(await screen.findByText(/no longer pending/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /allow/i })).not.toBeInTheDocument();
  });

  test("the footer kill control sends confirm_deny_kill, never an approval", async () => {
    const user = userEvent.setup();
    await mount();
    const kill = await screen.findByRole("button", { name: /kill/i });
    await user.click(kill);
    expect(sent).toContainEqual({ type: "confirm_deny_kill" });
    // The panic exit must not be able to approve anything.
    expect(sent).not.toContainEqual(expect.objectContaining({ approved: true }));
    // Disabled from the first click: no double-fire while the SW acts.
    expect(kill).toBeDisabled();
  });

  test("Deny keeps the default focus; the kill control is never autofocused", async () => {
    await mount();
    const deny = await screen.findByRole("button", { name: /deny/i });
    const kill = screen.getByRole("button", { name: /kill/i });
    expect(deny).toHaveFocus();
    expect(kill).not.toHaveFocus();
  });

  test("the kill control stays available on a presence-gated payload", async () => {
    stubPresence(REQUEST);
    const user = userEvent.setup();
    await mount();
    // No plain Allow: the answer is the host's request; deny-and-kill (both
    // capability reduction) remains one click away.
    expect(await screen.findByText("return document.cookie;")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^allow$/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /kill/i }));
    expect(sent).toContainEqual({ type: "confirm_deny_kill" });
  });
});

// The presence route: the window answers the host's request instead of offering Allow. The host's
// verdict closes the window through the service; the window closes itself only on the host's ok.
const REQUEST = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "page_eval on https://example.com",
  allowed_credential_ids: ["Y3JlZC1h"],
};

function stubPresence(
  request: typeof REQUEST | null,
  replies: Record<string, () => unknown> = {},
): void {
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: string; approved?: boolean };
    sent.push(m);
    if (m.type === "confirm_ready") return { ok: true, payload: { ...PAYLOAD, presence: true } };
    if (m.type === "webauthn_presence_pending") return { ok: true, request };
    return replies[m.type]?.() ?? { ok: true };
  });
}

describe("ConfirmApp presence route", () => {
  test("with a credential enrolled, the armed button runs the tap over the host's request and posts the assertion with its nonce", async () => {
    stubPresence(REQUEST);
    (fakeBrowser.runtime as unknown as Record<string, unknown>).id = "test-ext-id";
    const webauthn = installFakeWebAuthn();
    webauthn.getResponse = () => assertedCredential("Y3JlZC1h");
    const user = userEvent.setup();
    await mount();
    const approve = await screen.findByRole("button", {
      name: "Approve with this device's authenticator",
    });
    expect(approve).toBeDisabled(); // stray input cannot approve
    expect(screen.queryByRole("button", { name: /^allow/i })).not.toBeInTheDocument();
    expect(screen.getByText("host gate")).toBeInTheDocument();
    await waitFor(() => expect(approve).toBeEnabled(), { timeout: 2000 });
    await user.click(approve);
    await waitFor(() =>
      expect(sent).toContainEqual({
        type: "webauthn_presence_assert",
        nonce: "nonce-0002",
        credential_id: "Y3JlZC1h",
        authenticator_data: "YXV0aC1kYXRh",
        client_data_json: "Y2xpZW50LWRhdGEtZ2V0",
        signature: "c2lnbmF0dXJl",
      }),
    );
    expect(webauthn.calls.get).toEqual([requestOptions(REQUEST as never, "test-ext-id")]);
    // Never a window-side approval.
    expect(sent).not.toContainEqual(
      expect.objectContaining({ type: "confirm_resolve", approved: true }),
    );
    expect(window.close).toHaveBeenCalled();
  });

  test("with no credential enrolled, the button is the software confirmation, posted with the nonce", async () => {
    stubPresence({ ...REQUEST, allowed_credential_ids: [] });
    const user = userEvent.setup();
    await mount();
    const allow = await screen.findByRole("button", { name: "Allow (software confirmation)" });
    expect(screen.queryByText("host gate")).not.toBeInTheDocument();
    await waitFor(() => expect(allow).toBeEnabled(), { timeout: 2000 });
    await user.click(allow);
    await waitFor(() =>
      expect(sent).toContainEqual({ type: "webauthn_presence_confirm", nonce: "nonce-0002" }),
    );
    expect(window.close).toHaveBeenCalled();
  });

  test("an answer that is not accepted is shown, and the component itself neither closes nor approves", async () => {
    stubPresence(
      { ...REQUEST, allowed_credential_ids: [] },
      {
        webauthn_presence_confirm: () => ({
          ok: false,
          error: "software_confirmation_not_allowed",
        }),
      },
    );
    const user = userEvent.setup();
    await mount();
    const allow = await screen.findByRole("button", { name: "Allow (software confirmation)" });
    await waitFor(() => expect(allow).toBeEnabled(), { timeout: 2000 });
    await user.click(allow);
    expect(
      await screen.findByText("The answer was not accepted: <no downgrade sentence>"),
    ).toBeInTheDocument();
    // The service's dismiss closes the window on a host refusal; this document never does on its own.
    expect(window.close).not.toHaveBeenCalled();
    expect(sent).not.toContainEqual(expect.objectContaining({ approved: true }));
    await user.click(screen.getByRole("button", { name: /deny/i }));
    expect(sent).toContainEqual({ type: "confirm_resolve", id: "confirm_1", approved: false });
  });

  test("with no request pending only Deny remains", async () => {
    stubPresence(null);
    await mount();
    expect(await screen.findByText("return document.cookie;")).toBeInTheDocument();
    expect(await screen.findByText(/no longer pending/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /allow|approve/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /deny/i })).toBeInTheDocument();
  });

  test("a pending-request read that fails is shown as the failure, never as no request", async () => {
    vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
      const m = msg as { type: string };
      sent.push(m);
      if (m.type === "confirm_ready") return { ok: true, payload: { ...PAYLOAD, presence: true } };
      if (m.type === "webauthn_presence_pending") return { ok: false, error: "worker restarting" };
      return { ok: true };
    });
    await mount();
    expect(
      await screen.findByText("The answer was not accepted: worker restarting"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/no longer pending/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /allow|approve/i })).not.toBeInTheDocument();
  });
});

// The unpinned policy-relaxation payload. No page is involved, the detail
// carries wire field names that render beside their localized labels, and the
// ordinary Allow/Deny mechanics (arming delay, Escape, resolve) stay exactly
// the window's.
describe("ConfirmApp policy_relax", () => {
  function stubPolicyPayload(detail: string) {
    vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
      const m = msg as { type: string; approved?: boolean };
      sent.push(m);
      if (m.type === "confirm_ready") {
        return {
          ok: true,
          payload: { ...PAYLOAD, kind: "policy_relax", origin: "", tabTitle: "", detail },
        };
      }
      return { ok: true };
    });
  }

  test("renders each relaxing field's wire name beside its localized label, and no page row", async () => {
    stubPolicyPayload("pageEvalEnabled\nconfirmGraceMs = 120000");
    await mount();
    expect(await screen.findByText(/Loosen this browser's bridge policy\?/)).toBeInTheDocument();
    expect(
      screen.getByText(/pageEvalEnabled - Allow page_eval \(arbitrary JavaScript\)/),
    ).toBeInTheDocument();
    // Both line shapes label: a bare wire name (later-document relaxation
    // diff) and `field = value` (the first document's full value set).
    expect(
      screen.getByText(/confirmGraceMs = 120000 - Re-confirm grace window/),
    ).toBeInTheDocument();
    expect(screen.getByText("policy_current")).toBeInTheDocument();
    expect(screen.getByText(/Nothing proves who sent this policy/)).toBeInTheDocument();
    // No page is involved: the origin/title row is omitted, not rendered empty.
    expect(screen.queryByText('""')).not.toBeInTheDocument();
  });

  test("an unknown wire name stays verbatim - a granted field is never dropped from the payload", async () => {
    stubPolicyPayload("someFutureField");
    await mount();
    expect(await screen.findByText("someFutureField")).toBeInTheDocument();
  });

  test("the HOST segment renders IDLE: an unsigned app-confirm approval never claims host or authenticator attestation", async () => {
    stubPolicyPayload("pageEvalEnabled");
    await mount();
    await screen.findByText(/Loosen this browser's bridge policy\?/);
    // Nothing proved who sent this push, so the gate strip must not claim
    // otherwise: the host dot is idle - neither passed (live) nor held.
    const host = screen.getByText("host");
    expect(host.className).toContain("text-text-3");
    expect(host.className).not.toContain("text-text-2");
    const dot = host.querySelector(".status-dot");
    expect(dot).not.toBeNull();
    expect(dot?.className).not.toContain("live");
    expect(dot?.className).not.toContain("pending");
    // And it is the browser-side strip, never the authenticator one: the held
    // "host gate" rendering would read as authenticator attestation, and the
    // presence route would replace the Allow button.
    expect(screen.queryByText("host gate")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /allow/i })).toBeInTheDocument();
  });

  test("an empty detail falls back to the could-not-itemize note (defensive: the approval lane always itemizes, so it is unreachable) and still requires the gesture", async () => {
    stubPolicyPayload("");
    const user = userEvent.setup();
    await mount();
    expect(
      await screen.findByText(/The changes in this policy could not be itemized/),
    ).toBeInTheDocument();
    // The ordinary window mechanics govern: Allow arms, then approves.
    const allow = screen.getByRole("button", { name: /allow/i });
    await waitFor(() => expect(allow).toBeEnabled(), { timeout: 2000 });
    await user.click(allow);
    expect(sent).toContainEqual({ type: "confirm_resolve", id: "confirm_1", approved: true });
  });
});
