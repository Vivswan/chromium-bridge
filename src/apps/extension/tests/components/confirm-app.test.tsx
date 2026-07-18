// The confirmation window UI: the security-relevant behaviors. Allow arms only
// after a delay (stray input cannot approve), Escape denies, a settled/stale
// request shows the "gone" state. Rendered with fakeBrowser stubbing the
// confirm_ready/confirm_resolve round trip.

import type { ConfirmPayload } from "@chromium-bridge/shared";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";

const PAYLOAD: ConfirmPayload = {
  id: "confirm_1",
  kind: "eval",
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return document.cookie;",
  deadline: Date.now() + 45000,
};

let sent: Array<{ type: string; approved?: boolean }>;

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
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: string; approved?: boolean };
    sent.push(m);
    if (m.type === "confirm_ready") return { payload: PAYLOAD };
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
      return { payload: null };
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

  test("the kill control stays available on a hardware-gated payload", async () => {
    vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
      const m = msg as { type: string };
      sent.push(m);
      if (m.type === "confirm_ready") return { payload: { ...PAYLOAD, hardware: true } };
      return { ok: true };
    });
    const user = userEvent.setup();
    await mount();
    // Display-only mode: no Allow button, but deny-and-kill (both capability
    // reduction) remains one click away.
    expect(await screen.findByText("return document.cookie;")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /allow/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /kill/i }));
    expect(sent).toContainEqual({ type: "confirm_deny_kill" });
  });
});
