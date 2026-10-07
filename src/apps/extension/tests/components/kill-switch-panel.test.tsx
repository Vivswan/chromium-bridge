// The kill panel's release over the SW contract and a stood-in WebAuthn client. The panel never claims a release
// itself: the answer's verdict and the mirror do.

import type { PresenceRequestFrame } from "@chromium-bridge/shared/generated/envelope";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { requestOptions } from "@/lib/shared/webauthn-ceremony";
import { assertedCredential, type FakeWebAuthn, installFakeWebAuthn } from "./fake-webauthn";

const EXT_ID = "test-ext-id";

const REQUEST: PresenceRequestFrame = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "release the kill switch",
  allowed_credential_ids: ["Y3JlZC1h"],
};

type Reply = Record<string, unknown>;

let sent: Reply[];
let replies: Record<string, () => Reply | Promise<Reply>>;
let webauthn: FakeWebAuthn;

// Synthetic messages: the test pins which sentence a code selects, not the English wording.
const EN = Object.fromEntries(
  Object.entries({
    kill_desc: "desc",
    kill_release_pointer: "pointer",
    kill_engage: "Engage kill switch",
    kill_release: "Release kill switch",
    presence_asking: "asking",
    presence_tapping: "tapping",
    presence_confirming: "confirming",
    presence_window_title: "no authenticator enrolled here",
    presence_window_desc: "software confirmation",
    kill_release_confirm: "Confirm release",
    kill_release_failed: "Release refused: $1",
    kill_state_alive: "alive",
    kill_state_killed: "killed",
    kill_updated: "updated $1",
    kill_failed: "failed: $1",
    kill_no_reply: "no reply",
    webauthn_reason_wrong_browser_label: "<wrong browser sentence>",
    webauthn_reason_software_confirmation_not_allowed: "<no downgrade sentence>",
    webauthn_reason_prompt_dismissed: "<dismissed sentence>",
    common_cancel: "Cancel",
  }).map(([key, message]) => [key, { message }]),
);

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  sent = [];
  replies = {
    get_kill: () => ({ ok: true, sent: true, state: "killed", at: 1_700_000_000_000 }),
    kill_release: () => ({ ok: true, request: REQUEST }),
    webauthn_presence_assert: () => ({ ok: true }),
    webauthn_presence_confirm: () => ({ ok: true }),
  };
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
  const { KillSwitchPanel } = await import("@/entrypoints/options/KillSwitchPanel");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  const view = render(<KillSwitchPanel />);
  await screen.findByText("killed");
  return view;
}

const ASSERT = {
  type: "webauthn_presence_assert",
  nonce: REQUEST.nonce,
  credential_id: "Y3JlZC1h",
  authenticator_data: "YXV0aC1kYXRh",
  client_data_json: "Y2xpZW50LWRhdGEtZ2V0",
  signature: "c2lnbmF0dXJl",
};

describe("KillSwitchPanel release", () => {
  test("killed: Release asks the host, signs its request with this browser's authenticator, and the mirror shows the result", async () => {
    await mount();
    expect(screen.queryByRole("button", { name: "Engage kill switch" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Release kill switch" }));
    await waitFor(() =>
      expect(sent).toEqual([{ type: "get_kill" }, { type: "kill_release" }, ASSERT]),
    );
    // The panel claims nothing itself: the engaged state stays until the host's frame moves the mirror.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Release kill switch" })).toBeEnabled(),
    );
    expect(screen.getByText("killed")).toBeInTheDocument();
    expect(webauthn.calls).toEqual({ create: [], get: [requestOptions(REQUEST, EXT_ID)] });
    // The host's kill_status_result moved the mirror (kill.ts); the panel re-reads and the step text goes.
    replies.get_kill = () => ({ ok: true, sent: true, state: "alive", at: 1_700_000_001_000 });
    await fakeBrowser.storage.local.set({
      bridgeKillMirror: { state: "alive", at: 1_700_000_001_000 },
    });
    await screen.findByText("alive");
    expect(screen.queryByRole("button", { name: "Release kill switch" })).toBeNull();
    expect(screen.getByRole("button", { name: "Engage kill switch" })).toBeEnabled();
  });

  test("the host's action is on screen while this browser's authenticator is asked for the tap", async () => {
    // A tap approves whatever statement the host minted; the page once showed that statement only for a
    // software confirmation, so a hardware tap was asked for blind. The authenticator's prompt covers the page
    // the moment `get` is entered, so the statement must be committed by then, not merely scheduled.
    let tapped!: () => void;
    const held = new Promise<void>((resolve) => {
      tapped = resolve;
    });
    let onScreenAtGet: boolean | null = null;
    webauthn.getResponse = () => {
      onScreenAtGet = screen.queryByText(REQUEST.action) !== null;
      return held.then(() => assertedCredential("Y3JlZC1h"));
    };
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Release kill switch" }));
    await screen.findByText("tapping");
    expect(onScreenAtGet).toBe(true);
    expect(screen.getByText(REQUEST.action)).toBeInTheDocument();
    expect(sent.map((m) => m.type)).toEqual(["get_kill", "kill_release"]);
    tapped();
    await waitFor(() =>
      expect(sent).toEqual([{ type: "get_kill" }, { type: "kill_release" }, ASSERT]),
    );
    expect(screen.queryByText(REQUEST.action)).toBeNull();
  });

  test("a request admitting no credential is offered as a software confirmation, and Confirm answers with its nonce", async () => {
    replies.kill_release = () => ({
      ok: true,
      request: { ...REQUEST, allowed_credential_ids: [] },
    });
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Release kill switch" }));
    await screen.findByText("no authenticator enrolled here");
    expect(screen.getByText("software confirmation")).toBeInTheDocument();
    expect(screen.getByText(REQUEST.action)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Confirm release" }));
    await waitFor(() =>
      expect(sent).toEqual([
        { type: "get_kill" },
        { type: "kill_release" },
        { type: "webauthn_presence_confirm", nonce: REQUEST.nonce },
      ]),
    );
    expect(webauthn.calls.get).toEqual([]);
  });

  test("Cancel on the software confirmation answers nothing and offers Release again", async () => {
    replies.kill_release = () => ({
      ok: true,
      request: { ...REQUEST, allowed_credential_ids: [] },
    });
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Release kill switch" }));
    await screen.findByText("no authenticator enrolled here");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText("no authenticator enrolled here")).toBeNull();
    expect(screen.getByRole("button", { name: "Release kill switch" })).toBeEnabled();
    expect(sent.map((m) => m.type)).toEqual(["get_kill", "kill_release"]);
  });

  test.each([
    {
      name: "an assertion from a credential enrolled under another browser",
      arrange: () => {
        replies.webauthn_presence_assert = () => ({ ok: false, error: "wrong_browser_label" });
      },
      confirm: false,
      sentence: "<wrong browser sentence>",
    },
    {
      name: "a window confirmation the host does not admit",
      arrange: () => {
        replies.kill_release = () => ({
          ok: true,
          request: { ...REQUEST, allowed_credential_ids: [] },
        });
        replies.webauthn_presence_confirm = () => ({
          ok: false,
          error: "software_confirmation_not_allowed",
        });
      },
      confirm: true,
      sentence: "<no downgrade sentence>",
    },
    {
      name: "the user dismissing the authenticator prompt",
      arrange: () => {
        webauthn.getResponse = () => {
          throw new DOMException("The operation was cancelled", "NotAllowedError");
        };
      },
      confirm: false,
      sentence: "<dismissed sentence>",
    },
    {
      name: "a worker with no host, shown as it came",
      arrange: () => {
        replies.kill_release = () => ({ ok: false, error: "native host not connected" });
      },
      confirm: false,
      sentence: "native host not connected",
    },
  ])(
    "$name renders its sentence and leaves the switch engaged",
    async ({ arrange, confirm, sentence }) => {
      arrange();
      await mount();
      await userEvent.click(screen.getByRole("button", { name: "Release kill switch" }));
      if (confirm) {
        await screen.findByText("no authenticator enrolled here");
        await userEvent.click(screen.getByRole("button", { name: "Confirm release" }));
      }
      await screen.findByText(`Release refused: ${sentence}`);
      expect(screen.getByText("killed")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Release kill switch" })).toBeEnabled();
    },
  );
});
