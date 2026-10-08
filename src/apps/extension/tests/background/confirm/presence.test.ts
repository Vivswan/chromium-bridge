// The presence route's provider over a fake Connection and a fake window surface: the host is asked before any
// window opens, the window's answer is judged by the host alone, and every refusal denies with no window.

import type { ConfirmPayload } from "@genkan/shared/confirm";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { PresenceExchangeProvider } from "@/lib/background/confirm/presence";
import type {
  ConfirmationProvider,
  PresencePayload,
  Presentation,
} from "@/lib/background/confirm/service";
import {
  assertPresence,
  collaborator,
  confirmPresence,
  handleWebAuthnFrame,
  pendingPresenceRequest,
  resetWebAuthnForTests,
} from "@/lib/webauthn/exchange";
import { attach } from "../fake-connection";

const PAYLOAD: PresencePayload = {
  id: "confirm_1",
  kind: "eval",
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return 1;",
  deadline: 1_700_000_045_000,
  presence: true,
};

const REQUEST = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "page_eval on https://example.com",
  allowed_credential_ids: ["Y3JlZC1h"],
};

const ANSWER = {
  nonce: "nonce-0002",
  credential_id: "Y3JlZC1h",
  authenticator_data: "YXV0aA",
  client_data_json: "Y2Rq",
  signature: "c2ln",
};

interface FakeWindow extends Presentation {
  payload: ConfirmPayload;
  close: () => void;
  dismissed: boolean;
}

let posted: Array<Record<string, unknown>>;
let windows: FakeWindow[];

function fakeSurface(): ConfirmationProvider {
  return {
    present(payload) {
      let close!: () => void;
      const verdict = new Promise<boolean>((resolve) => {
        close = () => resolve(false);
      });
      const w: FakeWindow = {
        payload,
        verdict,
        close,
        dismissed: false,
        dismiss() {
          w.dismissed = true;
        },
      };
      windows.push(w);
      return w;
    },
  };
}

beforeEach(() => {
  fakeBrowser.reset();
  resetWebAuthnForTests();
  posted = [];
  windows = [];
  attach(collaborator, (frame) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  });
});

afterEach(() => {
  resetWebAuthnForTests();
  vi.restoreAllMocks();
});

async function settled(): Promise<void> {
  await new Promise((r) => setTimeout(r, 0));
}

describe("PresenceExchangeProvider", () => {
  test("asks the host for the op and origin first, opens the window on the request, and approves on the host's verdict for the tap", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const shown = provider.present(PAYLOAD);
    expect(posted).toEqual([
      { type: "presence_begin", action: "page_eval", origin: "https://example.com" },
    ]);
    expect(windows).toHaveLength(0);
    handleWebAuthnFrame(REQUEST as never);
    await settled();
    expect(windows).toHaveLength(1);
    await expect(shown.shown).resolves.toBe(true);
    expect(windows[0]?.payload).toBe(PAYLOAD);
    expect(pendingPresenceRequest()).toEqual(REQUEST);
    const answered = assertPresence(ANSWER);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
    await expect(shown.verdict).resolves.toBe(true);
  });

  test("an upload confirmation asks for page_upload, and a bare browser's software confirmation approves through the host", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const shown = provider.present({ ...PAYLOAD, kind: "upload", detail: "/tmp/f\n(input: #x)" });
    expect(posted[0]).toEqual({
      type: "presence_begin",
      action: "page_upload",
      origin: "https://example.com",
    });
    handleWebAuthnFrame({
      ...REQUEST,
      action: "page_upload on https://example.com",
      allowed_credential_ids: [],
    } as never);
    await settled();
    const answered = confirmPresence(REQUEST.nonce);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
    await expect(shown.verdict).resolves.toBe(true);
  });

  test("the host's refusal of the answer denies", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const shown = provider.present(PAYLOAD);
    handleWebAuthnFrame(REQUEST as never);
    await settled();
    const answered = assertPresence(ANSWER);
    handleWebAuthnFrame({ type: "presence_result", ok: false, reason: "challenge_mismatch" });
    await expect(answered).resolves.toEqual({ ok: false, error: "challenge_mismatch" });
    await expect(shown.verdict).resolves.toBe(false);
  });

  test("a presence_begin the host refuses denies with no window, and reports no surface shown", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const shown = provider.present(PAYLOAD);
    handleWebAuthnFrame({ type: "presence_result", ok: false, reason: "invalid_origin" });
    await expect(shown.verdict).resolves.toBe(false);
    await expect(shown.shown).resolves.toBe(false);
    expect(windows).toHaveLength(0);
  });

  test("a busy exchange and a missing host each deny with no window", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const busy = provider.present(PAYLOAD); // takes the slot
    const second = provider.present(PAYLOAD);
    await expect(second.verdict).resolves.toBe(false);
    collaborator.onDetach();
    await expect(busy.verdict).resolves.toBe(false);
    const gone = provider.present(PAYLOAD);
    await expect(gone.verdict).resolves.toBe(false);
    expect(windows).toHaveLength(0);
  });

  test("the window closed without answering denies, and the request is forgotten", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const shown = provider.present(PAYLOAD);
    handleWebAuthnFrame(REQUEST as never);
    await settled();
    windows[0]?.close();
    await expect(shown.verdict).resolves.toBe(false);
    shown.dismiss();
    expect(windows[0]?.dismissed).toBe(true);
    expect(pendingPresenceRequest()).toBeNull();
  });

  test("a dismiss before the host answers withdraws the begin: the exchange is free at once, and the late reply opens no window", async () => {
    const provider = new PresenceExchangeProvider(fakeSurface());
    const first = provider.present(PAYLOAD);
    first.dismiss();
    await expect(first.verdict).resolves.toBe(false);
    await expect(first.shown).resolves.toBe(false);
    // The next confirmation is not refused as busy; the host answers in order, so the first frame is the
    // withdrawn begin's reply (dropped) and the second is this one's request.
    const second = provider.present(PAYLOAD);
    expect(posted).toHaveLength(2);
    handleWebAuthnFrame(REQUEST as never);
    await settled();
    expect(windows).toHaveLength(0);
    expect(pendingPresenceRequest()).toBeNull();
    handleWebAuthnFrame({ ...REQUEST, nonce: "nonce-0003" } as never);
    await settled();
    expect(windows).toHaveLength(1);
    expect(pendingPresenceRequest()).toMatchObject({ nonce: "nonce-0003" });
    second.dismiss();
  });
});
