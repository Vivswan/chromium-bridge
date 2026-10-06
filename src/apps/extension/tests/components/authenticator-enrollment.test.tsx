// The authenticator block of the identity panel over the SW contract and a stood-in WebAuthn client. The
// approval step continues on its own because the host holds the approval 60 s for exactly the next enroll_begin.
// What the worker's note looks like once a real enrollment wrote it is tests/browser/presence_exchange_test.ts's.

import type {
  EnrollOptionsFrame,
  PresenceRequestFrame,
} from "@chromium-bridge/shared/envelope.gen";
import { PRESENCE_REQUIRED } from "@chromium-bridge/shared/webauthn";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { creationOptions, requestOptions } from "@/lib/shared/webauthn-ceremony";
import {
  assertedCredential,
  createdCredential,
  type FakeWebAuthn,
  installFakeWebAuthn,
} from "./fake-webauthn";

const EXT_ID = "test-ext-id";

const OPTIONS: EnrollOptionsFrame = {
  type: "enroll_options",
  challenge: "Y2hhbGxlbmdl",
  nonce: "nonce-0001",
  user_id: "YnJhdmU",
  user_name: "brave",
  exclude_credential_ids: [],
};

const REQUEST: PresenceRequestFrame = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "enroll a credential for browser 'brave'",
  allowed_credential_ids: ["Y3JlZC1vdGhlcg"],
};

type Reply = Record<string, unknown>;

let sent: Reply[];
let replies: Record<string, () => Reply>;
let webauthn: FakeWebAuthn;

// Synthetic messages: the test pins which sentence a code selects, not the English wording.
const EN = Object.fromEntries(
  Object.entries({
    webauthn_desc: "desc",
    webauthn_loading: "loading",
    webauthn_no_status: "no status: $1",
    webauthn_state_none: "no authenticator enrolled",
    webauthn_state_enrolled: "enrolled at $1",
    webauthn_btn_enroll: "Enroll this browser",
    webauthn_btn_enroll_another: "Enroll another authenticator",
    webauthn_btn_approve: "Approve",
    webauthn_step_asking: "asking",
    webauthn_step_creating: "creating",
    webauthn_step_approving: "approving",
    webauthn_approval_title: "approval needed",
    webauthn_approval_desc: "approve with an enrolled authenticator",
    webauthn_approval_action: "the host asks: $1",
    webauthn_enrolled_now: "enrolled now",
    webauthn_failed: "Enrollment refused: $1",
    webauthn_reason_sign_count_not_increased: "<replay sentence>",
    webauthn_reason_challenge_mismatch: "<challenge sentence>",
    webauthn_reason_prompt_dismissed: "<dismissed sentence>",
    webauthn_reason_credential_exists: "<exists sentence>",
    webauthn_reason_presence_required: "<presence sentence>",
    webauthn_reason_store_error: "<store sentence>",
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
    webauthn_enrollment: () => ({ ok: true, enrollment: null }),
    webauthn_enroll_begin: () => ({ ok: true, options: OPTIONS }),
    webauthn_enroll_finish: () => ({ ok: true, credentialId: "Y3JlZC1h" }),
    webauthn_presence_pending: () => ({ ok: true, request: REQUEST }),
    webauthn_presence_assert: () => ({ ok: true }),
  };
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as Reply & { type: string };
    sent.push(m);
    const reply = replies[m.type];
    if (!reply) throw new Error(`no reply for ${m.type}`);
    return reply();
  });
  webauthn = installFakeWebAuthn();
  webauthn.createResponse = () => createdCredential("Y3JlZC1h");
  webauthn.getResponse = () => assertedCredential("Y3JlZC1vdGhlcg");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { AuthenticatorEnrollment } = await import("@/entrypoints/options/AuthenticatorEnrollment");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  const view = render(<AuthenticatorEnrollment />);
  await screen.findByText("no authenticator enrolled");
  return view;
}

const FINISH = {
  type: "webauthn_enroll_finish",
  attestation_object: "YXR0ZXN0YXRpb24",
  client_data_json: "Y2xpZW50LWRhdGEtY3JlYXRl",
};

const ASSERT = {
  type: "webauthn_presence_assert",
  nonce: REQUEST.nonce,
  credential_id: "Y3JlZC1vdGhlcg",
  authenticator_data: "YXV0aC1kYXRh",
  client_data_json: "Y2xpZW50LWRhdGEtZ2V0",
  signature: "c2lnbmF0dXJl",
};

describe("AuthenticatorEnrollment", () => {
  test("fresh machine: Enroll asks the host, creates with its options, finishes, and reports enrolled", async () => {
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Enroll this browser" }));
    await screen.findByText("enrolled now");
    expect(sent).toEqual([
      { type: "webauthn_enrollment" },
      { type: "webauthn_enroll_begin" },
      FINISH,
    ]);
    expect(webauthn.calls).toEqual({ create: [creationOptions(OPTIONS, EXT_ID)], get: [] });
  });

  test("enrolled machine: the pushed request is an approval step, and its tap continues the enrollment on its own", async () => {
    let begins = 0;
    replies.webauthn_enroll_begin = () =>
      ++begins === 1 ? { ok: false, error: PRESENCE_REQUIRED } : { ok: true, options: OPTIONS };
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Enroll this browser" }));
    await screen.findByText("approval needed");
    expect(screen.getByText(`the host asks: ${REQUEST.action}`)).toBeInTheDocument();
    // Nothing was signed yet: the approval waits for the user, and Enroll is out of the way meanwhile.
    expect(webauthn.calls.get).toEqual([]);
    expect(screen.queryByRole("button", { name: "Enroll this browser" })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await screen.findByText("enrolled now");
    expect(sent).toEqual([
      { type: "webauthn_enrollment" },
      { type: "webauthn_enroll_begin" },
      { type: "webauthn_presence_pending" },
      ASSERT,
      { type: "webauthn_enroll_begin" },
      FINISH,
    ]);
    expect(webauthn.calls).toEqual({
      create: [creationOptions(OPTIONS, EXT_ID)],
      get: [requestOptions(REQUEST, EXT_ID)],
    });
  });

  test("Cancel on the approval step returns to Enroll without answering the request", async () => {
    replies.webauthn_enroll_begin = () => ({ ok: false, error: PRESENCE_REQUIRED });
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Enroll this browser" }));
    await screen.findByText("approval needed");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText("approval needed")).toBeNull();
    expect(screen.getByRole("button", { name: "Enroll this browser" })).toBeEnabled();
    expect(sent.map((m) => m.type)).toEqual([
      "webauthn_enrollment",
      "webauthn_enroll_begin",
      "webauthn_presence_pending",
    ]);
  });

  // The host's codes (presence/mod.rs, webauthn/refusal.rs) and the browser's DOMException names each select
  // one sentence; a code with a detail keeps the detail.
  test.each([
    {
      name: "a replayed approval assertion",
      arrange: () => {
        replies.webauthn_enroll_begin = () => ({ ok: false, error: PRESENCE_REQUIRED });
        replies.webauthn_presence_assert = () => ({ ok: false, error: "sign_count_not_increased" });
      },
      approve: true,
      sentence: "<replay sentence>",
    },
    {
      name: "a registration over the wrong challenge",
      arrange: () => {
        replies.webauthn_enroll_finish = () => ({ ok: false, error: "challenge_mismatch" });
      },
      approve: false,
      sentence: "<challenge sentence>",
    },
    {
      name: "the user dismissing the authenticator prompt",
      arrange: () => {
        webauthn.createResponse = () => {
          throw new DOMException("The operation was cancelled", "NotAllowedError");
        };
      },
      approve: false,
      sentence: "<dismissed sentence>",
    },
    {
      name: "an authenticator that already holds an excluded credential",
      arrange: () => {
        webauthn.createResponse = () => {
          throw new DOMException("already registered", "InvalidStateError");
        };
      },
      approve: false,
      sentence: "<exists sentence>",
    },
    {
      name: "a pushed request the worker no longer holds",
      arrange: () => {
        replies.webauthn_enroll_begin = () => ({ ok: false, error: PRESENCE_REQUIRED });
        replies.webauthn_presence_pending = () => ({ ok: true, request: null });
      },
      approve: false,
      sentence: "<presence sentence>",
    },
    {
      name: "a host store error, its detail appended",
      arrange: () => {
        replies.webauthn_enroll_begin = () => ({ ok: false, error: "store_error: disk full" });
      },
      approve: false,
      sentence: "<store sentence> (disk full)",
    },
  ])("$name renders its sentence", async ({ arrange, approve, sentence }) => {
    arrange();
    await mount();
    await userEvent.click(screen.getByRole("button", { name: "Enroll this browser" }));
    if (approve) {
      await screen.findByText("approval needed");
      await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    }
    await screen.findByText(`Enrollment refused: ${sentence}`);
    expect(screen.queryByText("enrolled now")).toBeNull();
    expect(screen.getByRole("button", { name: "Enroll this browser" })).toBeEnabled();
  });
});
