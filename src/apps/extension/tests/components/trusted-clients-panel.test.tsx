// The trusted-clients panel's pairing form over the SW contract and a stood-in WebAuthn client: the form posts
// exactly the host's frame, the host's request is signed here, and a value the host's grammar refuses is refused
// before anything is posted. The panel never claims a pairing itself: the host's verdict and the re-read list do.

import type { PresenceRequestFrame } from "@chromium-bridge/shared/generated/envelope";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { assertedCredential, type FakeWebAuthn, installFakeWebAuthn } from "./fake-webauthn";

const REQUEST: PresenceRequestFrame = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "pair trusted client 'codex' on signer TEAMID",
  allowed_credential_ids: ["Y3JlZC1h"],
};

type Reply = Record<string, unknown>;

let sent: Reply[];
let replies: Record<string, () => Reply>;
let webauthn: FakeWebAuthn;

// Synthetic messages: the test pins which sentence a key selects, not the English wording.
const EN = Object.fromEntries(
  Object.entries({
    clients_desc: "desc",
    clients_refresh: "Refresh",
    clients_revoke: "Revoke",
    clients_unenrolled: "unenrolled",
    clients_empty: "empty",
    clients_anchor_hash: "hash",
    clients_anchor_signer: "Signer",
    clients_pair_title: "Trust a client",
    clients_pair_desc: "pair desc",
    clients_pair_name: "Name",
    clients_pair_kind_hash: "Hash of the client binary",
    clients_pair_kind_signer: "Code signer",
    clients_pair_value: "Anchor value",
    clients_pair: "Trust",
    clients_pair_confirm: "Confirm pairing",
    clients_pair_failed: "Pairing refused: $1",
    clients_pair_invalid_name: "<name grammar sentence>",
    clients_pair_invalid_hash: "<hash grammar sentence>",
    clients_pair_invalid_signer: "<signer grammar sentence>",
    presence_asking: "asking",
    presence_tapping: "tapping",
    presence_confirming: "confirming",
    presence_window_title: "no authenticator enrolled here",
    presence_window_desc: "software confirmation",
    webauthn_reason_sign_count_not_increased: "<replay sentence>",
    common_cancel: "Cancel",
  }).map(([key, message]) => [key, { message }]),
);

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = "test-ext-id";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  sent = [];
  replies = {
    get_clients: () => ({ ok: true, enrolled: false, clients: [] }),
    pair_client: () => ({ ok: true, request: REQUEST }),
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
  webauthn.getResponse = () => assertedCredential("Y3JlZC1h");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { TrustedClientsPanel } = await import("@/entrypoints/options/TrustedClientsPanel");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  const view = render(<TrustedClientsPanel />);
  await screen.findByText("Trust a client");
  return view;
}

async function fill(name: string, kind: "hash" | "signer", value: string) {
  await userEvent.type(screen.getByLabelText("Name"), name);
  await userEvent.click(
    screen.getByLabelText(kind === "hash" ? "Hash of the client binary" : "Code signer"),
  );
  await userEvent.type(screen.getByLabelText("Anchor value"), value);
  await userEvent.click(screen.getByRole("button", { name: "Trust" }));
}

const ASSERT = {
  type: "webauthn_presence_assert",
  nonce: REQUEST.nonce,
  credential_id: "Y3JlZC1h",
  authenticator_data: "YXV0aC1kYXRh",
  client_data_json: "Y2xpZW50LWRhdGEtZ2V0",
  signature: "c2lnbmF0dXJl",
};

describe("TrustedClientsPanel pairing", () => {
  test("Trust posts the name and anchor, signs the host's request, and re-reads the list once the host paired it", async () => {
    await mount();
    await fill("codex", "signer", "TEAMID");
    await waitFor(() =>
      expect(sent).toEqual([
        { type: "get_clients" },
        { type: "pair_client", name: "codex", anchor: { kind: "signer", value: "TEAMID" } },
        ASSERT,
        { type: "get_clients" },
      ]),
    );
    // The form is cleared for the next client only once the host reported the pairing.
    expect(screen.getByLabelText("Name")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Trust" })).toBeDisabled();
  });

  test.each([
    {
      name: "a hash outside the digest grammar",
      kind: "hash" as const,
      value: "zz",
      sentence: "<hash grammar sentence>",
    },
    {
      name: "an uppercase hash",
      kind: "hash" as const,
      value: "AB".repeat(20),
      sentence: "<hash grammar sentence>",
    },
  ])("$name is refused before anything is posted", async ({ kind, value, sentence }) => {
    await mount();
    await fill("codex", kind, value);
    await screen.findByText(sentence);
    expect(sent.map((m) => m.type)).toEqual(["get_clients"]);
  });

  test("a name outside the label grammar is refused before anything is posted", async () => {
    await mount();
    await fill("bad name!", "signer", "TEAMID");
    await screen.findByText("<name grammar sentence>");
    expect(sent.map((m) => m.type)).toEqual(["get_clients"]);
  });

  test("a pairing the host refuses before any request shows the host's words, and a refused tap its sentence", async () => {
    replies.pair_client = () => ({
      ok: false,
      error: "user presence not attested: enrollment store: permission denied",
    });
    await mount();
    await fill("codex", "signer", "TEAMID");
    await screen.findByText(
      "Pairing refused: user presence not attested: enrollment store: permission denied",
    );
    expect(sent.map((m) => m.type)).toEqual(["get_clients", "pair_client"]);

    replies.pair_client = () => ({ ok: true, request: REQUEST });
    replies.webauthn_presence_assert = () => ({ ok: false, error: "sign_count_not_increased" });
    await userEvent.click(screen.getByRole("button", { name: "Trust" }));
    await screen.findByText("Pairing refused: <replay sentence>");
    expect(sent.filter((m) => m.type === "get_clients")).toHaveLength(1);
  });
});
