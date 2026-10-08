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
let replies: Record<string, () => Reply | Promise<Reply>>;
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
    clients_pair_invalid_signer_empty: "<signer empty sentence>",
    clients_pair_invalid_signer_nul: "<signer NUL sentence>",
    clients_pair_invalid_signer_ill_formed: "<signer surrogate sentence>",
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
  if (value !== "") await userEvent.type(screen.getByLabelText("Anchor value"), value);
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

  test("a signer anchor is posted exactly as entered, padding included", async () => {
    // The CLI's SignerId keeps `" Publisher "` as typed, so a form that trimmed it would store an anchor the
    // client attested as the original signer never matches.
    await mount();
    await fill("codex", "signer", " Publisher ");
    await waitFor(() =>
      expect(sent[1]).toEqual({
        type: "pair_client",
        name: "codex",
        anchor: { kind: "signer", value: " Publisher " },
      }),
    );
  });

  test("while the pairing awaits the host and the tap, the form is disabled and keeps the submitted values", async () => {
    // Only the Trust button honoured the pending state, so the name, kind, and value could be edited while
    // the host paired the values first submitted.
    let answer!: (reply: Reply) => void;
    replies.pair_client = () =>
      new Promise<Reply>((resolve) => {
        answer = resolve;
      });
    await mount();
    await fill("codex", "signer", "TEAMID");
    await screen.findByText("asking");
    const inputs = ["Name", "Anchor value", "Hash of the client binary", "Code signer"];
    for (const label of inputs) expect(screen.getByLabelText(label)).toBeDisabled();
    expect(screen.getByLabelText("Name")).toHaveValue("codex");
    expect(screen.getByLabelText("Anchor value")).toHaveValue("TEAMID");
    answer({ ok: true, request: REQUEST });
    await waitFor(() => expect(sent.at(-1)).toEqual({ type: "get_clients" }));
    for (const label of inputs) expect(screen.getByLabelText(label)).toBeEnabled();
    expect(screen.getByLabelText("Name")).toHaveValue("");
  });

  test.each([
    {
      name: "a hash outside the digest grammar",
      kind: "hash" as const,
      value: "zz",
      sentence: "<hash grammar sentence>",
    },
    // Each signer fault gets its own sentence (the CLI's for NUL, the page's for the surrogate), not one shared
    // refusal; the empty anchor never reaches a sentence, since Trust stays disabled on it (below).
    {
      name: "a NUL inside a signer anchor",
      kind: "signer" as const,
      value: "A\u0000B",
      sentence: "<signer NUL sentence>",
    },
    {
      name: "an unpaired surrogate as a signer anchor",
      kind: "signer" as const,
      value: "\uD800",
      sentence: "<signer surrogate sentence>",
    },
  ])("$name is refused before anything is posted", async ({ kind, value, sentence }) => {
    await mount();
    await fill("codex", kind, value);
    await screen.findByText(sentence);
    expect(sent.map((m) => m.type)).toEqual(["get_clients"]);
  });

  test("an empty anchor cannot be posted: Trust stays disabled, while a lone space is a signer the CLI accepts", async () => {
    await mount();
    await fill("codex", "signer", "");
    expect(screen.getByRole("button", { name: "Trust" })).toBeDisabled();
    expect(sent.map((m) => m.type)).toEqual(["get_clients"]);
    await userEvent.type(screen.getByLabelText("Anchor value"), " ");
    await userEvent.click(screen.getByRole("button", { name: "Trust" }));
    await waitFor(() =>
      expect(sent[1]).toEqual({
        type: "pair_client",
        name: "codex",
        anchor: { kind: "signer", value: " " },
      }),
    );
  });

  test("an uppercase hash posts in the canonical lowercase, as `pair-client --hash` stores it", async () => {
    await mount();
    await fill("codex", "hash", "AB".repeat(20));
    await waitFor(() =>
      expect(sent[1]).toEqual({
        type: "pair_client",
        name: "codex",
        anchor: { kind: "hash", value: "ab".repeat(20) },
      }),
    );
  });

  test.each([
    { name: "a name outside the label grammar", value: "bad name!" },
    // The CLI refuses a padded name; a page that trimmed it would trust "codex" for " codex ".
    { name: "a padded name", value: " codex " },
  ])("$name is refused before anything is posted", async ({ value }) => {
    await mount();
    await fill(value, "signer", "TEAMID");
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
