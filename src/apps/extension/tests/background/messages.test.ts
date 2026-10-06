// Sender gating, derived from the contract: the router refuses EVERY declared
// message from a non-extension-page sender, and every confirm-window message
// from any other extension page. A content script sends the router nothing,
// so a content-script sender for any of these is a compromised renderer
// reaching for trust state (allowlist, pin, enrollment status). Without this
// gate a content script on an approved origin could add_allow{evil.com}.

import {
  RUNTIME_CONTRACT,
  type RuntimeMsg,
  type RuntimeMsgType,
  type RuntimeRequest,
  runtimeResponseSchema,
} from "@chromium-bridge/shared/runtime-msg";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { resetKillForTests } from "@/lib/background/kill";
import { route } from "@/lib/background/messages";

const EXT_ID = "test-ext-id";

// A content-script sender: our extension id (content scripts share it), but an
// http(s) page URL - the discriminator the gate keys on.
const contentScriptSender = {
  id: EXT_ID,
  url: "https://evil.example/attack",
} as Browser.runtime.MessageSender;
const optionsSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/options.html`,
} as Browser.runtime.MessageSender;
const confirmSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/confirm.html?id=x`,
} as Browser.runtime.MessageSender;

const REFUSED_PAGE = { ok: false, error: "this action is only accepted from extension pages" };
const REFUSED_CONFIRM = { ok: false, error: "confirmations are confirm-window-only" };

// One well-formed request per contract entry. The mapped type makes a message
// type without a sample a compile error, and the roster below is read from
// the samples, so a new message cannot escape the gate tests (the extension
// typecheck covers this file, so the mapped type is enforced in CI).
const REQUESTS: { [K in RuntimeMsgType]: RuntimeRequest<K> } = {
  resolve_allow: { type: "resolve_allow", id: "allow_1", allow: true },
  get_allowlist: { type: "get_allowlist" },
  add_allow: { type: "add_allow", glob: "https://evil.example/*" },
  remove_allow: { type: "remove_allow", glob: "https://good.example/*" },
  get_status: { type: "get_status" },
  get_enrollment: { type: "get_enrollment" },
  get_clients: { type: "get_clients" },
  revoke_client: { type: "revoke_client", name: "claude-code" },
  get_kill: { type: "get_kill" },
  set_kill: { type: "set_kill", on: true },
  kill_release: { type: "kill_release" },
  get_audit: { type: "get_audit" },
  get_host_audit: { type: "get_host_audit" },
  sweep_pending: { type: "sweep_pending" },
  lang_choose: { type: "lang_choose", value: "en" },
  enroll_pair: { type: "enroll_pair" },
  enroll_verify: { type: "enroll_verify" },
  enroll_approve: { type: "enroll_approve" },
  enroll_reject: { type: "enroll_reject" },
  enroll_revoke: { type: "enroll_revoke" },
  webauthn_enroll_begin: { type: "webauthn_enroll_begin" },
  webauthn_enroll_finish: {
    type: "webauthn_enroll_finish",
    attestation_object: "YXR0",
    client_data_json: "Y2Rq",
  },
  webauthn_presence_pending: { type: "webauthn_presence_pending" },
  webauthn_enrollment: { type: "webauthn_enrollment" },
  webauthn_presence_assert: {
    type: "webauthn_presence_assert",
    nonce: "nonce-0002",
    credential_id: "Y3JlZC1h",
    authenticator_data: "YXV0aA",
    client_data_json: "Y2Rq",
    signature: "c2ln",
  },
  webauthn_presence_confirm: { type: "webauthn_presence_confirm", nonce: "nonce-0002" },
  webauthn_forget: { type: "webauthn_forget" },
  get_doctor: { type: "get_doctor" },
  get_registration: { type: "get_registration" },
  repair_registration: { type: "repair_registration" },
  get_policy: { type: "get_policy" },
  restrict_policy: { type: "restrict_policy", overlay: { pageEvalEnabled: false } },
  confirm_ready: { type: "confirm_ready", id: "x" },
  confirm_resolve: { type: "confirm_resolve", id: "x", approved: true },
  confirm_deny_kill: { type: "confirm_deny_kill" },
};

const EVERY_REQUEST: RuntimeMsg[] = Object.values(REQUESTS);
const CONFIRM_ONLY = EVERY_REQUEST.filter(
  (msg) => RUNTIME_CONTRACT[msg.type].gate === "confirm-window",
);

/** The response the router eventually delivers for one message. */
function answer(msg: RuntimeMsg, sender: Browser.runtime.MessageSender): Promise<unknown> {
  return new Promise((resolve) => {
    route(msg, sender, resolve);
  });
}

beforeEach(() => {
  fakeBrowser.reset();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
});

afterEach(() => {
  // confirm_deny_kill latches confirmations to auto-deny and arms the kill
  // exchange; neither may leak into the next case.
  resetKillForTests();
});

describe("router sender gating", () => {
  test.each(EVERY_REQUEST)("refuses $type from a content-script sender", async (msg) => {
    await expect(answer(msg, contentScriptSender)).resolves.toEqual(REFUSED_PAGE);
  });

  test.each(CONFIRM_ONLY)(
    "refuses $type from an extension page that is not the confirm window",
    async (msg) => {
      await expect(answer(msg, optionsSender)).resolves.toEqual(REFUSED_CONFIRM);
    },
  );

  // TypeScript lets a handler return fields the response schema never
  // declared (spreads and non-literal returns escape excess property checks),
  // and the pages' parse strips them, so a delivered-but-undeclared field
  // would drift with no failure anywhere. The confirm window passes both
  // gates, so it exercises every handler with no host attached.
  test.each(EVERY_REQUEST)(
    "$type answered to the confirm window is exactly its declared response",
    async (msg) => {
      const resp = await answer(msg, confirmSender);
      expect(runtimeResponseSchema(msg.type).parse(resp)).toEqual(resp);
    },
  );

  test("a content script CANNOT seed the allowlist via add_allow", async () => {
    await answer(REQUESTS.add_allow, contentScriptSender);
    const { allowlist } = await fakeBrowser.storage.local.get("allowlist");
    expect(allowlist ?? []).toEqual([]);
  });

  test("an extension page can read and add to the allowlist (the legit path is unbroken)", async () => {
    await fakeBrowser.storage.local.set({ allowlist: ["https://good.example/*"] });
    await expect(answer(REQUESTS.get_allowlist, optionsSender)).resolves.toEqual({
      ok: true,
      list: ["https://good.example/*"],
    });
    await expect(
      answer({ type: "add_allow", glob: "https://ok.example/deep/path" }, optionsSender),
    ).resolves.toEqual({ ok: true, list: ["https://good.example/*", "https://ok.example/*"] });
  });

  test("lang_choose with no live host stays a local choice: ok with sent:false", async () => {
    // No port is attached in this suite, so the relay reports sent:false and
    // the picker's own local write is the whole effect (the offline posture).
    await expect(answer({ type: "lang_choose", value: "zh_CN" }, optionsSender)).resolves.toEqual({
      ok: true,
      sent: false,
    });
  });

  test("the confirm window is accepted for confirm_ready: no pending payload is null, not a refusal", async () => {
    await expect(answer(REQUESTS.confirm_ready, confirmSender)).resolves.toEqual({
      ok: true,
      payload: null,
    });
  });

  test("sweep_pending re-derives the mirror through the SW (ghost record swept)", async () => {
    // The popup found an unparsable pendingAllow record and asked the SW to
    // sweep it; the popup itself never writes storage, since a popup-side
    // remove could race a freshly minted live request and strand its resolver.
    await fakeBrowser.storage.local.set({ pendingAllow: { id: "old-shape", glob: "x" } });
    await expect(answer(REQUESTS.sweep_pending, optionsSender)).resolves.toEqual({ ok: true });
    const { pendingAllow } = await fakeBrowser.storage.local.get("pendingAllow");
    expect(pendingAllow).toBeUndefined();
  });
});
