// The worker half of the WebAuthn ceremonies over a fake Connection: request/reply correlation, the
// fail-closed timeout and detach, the unsolicited-frame drops, and the pushed presence request's lifecycle.
// The host side is the Rust verifier's own tests; the tag roster itself is held to the generated table by
// tests/background/port-routing.test.ts and scripts/check-envelope.ts.

import { WEBAUTHN_ENROLLMENT_KEY } from "@chromium-bridge/shared/runtime-msg";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { HOST_REPLY_TIMEOUT_MS } from "@/lib/background/exchange";
import {
  abandonPresence,
  assertPresence,
  beginEnrollment,
  beginKillRelease,
  beginPresence,
  claimKillRelease,
  collaborator,
  confirmPresence,
  finishEnrollment,
  forgetBrowser,
  handleWebAuthnFrame,
  pendingPresenceRequest,
  recordedEnrollment,
  resetWebAuthnForTests,
} from "@/lib/webauthn/exchange";
import { attach } from "../background/fake-connection";

let posted: Array<Record<string, unknown>>;

const enrollOptions = {
  type: "enroll_options",
  challenge: "Y2hhbGxlbmdl",
  nonce: "nonce-0001",
  user_id: "dXNlci1pZA",
  user_name: "brave",
  exclude_credential_ids: [],
};

const presenceRequest = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "pair_client:codex",
  allowed_credential_ids: ["Y3JlZC1h"],
};

const registration = { attestation_object: "YXR0", client_data_json: "Y2Rq" };
const assertion = {
  credential_id: "Y3JlZC1h",
  authenticator_data: "YXV0aA",
  client_data_json: "Y2Rq",
  signature: "c2ln",
};
const answer = { nonce: "nonce-0002", ...assertion };

beforeEach(() => {
  fakeBrowser.reset();
  resetWebAuthnForTests();
  posted = [];
  attach(collaborator, (frame) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  });
});

afterEach(() => {
  resetWebAuthnForTests();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("enrollment exchanges", () => {
  test("enroll_begin round-trips the host's creation options", async () => {
    const p = beginEnrollment();
    expect(posted).toEqual([{ type: "enroll_begin" }]);
    handleWebAuthnFrame(enrollOptions as never);
    await expect(p).resolves.toEqual({ ok: true, options: enrollOptions });
  });

  test("enroll_begin refused by the host resolves with the host's reason", async () => {
    const p = beginEnrollment();
    handleWebAuthnFrame({ type: "enroll_result", ok: false, reason: "enrollment_unavailable" });
    await expect(p).resolves.toEqual({ ok: false, error: "enrollment_unavailable" });
  });

  test("enroll_finish posts the registration and resolves with the credential id", async () => {
    const p = finishEnrollment(registration);
    expect(posted).toEqual([{ type: "enroll_finish", ...registration }]);
    handleWebAuthnFrame({ type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" });
    await expect(p).resolves.toEqual({ ok: true, credentialId: "Y3JlZC1h" });
  });

  test.each([
    ["ok without a credential id", { type: "enroll_result", ok: true }],
    ["ok with an empty credential id", { type: "enroll_result", ok: true, credential_id: "" }],
    [
      "ok carrying a reason",
      { type: "enroll_result", ok: true, credential_id: "Y3JlZC1h", reason: "attestation_format" },
    ],
    ["a refusal without a reason", { type: "enroll_result", ok: false }],
  ])(
    "an enroll_result the host's producer cannot emit (%s) is malformed, never a success",
    async (_name, frame) => {
      // EnrollOutcome::into_frame emits exactly two shapes; a frame outside them is not the host's and must
      // not resolve the ceremony either way.
      const p = finishEnrollment(registration);
      handleWebAuthnFrame(frame as never);
      await expect(p).resolves.toEqual({ ok: false, error: "malformed enroll_result from host" });
    },
  );
});

describe("the enrollment note for the options page", () => {
  test("an ok enroll_result notes the credential; the note reads back; a refusal leaves none", async () => {
    vi.useFakeTimers({ now: 1_700_000_000_000 });
    const p = finishEnrollment(registration);
    handleWebAuthnFrame({ type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" });
    await expect(p).resolves.toEqual({ ok: true, credentialId: "Y3JlZC1h" });
    await expect(recordedEnrollment()).resolves.toEqual({
      ok: true,
      enrollment: { credentialId: "Y3JlZC1h", enrolledAt: 1_700_000_000_000 },
    });
    await fakeBrowser.storage.local.remove(WEBAUTHN_ENROLLMENT_KEY);
    const refused = finishEnrollment(registration);
    handleWebAuthnFrame({ type: "enroll_result", ok: false, reason: "challenge_mismatch" });
    await expect(refused).resolves.toEqual({ ok: false, error: "challenge_mismatch" });
    await expect(recordedEnrollment()).resolves.toEqual({ ok: true, enrollment: null });
  });

  test("a present note that does not parse is a refusal, never 'not enrolled'", async () => {
    await fakeBrowser.storage.local.set({ [WEBAUTHN_ENROLLMENT_KEY]: { credentialId: "" } });
    await expect(recordedEnrollment()).resolves.toEqual({
      ok: false,
      error: "the stored enrollment note is malformed",
    });
  });
});

describe("forgetting this browser", () => {
  const note = { credentialId: "Y3JlZC1h", enrolledAt: 1 };

  test("browser_revoke posts the frame; the host's ok clears the note and the pending request", async () => {
    await fakeBrowser.storage.local.set({ [WEBAUTHN_ENROLLMENT_KEY]: note });
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const p = forgetBrowser();
    expect(posted).toEqual([{ type: "browser_revoke" }]);
    handleWebAuthnFrame({ type: "browser_revoke_result", ok: true });
    await expect(p).resolves.toEqual({ ok: true });
    await expect(recordedEnrollment()).resolves.toEqual({ ok: true, enrollment: null });
    expect(pendingPresenceRequest()).toBeNull();
  });

  test("not_enrolled clears a note the CLI left stale but keeps the pending request; any other refusal keeps the note", async () => {
    await fakeBrowser.storage.local.set({ [WEBAUTHN_ENROLLMENT_KEY]: note });
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const stale = forgetBrowser();
    handleWebAuthnFrame({ type: "browser_revoke_result", ok: false, reason: "not_enrolled" });
    await expect(stale).resolves.toEqual({ ok: false, error: "not_enrolled" });
    await expect(recordedEnrollment()).resolves.toEqual({ ok: true, enrollment: null });
    expect(pendingPresenceRequest()).toEqual(presenceRequest);
    await fakeBrowser.storage.local.set({ [WEBAUTHN_ENROLLMENT_KEY]: note });
    const refused = forgetBrowser();
    handleWebAuthnFrame({
      type: "browser_revoke_result",
      ok: false,
      reason: "store_error: disk full",
    });
    await expect(refused).resolves.toEqual({ ok: false, error: "store_error: disk full" });
    await expect(recordedEnrollment()).resolves.toEqual({ ok: true, enrollment: note });
  });
});

describe("kill release", () => {
  test("kill_release posts the frame; the pushed presence_request answers it, stays pending for the page, and opens no page", async () => {
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const release = { ...presenceRequest, action: "release the kill switch" };
    const p = beginKillRelease();
    expect(posted).toEqual([{ type: "kill_release" }]);
    handleWebAuthnFrame(release as never);
    await expect(p).resolves.toEqual({ ok: true, request: release });
    expect(pendingPresenceRequest()).toEqual(release);
    expect(open).not.toHaveBeenCalled();
    // The page's answer rides the presence path, but its verdict is the release outcome kill.ts hands over.
    const answered = assertPresence(answer);
    expect(posted).toEqual([{ type: "kill_release" }, { type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    claimKillRelease({ ok: true })?.({ ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
  });

  // The host writes the record, then emits presence_result ok followed by kill_status_result: ok:false with
  // the error when the write failed, so the presence verdict alone would call a still-engaged switch released.
  test("a release answer waits for the kill_status_result after presence_result ok, and a failed write is its refusal", async () => {
    vi.useFakeTimers();
    const p = beginKillRelease();
    handleWebAuthnFrame({ ...presenceRequest, action: "release the kill switch" } as never);
    await p;
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    let settled = false;
    void answered.then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    claimKillRelease({ ok: false })?.({ ok: false, error: "trust record: permission denied" });
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "trust record: permission denied",
    });
  });

  test("a release outcome that never arrives times out to a refusal", async () => {
    vi.useFakeTimers();
    const p = beginKillRelease();
    handleWebAuthnFrame({ ...presenceRequest, action: "release the kill switch" } as never);
    await p;
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "no reply from the native host (timed out)",
    });
  });

  test("an enrollment approval is settled by its presence_result alone", async () => {
    // A pushed request (no kill_release asked) has no kill_status_result to wait for.
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
  });

  // The handoff from a real kill_status_result is pinned in tests/background/kill.test.ts.
  test("a refusal handed over while another exchange is outstanding leaves that exchange alone", async () => {
    // Only a kill_release can be answered by a kill_status_result; an enroll_begin's reply is still coming.
    const p = beginEnrollment();
    expect(claimKillRelease({ ok: false, error: "trust record unreadable" })).toBeNull();
    handleWebAuthnFrame(enrollOptions as never);
    await expect(p).resolves.toEqual({ ok: true, options: enrollOptions });
  });
});

describe("presence exchange", () => {
  test("a pushed presence_request is held for the page and opens the options page", () => {
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    expect(pendingPresenceRequest()).toBeNull();
    handleWebAuthnFrame(presenceRequest as never);
    expect(pendingPresenceRequest()).toEqual(presenceRequest);
    expect(open).toHaveBeenCalledTimes(1);
  });

  test("a newer request replaces an unanswered one", () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const newer = { ...presenceRequest, nonce: "nonce-0003", challenge: "bmV3ZXI" };
    handleWebAuthnFrame(newer as never);
    expect(pendingPresenceRequest()).toEqual(newer);
  });

  test("presence_assert consumes the pending request and resolves with the host's verdict", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const p = assertPresence(answer);
    expect(pendingPresenceRequest()).toBeNull();
    expect(posted).toEqual([{ type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: false, reason: "sign_count_not_increased" });
    await expect(p).resolves.toEqual({ ok: false, error: "sign_count_not_increased" });
  });

  test("a presence_result the host's producer cannot emit is malformed, never an approval", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const p = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true, reason: "signature_invalid" });
    await expect(p).resolves.toEqual({ ok: false, error: "malformed presence_result from host" });
  });

  test("a busy exchange refuses the assertion and keeps the request pending for a retry", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const enrolling = beginEnrollment();
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "a WebAuthn exchange is already in flight",
    });
    expect(pendingPresenceRequest()).toEqual(presenceRequest);
    expect(posted).toEqual([{ type: "enroll_begin" }]);
    handleWebAuthnFrame(enrollOptions as never);
    await expect(enrolling).resolves.toMatchObject({ ok: true });
    const p = assertPresence(answer);
    expect(posted).toEqual([{ type: "enroll_begin" }, { type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(p).resolves.toEqual({ ok: true });
  });

  test("an answer to a superseded request is refused and the newer request stays pending", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const newer = { ...presenceRequest, nonce: "nonce-0003", challenge: "bmV3ZXI" };
    handleWebAuthnFrame(newer as never);
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "the presence request was superseded",
    });
    expect(pendingPresenceRequest()).toEqual(newer);
    expect(posted).toEqual([]);
    const p = assertPresence({ ...answer, nonce: "nonce-0003" });
    expect(posted).toEqual([{ type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(p).resolves.toEqual({ ok: true });
  });

  test("a failed post keeps the request pending, and the retry posts it", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    let accept = false;
    attach(collaborator, (frame) => {
      if (!accept) return false;
      posted.push(frame as Record<string, unknown>);
      return true;
    });
    handleWebAuthnFrame(presenceRequest as never);
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "failed to send the request to the native host",
    });
    expect(pendingPresenceRequest()).toEqual(presenceRequest);
    accept = true;
    const p = assertPresence(answer);
    expect(pendingPresenceRequest()).toBeNull();
    expect(posted).toEqual([{ type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(p).resolves.toEqual({ ok: true });
  });

  test("an assertion with no request pending is refused without posting", async () => {
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "no presence request is pending",
    });
    expect(posted).toEqual([]);
  });

  test("a detach drops the pending request: the host that asked is gone", () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    collaborator.onDetach();
    expect(pendingPresenceRequest()).toBeNull();
  });
});

describe("a page operation's presence request", () => {
  const pageOp = { ...presenceRequest, action: "page_eval on https://example.com" };

  test("presence_begin posts the op and origin; the pushed request answers it, stays pending, opens no page, and the tap's verdict reaches the asker", async () => {
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const verdicts: boolean[] = [];
    const p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok));
    expect(posted).toEqual([
      { type: "presence_begin", action: "page_eval", origin: "https://example.com" },
    ]);
    handleWebAuthnFrame(pageOp as never);
    await expect(p).resolves.toEqual({ ok: true, request: pageOp });
    expect(pendingPresenceRequest()).toEqual(pageOp);
    expect(open).not.toHaveBeenCalled();
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
    expect(verdicts).toEqual([true]);
  });

  test("the host's refusal of the answer is the asker's false verdict, exactly once", async () => {
    const verdicts: boolean[] = [];
    const p = beginPresence("page_upload", "https://example.com", (ok) => verdicts.push(ok));
    handleWebAuthnFrame(pageOp as never);
    await p;
    const answered = confirmPresence(pageOp.nonce);
    expect(posted[1]).toEqual({ type: "presence_confirm", nonce: pageOp.nonce });
    handleWebAuthnFrame({
      type: "presence_result",
      ok: false,
      reason: "software_confirmation_not_allowed",
    });
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "software_confirmation_not_allowed",
    });
    expect(verdicts).toEqual([false]);
  });

  test("a presence_begin the host refuses resolves with its reason and calls no verdict", async () => {
    const verdicts: boolean[] = [];
    const p = beginPresence("page_eval", "null", (ok) => verdicts.push(ok));
    handleWebAuthnFrame({ type: "presence_result", ok: false, reason: "invalid_origin" });
    await expect(p).resolves.toEqual({ ok: false, error: "invalid_origin" });
    expect(pendingPresenceRequest()).toBeNull();
    expect(verdicts).toEqual([]);
  });

  test("a request superseded, detached, or abandoned before its answer ends with false (or silently, when abandoned)", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const verdicts: boolean[] = [];
    let p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok));
    handleWebAuthnFrame(pageOp as never);
    await p;
    handleWebAuthnFrame({ ...pageOp, nonce: "nonce-0003", challenge: "bmV3ZXI" } as never);
    expect(verdicts).toEqual([false]);

    p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok));
    handleWebAuthnFrame(pageOp as never);
    await p;
    collaborator.onDetach();
    expect(verdicts).toEqual([false, false]);
    expect(pendingPresenceRequest()).toBeNull();

    attach(collaborator, (frame) => {
      posted.push(frame as Record<string, unknown>);
      return true;
    });
    p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok));
    handleWebAuthnFrame(pageOp as never);
    await p;
    abandonPresence("some-other-nonce");
    expect(pendingPresenceRequest()).toEqual(pageOp);
    abandonPresence(pageOp.nonce);
    expect(pendingPresenceRequest()).toBeNull();
    expect(verdicts).toEqual([false, false]);
  });

  test("a posted answer whose exchange times out ends the asker's request with false", async () => {
    vi.useFakeTimers();
    const verdicts: boolean[] = [];
    const p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok));
    handleWebAuthnFrame(pageOp as never);
    await p;
    const answered = assertPresence(answer);
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "no reply from the native host (timed out)",
    });
    expect(verdicts).toEqual([false]);
  });
});

describe("fail-closed plumbing", () => {
  test("no port, a failed post, and a second exchange in flight each refuse", async () => {
    collaborator.onDetach();
    await expect(beginEnrollment()).resolves.toEqual({
      ok: false,
      error: "native host not connected",
    });
    attach(collaborator, () => false);
    await expect(beginEnrollment()).resolves.toEqual({
      ok: false,
      error: "failed to send the request to the native host",
    });
    attach(collaborator, () => true);
    const first = beginEnrollment();
    await expect(finishEnrollment(registration)).resolves.toEqual({
      ok: false,
      error: "a WebAuthn exchange is already in flight",
    });
    handleWebAuthnFrame(enrollOptions as never);
    await expect(first).resolves.toMatchObject({ ok: true });
  });

  test("an unanswered exchange times out to a refusal, never a hang", async () => {
    vi.useFakeTimers();
    const p = beginEnrollment();
    vi.advanceTimersByTime(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(p).resolves.toEqual({
      ok: false,
      error: "no reply from the native host (timed out)",
    });
  });

  test("a detach fails the outstanding exchange", async () => {
    const p = finishEnrollment(registration);
    collaborator.onDetach();
    await expect(p).resolves.toEqual({ ok: false, error: "native host disconnected" });
  });

  test("a reply wearing a tag the exchange did not ask for is dropped, and the exchange stays open", async () => {
    // A presence_result cannot answer an enroll_finish: a confused or substituted host must not resolve
    // a ceremony with the other ceremony's verdict.
    const p = finishEnrollment(registration);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    handleWebAuthnFrame({ type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" });
    await expect(p).resolves.toEqual({ ok: true, credentialId: "Y3JlZC1h" });
  });

  test("a result with nothing outstanding is dropped without touching state", () => {
    handleWebAuthnFrame({ type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" });
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    expect(posted).toEqual([]);
    expect(pendingPresenceRequest()).toBeNull();
  });
});
