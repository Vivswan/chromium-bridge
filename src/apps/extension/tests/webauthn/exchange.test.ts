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
  beginAct,
  beginEnrollment,
  beginPresence,
  claimAct,
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
    const p = beginAct({ type: "kill_release" });
    expect(posted).toEqual([{ type: "kill_release" }]);
    handleWebAuthnFrame(release as never);
    await expect(p).resolves.toEqual({ ok: true, request: release });
    expect(pendingPresenceRequest()).toEqual(release);
    expect(open).not.toHaveBeenCalled();
    // The page's answer rides the presence path, but its verdict is the release outcome kill.ts hands over.
    const answered = assertPresence(answer);
    expect(posted).toEqual([{ type: "kill_release" }, { type: "presence_assert", ...assertion }]);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    claimAct("kill_status_result", { ok: true })?.({ ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
  });

  // The host writes the record, then emits presence_result ok followed by kill_status_result: ok:false with
  // the error when the write failed, so the presence verdict alone would call a still-engaged switch released.
  test("a release answer waits for the kill_status_result after presence_result ok, and a failed write is its refusal", async () => {
    vi.useFakeTimers();
    const p = beginAct({ type: "kill_release" });
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
    claimAct("kill_status_result", { ok: false })?.({
      ok: false,
      error: "trust record: permission denied",
    });
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "trust record: permission denied",
    });
  });

  test("a release outcome that never arrives times out to a refusal", async () => {
    vi.useFakeTimers();
    const p = beginAct({ type: "kill_release" });
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
    expect(claimAct("kill_status_result", { ok: false })).toBeNull();
    handleWebAuthnFrame(enrollOptions as never);
    await expect(p).resolves.toEqual({ ok: true, options: enrollOptions });
  });
});

describe("presence-gated acts beyond the release", () => {
  const grant = { type: "policy_set" as const, overlay: { pageEvalEnabled: true } };

  test("a refusal before any request settles the act with the host's words, and nothing stays pending", async () => {
    const begun = beginAct(grant);
    expect(posted).toEqual([grant]);
    const settle = claimAct("policy_set_result", { ok: false });
    expect(settle).not.toBeNull();
    settle?.({ ok: false, error: "no host key on this machine" });
    await expect(begun).resolves.toEqual({ ok: false, error: "no host key on this machine" });
    expect(pendingPresenceRequest()).toBeNull();
  });

  test("a free lane's early ok settles the act with no request to answer", async () => {
    const rollback = { type: "policy_rollback" as const, revision: 1 };
    const begun = beginAct(rollback);
    claimAct("policy_rollback_result", { ok: true })?.({ ok: true });
    await expect(begun).resolves.toEqual({ ok: true, request: null });
  });

  test("an act's outcome is claimed by its own result tag alone, and the answer waits for it", async () => {
    vi.useFakeTimers();
    const begun = beginAct(grant);
    handleWebAuthnFrame({ ...presenceRequest, action: "set policy: pageEvalEnabled=on" } as never);
    await begun;
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    // A kill push arriving now is not this act's verdict.
    expect(claimAct("kill_status_result", { ok: true })).toBeNull();
    let settled = false;
    void answered.then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    claimAct("policy_set_result", { ok: false })?.({
      ok: false,
      error: "the policy store changed while this write awaited its signature",
    });
    await expect(answered).resolves.toEqual({
      ok: false,
      error: "the policy store changed while this write awaited its signature",
    });
  });

  const TIMED_OUT = { ok: false, error: "no reply from the native host (timed out)" };
  const grantRequest = { ...presenceRequest, action: "set policy: pageEvalEnabled=on" };

  test("a timed-out act's late reply never settles the act that followed it", async () => {
    // The host answers in order on one pipe and its frames carry no id, so the reply owed to A is the first
    // frame that could be it, consumed before any correlation; B's own request then answers B.
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const a = beginAct(grant);
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(a).resolves.toEqual(TIMED_OUT);
    const b = beginAct(grant);
    expect(claimAct("policy_set_result", { ok: false })).toBeNull();
    let settled = false;
    void b.then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(settled).toBe(false);
    handleWebAuthnFrame(grantRequest as never);
    await expect(b).resolves.toEqual({ ok: true, request: grantRequest });
    expect(pendingPresenceRequest()).toEqual(grantRequest);
  });

  test("a timed-out answer is owed the host's verdict and, when it passed, the act's outcome; neither answers the next act", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const a = beginAct(grant);
    handleWebAuthnFrame(grantRequest as never);
    await a;
    const answered = assertPresence(answer);
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(answered).resolves.toEqual(TIMED_OUT);
    const b = beginAct(grant);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    expect(claimAct("policy_set_result", { ok: false })).toBeNull();
    handleWebAuthnFrame(grantRequest as never);
    await expect(b).resolves.toEqual({ ok: true, request: grantRequest });
  });

  test.each([
    { phase: "its request", answerFirst: false, verdictFirst: false },
    { phase: "its verdict", answerFirst: true, verdictFirst: false },
    { phase: "its outcome", answerFirst: true, verdictFirst: true },
  ])(
    "a release that timed out awaiting $phase locks the exchange until the host reconnects",
    async ({ answerFirst, verdictFirst }) => {
      // kill_status_result is also what the host pushes (a transition, an unreadable record), so a late one
      // cannot be told to be the release's: no debt can be recorded, and nothing else may begin on this
      // connection.
      vi.useFakeTimers();
      vi.spyOn(console, "warn").mockImplementation(() => {});
      vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
      const a = beginAct({ type: "kill_release" });
      const release = { ...presenceRequest, action: "release the kill switch" };
      let timedOut: Promise<unknown> = a;
      if (answerFirst) {
        handleWebAuthnFrame(release as never);
        await a;
        timedOut = assertPresence(answer);
        // The verdict passed: the host now owes the release's outcome frame, and that wait times out.
        if (verdictFirst) handleWebAuthnFrame({ type: "presence_result", ok: true });
      }
      await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
      await expect(timedOut).resolves.toEqual(TIMED_OUT);
      const locked = {
        ok: false,
        error:
          "the native host owes a reply to a kill-switch release that timed out; the WebAuthn exchange is locked until the host reconnects",
      };
      await expect(beginAct(grant)).resolves.toEqual(locked);
      await expect(beginEnrollment()).resolves.toEqual(locked);
      expect(claimAct("kill_status_result", { ok: false })).toBeNull();
      expect(posted).toHaveLength(answerFirst ? 2 : 1);
      // The next connection starts clean.
      collaborator.onDetach();
      attach(collaborator, (frame) => {
        posted.push(frame as Record<string, unknown>);
        return true;
      });
      const b = beginAct(grant);
      handleWebAuthnFrame(grantRequest as never);
      await expect(b).resolves.toEqual({ ok: true, request: grantRequest });
    },
  );

  test("a timed-out enrollment on an enrolled machine is owed the pushed request and the refusal that follows it", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const enrolling = beginEnrollment();
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(enrolling).resolves.toEqual(TIMED_OUT);
    const b = beginAct(grant);
    handleWebAuthnFrame(presenceRequest as never);
    expect(pendingPresenceRequest()).toBeNull();
    handleWebAuthnFrame({ type: "enroll_result", ok: false, reason: "presence_required" } as never);
    handleWebAuthnFrame(grantRequest as never);
    await expect(b).resolves.toEqual({ ok: true, request: grantRequest });
  });

  test("posting a new act drops the request the host superseded; a refused post leaves it", async () => {
    const begun = beginAct(grant);
    const request = { ...presenceRequest, action: "set policy: pageEvalEnabled=on" };
    handleWebAuthnFrame(request as never);
    await begun;
    expect(pendingPresenceRequest()).toEqual(request);
    // The host clears its slot the moment the next request arrives, so the page's copy is stale from then on.
    const next = beginAct({ type: "policy_rollback", revision: 9 });
    expect(pendingPresenceRequest()).toBeNull();
    claimAct("policy_rollback_result", { ok: false })?.({
      ok: false,
      error: "no history entry at revision 9",
    });
    await expect(next).resolves.toEqual({ ok: false, error: "no history entry at revision 9" });
    // A post the exchange refuses (busy) never reached the host: the pending request stands.
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    void beginEnrollment();
    handleWebAuthnFrame(request as never);
    const busy = await beginAct(grant);
    expect(busy).toEqual({ ok: false, error: "a WebAuthn exchange is already in flight" });
    expect(pendingPresenceRequest()).toEqual(request);
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

  test("a frame posted while a request is pending supersedes it, as the host's slot does", async () => {
    // The host takes its pending slot on every enrollment frame and every act, so once enroll_begin is on the
    // pipe the pushed request can no longer be answered there; the worker drops its copy the moment the post
    // succeeds.
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    handleWebAuthnFrame(presenceRequest as never);
    const enrolling = beginEnrollment();
    expect(pendingPresenceRequest()).toBeNull();
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "no presence request is pending",
    });
    expect(posted).toEqual([{ type: "enroll_begin" }]);
    handleWebAuthnFrame(enrollOptions as never);
    await expect(enrolling).resolves.toMatchObject({ ok: true });
  });

  test("a busy exchange refuses the assertion and keeps the request pending for a retry", async () => {
    // A request pushed while an enrollment is open (its replies are named, so the push answers nothing) stays
    // pending through the refusal: the frame never reached the host, so the host's slot still holds it.
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const enrolling = beginEnrollment();
    handleWebAuthnFrame(presenceRequest as never);
    await expect(assertPresence(answer)).resolves.toEqual({
      ok: false,
      error: "a WebAuthn exchange is already in flight",
    });
    expect(pendingPresenceRequest()).toEqual(presenceRequest);
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
    const p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
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
    const p = beginPresence("page_upload", "https://example.com", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame({ ...pageOp, action: "page_upload on https://example.com" } as never);
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
    const p = beginPresence("page_eval", "null", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame({ type: "presence_result", ok: false, reason: "invalid_origin" });
    await expect(p).resolves.toEqual({ ok: false, error: "invalid_origin" });
    expect(pendingPresenceRequest()).toBeNull();
    expect(verdicts).toEqual([]);
  });

  test("a request superseded, detached, or abandoned before its answer ends with false (or silently, when abandoned)", async () => {
    vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const verdicts: boolean[] = [];
    let p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame(pageOp as never);
    await p;
    handleWebAuthnFrame({ ...pageOp, nonce: "nonce-0003", challenge: "bmV3ZXI" } as never);
    expect(verdicts).toEqual([false]);

    p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame(pageOp as never);
    await p;
    collaborator.onDetach();
    expect(verdicts).toEqual([false, false]);
    expect(pendingPresenceRequest()).toBeNull();

    attach(collaborator, (frame) => {
      posted.push(frame as Record<string, unknown>);
      return true;
    });
    p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame(pageOp as never);
    await p;
    abandonPresence("some-other-nonce");
    expect(pendingPresenceRequest()).toEqual(pageOp);
    abandonPresence(pageOp.nonce);
    expect(pendingPresenceRequest()).toBeNull();
    expect(verdicts).toEqual([false, false]);
  });

  test("a request naming another act than the one asked is refused and not held", async () => {
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const verdicts: boolean[] = [];
    const p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
    handleWebAuthnFrame({ ...pageOp, action: "page_upload on https://evil.example" } as never);
    await expect(p).resolves.toEqual({ ok: false, error: "the host's request names another act" });
    expect(pendingPresenceRequest()).toBeNull();
    expect(open).not.toHaveBeenCalled();
    expect(verdicts).toEqual([]);
  });

  test("a begin cancelled before the host answers frees the exchange at once, and its late reply is dropped", async () => {
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const begin = beginPresence("page_eval", "https://example.com", () => {});
    begin.cancel();
    await expect(begin.view).resolves.toEqual({
      ok: false,
      error: "the confirmation ended before the host answered",
    });
    // The next act is not refused as busy, and the host answers in order: the cancelled begin's reply comes
    // first and is dropped, then the enrollment's options answer the enrollment.
    const enrolling = beginEnrollment();
    expect(posted).toEqual([
      { type: "presence_begin", action: "page_eval", origin: "https://example.com" },
      { type: "enroll_begin" },
    ]);
    handleWebAuthnFrame(pageOp as never);
    expect(pendingPresenceRequest()).toBeNull();
    expect(open).not.toHaveBeenCalled();
    handleWebAuthnFrame(enrollOptions as never);
    await expect(enrolling).resolves.toEqual({ ok: true, options: enrollOptions });
    // Cancelling once the host has answered changes nothing: a push after it is a push.
    begin.cancel();
    handleWebAuthnFrame(pageOp as never);
    expect(pendingPresenceRequest()).toEqual(pageOp);
    expect(open).toHaveBeenCalledTimes(1);
  });

  test("a begin whose exchange times out owes the host's late reply the same drop as a cancelled one", async () => {
    vi.useFakeTimers();
    const open = vi.spyOn(fakeBrowser.runtime, "openOptionsPage").mockResolvedValue(undefined);
    const begin = beginPresence("page_eval", "https://example.com", () => {});
    await vi.advanceTimersByTimeAsync(HOST_REPLY_TIMEOUT_MS + 1);
    await expect(begin.view).resolves.toEqual({
      ok: false,
      error: "no reply from the native host (timed out)",
    });
    // The host's reply, late, is the timed-out begin's: dropped, held for nobody, no page opened.
    handleWebAuthnFrame(pageOp as never);
    expect(pendingPresenceRequest()).toBeNull();
    expect(open).not.toHaveBeenCalled();
    // The debt is one reply deep: the next push is a push.
    handleWebAuthnFrame(pageOp as never);
    expect(pendingPresenceRequest()).toEqual(pageOp);
    expect(open).toHaveBeenCalledTimes(1);
  });

  test("a posted answer whose exchange times out ends the asker's request with false", async () => {
    vi.useFakeTimers();
    const verdicts: boolean[] = [];
    const p = beginPresence("page_eval", "https://example.com", (ok) => verdicts.push(ok)).view;
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
