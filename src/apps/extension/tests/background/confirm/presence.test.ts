// The Enclave user-presence provider (ADR-0031): the confirmation gate that
// only a verified host signature can approve. These are the adversarial
// pins for the phase:
//   - a valid signed proof (pinned key, presence domain, exact nonce+context)
//     approves;
//   - a proof signed by ANY other key denies AND marks the bridge
//     compromised;
//   - an enrollment-domain signature can never approve a presence round
//     (domain separation);
//   - a presence_error, a missing pin, a detached port, and a late proof
//     after dismissal all deny;
//   - the service refuses a window-side approval for a hardware payload
//     (resolveConfirm), while denial stays window-reachable;
//   - opted-out (touchIdConfirm=false) falls back to the window provider -
//     still confirmed - and non-eval/upload kinds never route to hardware.

import { type ConfirmPayload, isHardwareGated } from "@chromium-bridge/shared";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { getCompromised, setPin } from "@/lib/background/enclave-pin";
import {
  base64Encode,
  buildChallengeMessage,
  buildPresenceMessage,
  computeKeyId,
} from "@/lib/background/enclave-verify";

vi.mock("@/lib/background/enrollment", () => ({
  platformCanEnroll: vi.fn(() => Promise.resolve(true)),
}));

import {
  attachPort,
  detachPort,
  EnclavePresenceProvider,
  handlePresenceFrame,
  isPresenceFrame,
  presenceRoutingEnabled,
  resetPresenceForTests,
} from "@/lib/background/confirm/presence";
import type { ConfirmationProvider, Presentation } from "@/lib/background/confirm/service";
import {
  confirmWithUser,
  currentPanicEpoch,
  installConfirmationProvider,
  installPresenceProvider,
  resolveConfirm,
} from "@/lib/background/confirm/service";
import { getEffectivePolicy } from "@/lib/background/effective-policy";
// The MOCKED capability probe (the factory above), so a test can park or
// fail one round's setup on demand.
import { platformCanEnroll } from "@/lib/background/enrollment";

// The decision-start reads a real caller performs (pre-cutover here, so the
// legacy settings govern): unwrap the state-typed snapshot for the routing
// predicate.
async function freshValues() {
  const policy = await getEffectivePolicy();
  if (policy.state === "blocked") throw new Error(policy.reason);
  return policy.values;
}

// ---- test key + proof helpers (WebCrypto plays the Secure Enclave) -----------

interface TestKey {
  kp: CryptoKeyPair;
  pubkeyB64: string;
  keyId: string;
}

async function genKey(): Promise<TestKey> {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { kp, pubkeyB64: base64Encode(raw), keyId: await computeKeyId(raw) };
}

async function signB64(key: TestKey, message: Uint8Array): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key.kp.privateKey,
      message as BufferSource,
    ),
  );
  return base64Encode(sig);
}

async function pinKey(key: TestKey): Promise<void> {
  await setPin({ keyId: key.keyId, pubkeyB64: key.pubkeyB64, pinnedAt: Date.now() });
}

/** A display provider that never answers on its own (like the real window
 * while the user watches it) and records what it was shown. */
function displayStub(): { provider: ConfirmationProvider; shown: ConfirmPayload[] } {
  const shown: ConfirmPayload[] = [];
  return {
    shown,
    provider: {
      present(payload: ConfirmPayload): Presentation {
        shown.push(payload);
        return { verdict: new Promise<boolean>(() => {}), dismiss: () => {} };
      },
    },
  };
}

/** Run one provider round directly: present, capture the outgoing challenge,
 * hand the answer frame back, await the verdict. */
async function roundTrip(
  key: TestKey | null,
  answer: (sent: { nonce: string; context: string }) => Promise<unknown> | unknown,
): Promise<boolean> {
  const sent: Array<{ nonce: string; context: string }> = [];
  attachPort((frame) => {
    sent.push(frame as { nonce: string; context: string });
    return true;
  });
  const { provider } = displayStub();
  const p = new EnclavePresenceProvider(provider);
  const presentation = p.present(payload("eval", "1 + 1"));
  // Let runRound send the challenge.
  await vi.waitFor(() => expect(sent.length).toBe(1));
  const frame = await answer(first(sent));
  if (frame !== undefined) handlePresenceFrame(frame);
  const verdict = await presentation.verdict;
  void key;
  return verdict;
}

function payload(kind: "eval" | "upload", detail: string): ConfirmPayload {
  return {
    id: `confirm_test_${Math.random()}`,
    kind,
    origin: "https://example.test",
    tabTitle: "t",
    detail,
    deadline: Date.now() + 30_000,
    hardware: true,
  };
}

/** First element or throw - keeps the strict-index checker happy in tests. */
function first<T>(a: T[]): T {
  const v = a[0];
  if (v === undefined) throw new Error("expected at least one element");
  return v;
}

beforeEach(() => {
  fakeBrowser.reset();
  resetPresenceForTests();
});

describe("frame classification", () => {
  test("recognizes exactly the presence answer frames", () => {
    expect(isPresenceFrame({ type: "presence_proof", sig: "s" })).toBe(true);
    expect(isPresenceFrame({ type: "presence_error" })).toBe(true);
    expect(isPresenceFrame({ type: "enclave_proof", sig: "s" })).toBe(false);
    expect(isPresenceFrame({ op: "tab_list", id: 1 })).toBe(false);
    expect(isPresenceFrame(null)).toBe(false);
  });
});

describe("EnclavePresenceProvider verdicts", () => {
  test("a valid proof from the pinned key approves", async () => {
    const key = await genKey();
    await pinKey(key);
    const approved = await roundTrip(key, async ({ nonce, context }) => ({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(nonce, context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    }));
    expect(approved).toBe(true);
    expect(await getCompromised()).toBeNull();
  });

  test("a proof signed by a different key denies and marks compromised", async () => {
    const pinned = await genKey();
    const imposter = await genKey();
    await pinKey(pinned);
    const approved = await roundTrip(pinned, async ({ nonce, context }) => ({
      type: "presence_proof",
      // The imposter even CLAIMS the pinned identity; only the signature is
      // its own. Verification runs against the pinned bytes and fails.
      sig: await signB64(imposter, buildPresenceMessage(nonce, context)),
      key_id: pinned.keyId,
      pubkey: pinned.pubkeyB64,
    }));
    expect(approved).toBe(false);
    const mark = await getCompromised();
    expect(mark).not.toBeNull();
    expect(mark?.reason).toContain("presence proof failed verification");
  });

  test("an enrollment-domain signature never approves a presence round", async () => {
    const key = await genKey();
    await pinKey(key);
    const approved = await roundTrip(key, async ({ nonce, context }) => ({
      type: "presence_proof",
      // Signed by the REAL pinned key, but over the enrollment domain: a
      // captured/coerced ceremony signature must not double as an approval.
      sig: await signB64(key, buildChallengeMessage(nonce, context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    }));
    expect(approved).toBe(false);
  });

  test("a proof over a different context (another action) denies", async () => {
    const key = await genKey();
    await pinKey(key);
    const approved = await roundTrip(key, async ({ nonce }) => ({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(nonce, "ext:other:presence:eval:deadbeef")),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    }));
    expect(approved).toBe(false);
  });

  test("a presence_error denies", async () => {
    const key = await genKey();
    await pinKey(key);
    const approved = await roundTrip(key, () => ({ type: "presence_error", reason: "busy" }));
    expect(approved).toBe(false);
  });

  test("no pin means no round: denied without sending a challenge", async () => {
    const sent: unknown[] = [];
    attachPort((frame) => {
      sent.push(frame);
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const verdict = await p.present(payload("eval", "x")).verdict;
    expect(verdict).toBe(false);
    expect(sent.length).toBe(0);
  });

  test("port detaching mid-round denies", async () => {
    const key = await genKey();
    await pinKey(key);
    const approved = await roundTrip(key, () => {
      detachPort();
      return undefined; // no answer will ever come
    });
    expect(approved).toBe(false);
  });

  test("a valid proof arriving after the port detached is denied (fail closed)", async () => {
    // The port can drop AFTER the proof frame is claimed but BEFORE the async
    // pin lookup + verify finish. detachPort cannot cancel an already-claimed
    // round, so the post-verification port re-check is what honors the
    // disconnect-denies contract - even though the signature itself is valid.
    const key = await genKey();
    await pinKey(key);
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const presentation = p.present(payload("eval", "x"));
    await vi.waitFor(() => expect(sent.length).toBe(1));
    const proof = {
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    };
    // Deliver the (cryptographically valid) proof - this synchronously claims
    // the round off `pending` and starts the async verify - THEN drop the
    // port before the verify resolves. detachPort now finds no pending round
    // to cancel, so only the post-verification generation check can deny it.
    handlePresenceFrame(proof);
    detachPort();
    expect(await presentation.verdict).toBe(false);
    // A valid signature is not a compromise: no compromised mark is set.
    expect(await getCompromised()).toBeNull();
  });

  test("a proof arriving after a disconnect+reconnect is denied (generation check)", async () => {
    // The tighter race the plain !post check missed: the port drops AND a new
    // one attaches before the async verify finishes, so `post` is non-null at
    // verdict time. The port-generation token catches it - the challenge was
    // sent on an older generation than the live one.
    const key = await genKey();
    await pinKey(key);
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const presentation = p.present(payload("eval", "x"));
    await vi.waitFor(() => expect(sent.length).toBe(1));
    const proof = {
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    };
    // Claim the round, then simulate a full reconnect (detach + a fresh
    // attach) before the verdict resolves: `post` is non-null again.
    handlePresenceFrame(proof);
    detachPort();
    attachPort(() => true);
    expect(await presentation.verdict).toBe(false);
    expect(await getCompromised()).toBeNull();
  });

  test("a late proof after dismissal is dropped (nonce burned)", async () => {
    const key = await genKey();
    await pinKey(key);
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const presentation = p.present(payload("eval", "x"));
    await vi.waitFor(() => expect(sent.length).toBe(1));
    // The service gives up (deadline) and dismisses; the round is cancelled.
    presentation.dismiss();
    expect(await presentation.verdict).toBe(false);
    // The tap completes anyway and the proof arrives late: nothing to
    // approve, and nothing throws.
    handlePresenceFrame({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    });
    expect(await presentation.verdict).toBe(false);
  });

  test("two same-tick rounds: the second is refused and cannot corrupt the first", async () => {
    // The slot is claimed synchronously, before any await. The old code
    // claimed it only after two awaits, so two same-tick rounds BOTH passed
    // the single-flight guard: two challenges went out, the second claim
    // overwrote the first (orphaning its settle), and the first challenge's
    // valid proof then verified against the wrong nonce - denying the tap
    // the user just gave and marking the bridge compromised.
    const key = await genKey();
    await pinKey(key);
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const round1 = p.present(payload("eval", "one"));
    const round2 = p.present(payload("eval", "two"));
    // The second round is refused outright - its verdict denies without a
    // challenge ever going out for it.
    expect(await round2.verdict).toBe(false);
    await vi.waitFor(() => expect(sent.length).toBe(1));
    // Give the refused round's setup every chance to misbehave late.
    await new Promise((r) => setTimeout(r, 20));
    expect(sent.length).toBe(1);
    // The first round is intact: its own challenge's proof approves it.
    handlePresenceFrame({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    });
    expect(await round1.verdict).toBe(true);
    expect(await getCompromised()).toBeNull();
  });

  test("an answer that precedes the challenge denies and the challenge is never sent", async () => {
    // The round is claimed synchronously but its challenge goes out only
    // after async setup. A frame landing in that gap answers nothing that
    // was ever asked: deny the round, and the aborted setup must not send
    // a challenge for a round that is already settled.
    const key = await genKey();
    await pinKey(key);
    const sent: unknown[] = [];
    attachPort((frame) => {
      sent.push(frame);
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const presentation = p.present(payload("eval", "x"));
    // Same tick, before the setup's awaits complete.
    handlePresenceFrame({ type: "presence_error", reason: "spurious" });
    expect(await presentation.verdict).toBe(false);
    await new Promise((r) => setTimeout(r, 20));
    expect(sent.length).toBe(0);
  });

  test("a stale setup rejecting late cannot cancel a successor round", async () => {
    // Round A parks inside presenceCapable (platformCanEnroll gated); a
    // teardown settles it fail-closed; round B claims the freed slot and
    // sends its challenge. A's parked setup then REJECTS: the catch may
    // cancel only a round it still owns - an unconditional cancelPending
    // there would kill B, denying the tap the user is about to give.
    const key = await genKey();
    await pinKey(key);
    let rejectA!: (e: unknown) => void;
    vi.mocked(platformCanEnroll).mockImplementationOnce(
      () =>
        new Promise<boolean>((_, rej) => {
          rejectA = rej;
        }),
    );
    attachPort(() => true);
    const { provider } = displayStub();
    const roundA = new EnclavePresenceProvider(provider).present(payload("eval", "a"));
    detachPort(); // settles A; its setup is still parked in presenceCapable
    expect(await roundA.verdict).toBe(false);

    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const roundB = new EnclavePresenceProvider(provider).present(payload("eval", "b"));
    await vi.waitFor(() => expect(sent.length).toBe(1));

    rejectA(new Error("late setup failure")); // A's stale setup rejects now
    await new Promise((r) => setTimeout(r, 20));

    // B is unaffected: its own challenge's valid proof still approves it.
    handlePresenceFrame({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    });
    expect(await roundB.verdict).toBe(true);
    expect(await getCompromised()).toBeNull();
  });
});

// The codex-vs-Opus adjudication (stale port after a FAILED re-entrant
// connect, where port.ts fires no local onDisconnect). teardownLink's
// presence-facing action on the connected branch is exactly detachPort();
// this exercises that action and lets the code decide who is right.
//
// Verdict: the round DENIES. detachPort cancels the outstanding round
// synchronously at teardown, so a later cryptographically valid proof finds
// nothing to approve. Pre-fix, teardownLink did NOT call detachPort, so
// presence stayed in its happy-path state (module port still the old
// attachment, round still pending) and the same valid proof APPROVED while
// the link was down - codex's bug was real; the fix (detachPort in teardown,
// plus the inbound identity gate in port.ts) is what closes it.
describe("adjudication: a valid proof after teardown cannot approve", () => {
  test("detachPort at teardown denies a subsequently delivered valid proof", async () => {
    const key = await genKey();
    await pinKey(key);
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const { provider } = displayStub();
    const p = new EnclavePresenceProvider(provider);
    const presentation = p.present(payload("eval", "steal"));
    await vi.waitFor(() => expect(sent.length).toBe(1));
    // Build the genuine tap's proof for THIS challenge.
    const proof = {
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    };
    // The failed re-entrant connect: teardownLink's presence action, with no
    // onDisconnect and no replacement attach.
    detachPort();
    // The round is already denied by the teardown; the late (valid) proof
    // finds no round and cannot revive it.
    handlePresenceFrame(proof);
    expect(await presentation.verdict).toBe(false);
    // A valid signature is not a compromise: no mark.
    expect(await getCompromised()).toBeNull();
  });
});

describe("service routing and the window-approval refusal", () => {
  test("hardware payloads cannot be approved through resolveConfirm", async () => {
    const key = await genKey();
    await pinKey(key);
    await fakeBrowser.storage.local.set({ touchIdConfirm: true });
    const sent: Array<{ nonce: string; context: string }> = [];
    attachPort((frame) => {
      sent.push(frame as { nonce: string; context: string });
      return true;
    });
    const display = displayStub();
    installConfirmationProvider(display.provider);
    installPresenceProvider(new EnclavePresenceProvider(display.provider));

    const result = confirmWithUser({
      kind: "eval",
      origin: "https://example.test",
      tabTitle: "t",
      detail: "fetch('/steal')",
      timeoutMs: 30_000,
      presenceRouting: await presenceRoutingEnabled(await freshValues()),
      panicEpoch: currentPanicEpoch(),
    });
    await vi.waitFor(() => expect(display.shown.length).toBe(1));
    const shown = first(display.shown);
    expect(isHardwareGated(shown)).toBe(true);

    // The adversarial move: something with extension-page reach tries to
    // approve through the window path. Refused - the tap is the approval.
    expect(resolveConfirm(shown.id, true).ok).toBe(false);

    // The genuine tap arrives as a signed proof and approves.
    await vi.waitFor(() => expect(sent.length).toBe(1));
    handlePresenceFrame({
      type: "presence_proof",
      sig: await signB64(key, buildPresenceMessage(first(sent).nonce, first(sent).context)),
      key_id: key.keyId,
      pubkey: key.pubkeyB64,
    });
    expect(await result).toBe(true);
  });

  test("denial through the window stays possible for hardware payloads", async () => {
    const key = await genKey();
    await pinKey(key);
    await fakeBrowser.storage.local.set({ touchIdConfirm: true });
    attachPort(() => true);
    const display = displayStub();
    installConfirmationProvider(display.provider);
    installPresenceProvider(new EnclavePresenceProvider(display.provider));

    const result = confirmWithUser({
      kind: "upload",
      origin: "https://example.test",
      tabTitle: "t",
      detail: "/etc/passwd",
      timeoutMs: 30_000,
      presenceRouting: await presenceRoutingEnabled(await freshValues()),
      panicEpoch: currentPanicEpoch(),
    });
    await vi.waitFor(() => expect(display.shown.length).toBe(1));
    const denied = resolveConfirm(first(display.shown).id, false);
    expect(denied.ok).toBe(true);
    expect(await result).toBe(false);
  });

  test("opted out falls back to the window provider (no hardware flag)", async () => {
    const key = await genKey();
    await pinKey(key);
    await fakeBrowser.storage.local.set({ touchIdConfirm: false });
    const display = displayStub();
    installConfirmationProvider(display.provider);
    installPresenceProvider(new EnclavePresenceProvider(display.provider));

    const result = confirmWithUser({
      kind: "eval",
      origin: "https://example.test",
      tabTitle: "t",
      detail: "1",
      timeoutMs: 30_000,
      presenceRouting: await presenceRoutingEnabled(await freshValues()),
      panicEpoch: currentPanicEpoch(),
    });
    await vi.waitFor(() => expect(display.shown.length).toBe(1));
    const shown = first(display.shown);
    expect(isHardwareGated(shown)).toBe(false);
    // The window Allow works, as before Phase 8.
    expect(resolveConfirm(shown.id, true).ok).toBe(true);
    expect(await result).toBe(true);
  });

  test("kinds other than eval/upload never route to hardware", async () => {
    const key = await genKey();
    await pinKey(key);
    await fakeBrowser.storage.local.set({ touchIdConfirm: true });
    const display = displayStub();
    installConfirmationProvider(display.provider);
    installPresenceProvider(new EnclavePresenceProvider(display.provider));

    const result = confirmWithUser({
      kind: "click",
      origin: "https://example.test",
      tabTitle: "t",
      detail: "submit",
      timeoutMs: 30_000,
      presenceRouting: await presenceRoutingEnabled(await freshValues()),
      panicEpoch: currentPanicEpoch(),
    });
    await vi.waitFor(() => expect(display.shown.length).toBe(1));
    expect(isHardwareGated(first(display.shown))).toBe(false);
    expect(resolveConfirm(first(display.shown).id, false).ok).toBe(true);
    expect(await result).toBe(false);
  });
});
