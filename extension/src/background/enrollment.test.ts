import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as pinStore from "./enclave-pin";
import {
  approvePending,
  attachPort,
  detachPort,
  enrollmentGate,
  getEnrollmentStatus,
  handleEnclaveFrame,
  isEnclaveFrame,
  onPortConnected,
  rejectPending,
  revokePin,
  startPairing,
  verifyPinnedNow,
} from "./enrollment";
import { base64Encode, buildChallengeMessage, computeKeyId } from "./enclave-verify";

// The ceremony state machine, driven end to end with a mocked chrome and a
// WebCrypto key standing in for the host's Secure Enclave key. What CANNOT be
// tested here: the real native host, the keychain, and the Touch ID prompt;
// those have a manual script on the host side
// (docs/security/enrollment-manual-test.md).

// ---- chrome mock ------------------------------------------------------------

// The browser's platform probe, which scopes enrollment enforcement. Tests
// default to "mac" (enforcing); the platform-scoping suite overrides it.
let mockOs = "mac";

function installChromeMock(): Record<string, unknown> {
  const store: Record<string, unknown> = {};
  (globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      id: "test-ext-id",
      getPlatformInfo: () => Promise.resolve({ os: mockOs }),
    },
    storage: {
      local: {
        // Supports both the callback style (settings.ts) and the promise
        // style (enclave-pin.ts).
        get: (key: string | string[], cb?: (r: Record<string, unknown>) => void) => {
          const keys = typeof key === "string" ? [key] : key;
          const result: Record<string, unknown> = {};
          for (const k of keys) if (k in store) result[k] = store[k];
          if (typeof cb === "function") {
            cb(result);
            return;
          }
          return Promise.resolve(result);
        },
        set: (obj: Record<string, unknown>) => {
          Object.assign(store, obj);
          return Promise.resolve();
        },
        remove: (key: string | string[]) => {
          for (const k of Array.isArray(key) ? key : [key]) delete store[k];
          return Promise.resolve();
        },
      },
    },
    action: {
      setBadgeText: () => Promise.resolve(),
      setBadgeBackgroundColor: () => Promise.resolve(),
    },
  };
  return store;
}

// ---- test key (plays the host's Enclave key) ---------------------------------

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

async function proofFrame(key: TestKey, nonce: string, context?: string) {
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key.kp.privateKey,
      buildChallengeMessage(nonce, context)
    )
  );
  return {
    type: "enclave_proof",
    sig: base64Encode(sig),
    key_id: key.keyId,
    pubkey: key.pubkeyB64,
  };
}

// ---- harness ------------------------------------------------------------------

let store: Record<string, unknown>;
let posted: Array<Record<string, unknown>>;

beforeEach(() => {
  mockOs = "mac";
  store = installChromeMock();
  posted = [];
  detachPort(); // clear any leftover outstanding challenge from a prior test
  attachPort((frame) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  });
});

afterEach(() => {
  detachPort();
});

function lastChallenge(): { nonce: string; context: string } {
  const frame = posted[posted.length - 1];
  expect(frame.type).toBe("enclave_challenge");
  return { nonce: frame.nonce as string, context: frame.context as string };
}

async function pairAndPin(key: TestKey): Promise<void> {
  await onPortConnected();
  const { nonce, context } = lastChallenge();
  await handleEnclaveFrame(await proofFrame(key, nonce, context));
  const approved = await approvePending();
  expect(approved.ok).toBe(true);
}

// ---- tests ----------------------------------------------------------------------

describe("isEnclaveFrame", () => {
  test("matches the three control tags and nothing else", () => {
    expect(isEnclaveFrame({ type: "enclave_proof" })).toBe(true);
    expect(isEnclaveFrame({ type: "enclave_error" })).toBe(true);
    expect(isEnclaveFrame({ type: "enclave_challenge" })).toBe(true);
    expect(isEnclaveFrame({ id: 1, op: "tab_list", args: {} })).toBe(false);
    expect(isEnclaveFrame({ type: "something_else" })).toBe(false);
    expect(isEnclaveFrame(null)).toBe(false);
    expect(isEnclaveFrame("enclave_proof")).toBe(false);
  });
});

describe("pin store", () => {
  test("pin roundtrip with a real key; clearAll forgets everything", async () => {
    const key = await genKey();
    expect(await pinStore.getPin()).toBeNull();
    const pin = { keyId: key.keyId, pubkeyB64: key.pubkeyB64, pinnedAt: 123 };
    await pinStore.setPin(pin);
    expect(await pinStore.getPin()).toEqual(pin);
    await pinStore.clearAll();
    expect(await pinStore.getPin()).toBeNull();
    expect(await pinStore.getPending()).toBeNull();
    expect(await pinStore.getCompromised()).toBeNull();
  });

  test("a stored pin whose keyId does not match its pubkey is not a pin", async () => {
    const key = await genKey();
    store["enclavePin"] = { keyId: "a".repeat(64), pubkeyB64: key.pubkeyB64, pinnedAt: 1 };
    expect(await pinStore.getPin()).toBeNull();
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("a stored pin whose pubkey does not decode is not a pin", async () => {
    // "QUJD" is canonical base64 for "ABC": 3 bytes, not a 65-byte point.
    store["enclavePin"] = { keyId: "a".repeat(64), pubkeyB64: "QUJD", pinnedAt: 1 };
    expect(await pinStore.getPin()).toBeNull();
    store["enclavePin"] = { keyId: "short", pubkeyB64: "QUJD", pinnedAt: 1 };
    expect(await pinStore.getPin()).toBeNull();
    expect((await enrollmentGate()).allowed).toBe(false);
  });
});

describe("ceremony state machine", () => {
  test("default state fails closed with pairing instructions", async () => {
    const gate = await enrollmentGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("chromium-bridge pair");
    expect((await getEnrollmentStatus()).state).toBe("unpaired");
  });

  test("full ceremony: challenge -> proof -> pending -> approve -> pinned", async () => {
    const key = await genKey();

    await onPortConnected();
    expect(posted.length).toBe(1);
    const { nonce, context } = lastChallenge();
    expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(context).toContain("test-ext-id");

    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    let st = await getEnrollmentStatus();
    expect(st.state).toBe("pending");
    expect(st.keyId).toBe(key.keyId);
    let gate = await enrollmentGate();
    expect(gate.allowed).toBe(false); // pending is still blocked

    expect((await approvePending()).ok).toBe(true);
    st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect(st.keyId).toBe(key.keyId);
    gate = await enrollmentGate();
    expect(gate.allowed).toBe(true);
  });

  test("once pinned, reconnects are not challenged (session granularity)", async () => {
    const key = await genKey();
    await pairAndPin(key);
    const before = posted.length;
    await onPortConnected();
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("a proof from the wrong key never becomes pending", async () => {
    const attacker = await genKey();
    await onPortConnected();
    const { nonce } = lastChallenge();
    // Signed over the right nonce but the wrong context: fails verification.
    await handleEnclaveFrame(await proofFrame(attacker, nonce, "wrong-context"));
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect(st.lastError).toContain("rejected");
  });

  test("manual verify against the pin succeeds for the pinned key", async () => {
    const key = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect(typeof st.lastVerifiedAt).toBe("number");
    expect((await enrollmentGate()).allowed).toBe(true);
  });

  test("verify answered by another key fails closed", async () => {
    const key = await genKey();
    const attacker = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(attacker, nonce, context));
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("compromised");
    const gate = await enrollmentGate();
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("failed closed");
  });

  test("verify answered with the pinned identifiers but another signer fails closed", async () => {
    const key = await genKey();
    const attacker = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    const { nonce, context } = lastChallenge();
    const forged = await proofFrame(attacker, nonce, context);
    forged.key_id = key.keyId;
    forged.pubkey = key.pubkeyB64;
    await handleEnclaveFrame(forged);
    expect((await getEnrollmentStatus()).state).toBe("compromised");
  });

  test("unsolicited and replayed proofs are dropped without touching state", async () => {
    const key = await genKey();
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    const frame = await proofFrame(key, nonce, context);
    await handleEnclaveFrame(frame);
    expect((await approvePending()).ok).toBe(true);
    // Same frame delivered again: no outstanding challenge, so it is dropped.
    await handleEnclaveFrame(frame);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect((await enrollmentGate()).allowed).toBe(true);
  });

  test("a proof for a challenge lost to a SW restart is dropped", async () => {
    const key = await genKey();
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    const frame = await proofFrame(key, nonce, context);
    detachPort(); // port drop / SW death clears the outstanding nonce
    attachPort((f) => {
      posted.push(f as Record<string, unknown>);
      return true;
    });
    await handleEnclaveFrame(frame);
    expect((await getEnrollmentStatus()).state).toBe("unpaired");
  });

  test("not_enrolled during pairing surfaces the pair instruction, still blocked", async () => {
    await onPortConnected();
    await handleEnclaveFrame({ type: "enclave_error", reason: "not_enrolled" });
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect(st.lastError).toContain("chromium-bridge pair");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("a host claiming unsupported_platform on macOS stays blocked (no downgrade dodge)", async () => {
    await onPortConnected();
    await handleEnclaveFrame({ type: "enclave_error", reason: "unsupported_platform" });
    const st = await getEnrollmentStatus();
    expect(st.lastError).toContain("suspect");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("unsupported_platform during verify fails closed (downgrade claim on a pinned machine)", async () => {
    const key = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    await handleEnclaveFrame({ type: "enclave_error", reason: "unsupported_platform" });
    expect((await getEnrollmentStatus()).state).toBe("compromised");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("signing_failed during verify does NOT fail closed (prompt declined)", async () => {
    const key = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    await handleEnclaveFrame({ type: "enclave_error", reason: "signing_failed" });
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect(st.lastError).toContain("signing_failed");
    expect((await enrollmentGate()).allowed).toBe(true);
  });

  test("not_enrolled during verify DOES fail closed (pinned key is gone)", async () => {
    const key = await genKey();
    await pairAndPin(key);
    expect((await verifyPinnedNow()).ok).toBe(true);
    await handleEnclaveFrame({ type: "enclave_error", reason: "not_enrolled" });
    expect((await getEnrollmentStatus()).state).toBe("compromised");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("rejecting the fingerprint pauses auto-pairing", async () => {
    const key = await genKey();
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    expect((await rejectPending()).ok).toBe(true);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect(st.paused).toBe(true);
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before); // no surprise Touch ID prompt
    // startPairing resumes explicitly.
    expect((await startPairing()).ok).toBe(true);
    expect(posted.length).toBe(before + 1);
  });

  test("revoke forgets the pin, blocks, and pauses auto-pairing", async () => {
    const key = await genKey();
    await pairAndPin(key);
    expect((await revokePin()).ok).toBe(true);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect((await enrollmentGate()).allowed).toBe(false);
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("startPairing refuses while a key is pinned", async () => {
    const key = await genKey();
    await pairAndPin(key);
    const res = await startPairing();
    expect(res.ok).toBe(false);
    expect(res.error).toContain("revoke");
  });

  test("requireEnrollment=false opens the gate and skips the ceremony", async () => {
    store["requireEnrollment"] = false;
    expect((await enrollmentGate()).allowed).toBe(true);
    await onPortConnected();
    expect(posted.length).toBe(0);
  });

  test("a stale reject after approval does not touch the pin", async () => {
    const key = await genKey();
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    expect((await approvePending()).ok).toBe(true);
    // Second tab clicks reject after the first tab approved.
    const rej = await rejectPending();
    expect(rej.ok).toBe(false);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect(st.paused).not.toBe(true);
    expect((await enrollmentGate()).allowed).toBe(true);
  });

  test("interleaved approve and revoke serialize; revoke wins and nothing resurrects the pin", async () => {
    const key = await genKey();
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    // Fire both without awaiting in between: the transition queue must run
    // them in call order (approve, then revoke), leaving the pin gone.
    const approveP = approvePending();
    const revokeP = revokePin();
    expect((await approveP).ok).toBe(true);
    expect((await revokeP).ok).toBe(true);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("a pairing proof in flight cannot recreate pending state after revoke", async () => {
    const keyA = await genKey();
    const keyB = await genKey();
    await pairAndPin(keyA);
    expect((await revokePin()).ok).toBe(true);
    // Paused now; restart pairing manually, then interleave a revoke with the
    // proof so the proof processes after state was wiped again.
    expect((await startPairing()).ok).toBe(true);
    const { nonce, context } = lastChallenge();
    const frame = await proofFrame(keyB, nonce, context);
    const revokeP = revokePin(); // queued first: clears the outstanding nonce
    const proofP = handleEnclaveFrame(frame); // queued second: must be unsolicited
    await Promise.all([revokeP, proofP]);
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("unpaired");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("a revoke queued while the gate is evaluating blocks the in-flight op", async () => {
    const key = await genKey();
    await pairAndPin(key);

    // Hold the transition queue with a stalled transition (onPortConnected's
    // first storage read), so the revoke below sits QUEUED - not yet applied -
    // while the gate's first-pass reads still see the pinned state. The old,
    // unserialized gate answered "allowed" from exactly this interleaving and
    // the op dispatched after the revoke had landed.
    type StorageGet = (
      key: string | string[],
      cb?: (r: Record<string, unknown>) => void
    ) => Promise<Record<string, unknown>> | undefined;
    const local = (globalThis as unknown as { chrome: { storage: { local: { get: StorageGet } } } })
      .chrome.storage.local;
    const realGet = local.get;
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    local.get = (k, cb) => {
      if (typeof cb === "function") {
        void held.then(() => realGet(k, cb));
        return undefined;
      }
      return held.then(() => realGet(k)) as Promise<Record<string, unknown>>;
    };
    const blocker = onPortConnected(); // stalls inside the queue on its first read
    local.get = realGet; // everything else reads normally

    let dispatched = 0;
    const gateP = enrollmentGate(() => {
      dispatched += 1;
    }); // first pass sees the pinned state
    const revokeP = revokePin(); // queued behind the blocker, ahead of the gate's re-check
    await new Promise((resolve) => setTimeout(resolve, 0)); // let the first pass finish
    release();
    await Promise.all([blocker, revokeP]);

    const gate = await gateP;
    expect(gate.allowed).toBe(false);
    expect(dispatched).toBe(0); // the op never began dispatching
  });

  test("a compromise mark landing while the gate is mid-evaluation blocks the in-flight op", async () => {
    const key = await genKey();
    await pairAndPin(key);

    // Stall the gate's platform probe: the first pass has already read
    // compromised = null when the mark lands, so only the serialized re-check
    // can honor it. The old, unserialized gate dispatched from the stale
    // pre-mark answer.
    const runtime = (
      globalThis as unknown as {
        chrome: { runtime: { getPlatformInfo: () => Promise<{ os: string }> } };
      }
    ).chrome.runtime;
    const realProbe = runtime.getPlatformInfo;
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    runtime.getPlatformInfo = async () => {
      await held;
      return realProbe();
    };

    let dispatched = 0;
    const gateP = enrollmentGate(() => {
      dispatched += 1;
    });
    await new Promise((resolve) => setTimeout(resolve, 0)); // gate is parked on the probe
    await pinStore.setCompromised({ reason: "marked mid-gate", at: Date.now() });
    runtime.getPlatformInfo = realProbe;
    release();

    const gate = await gateP;
    expect(gate.allowed).toBe(false);
    if (!gate.allowed) expect(gate.reason).toContain("failed closed");
    expect(dispatched).toBe(0); // the op never began dispatching
  });

  test("a revoke queued during the confirming read runs strictly after the op began", async () => {
    const key = await genKey();
    await pairAndPin(key);

    // The last interleaving: the transition arrives AFTER the serialized
    // confirming read has started. The op is then ordered before the
    // transition by mechanism - its dispatch kickoff runs synchronously
    // inside the gate's critical section, so the queued revoke cannot apply
    // first. Stall the confirming read's platform probe (the second probe
    // call; the first pass takes the first) to queue the revoke mid-confirm.
    const runtime = (
      globalThis as unknown as {
        chrome: { runtime: { getPlatformInfo: () => Promise<{ os: string }> } };
      }
    ).chrome.runtime;
    const realProbe = runtime.getPlatformInfo;
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let probeCalls = 0;
    runtime.getPlatformInfo = async () => {
      probeCalls += 1;
      if (probeCalls === 2) await held; // park only the confirming read
      return realProbe();
    };

    const events: string[] = [];
    const gateP = enrollmentGate(() => {
      // Synchronous view from inside the critical section: the revoke queued
      // below must not have touched the store yet.
      events.push(store["enclavePin"] ? "dispatched-before-revoke" : "dispatched-after-revoke");
    });
    await new Promise((resolve) => setTimeout(resolve, 0)); // confirm is parked on the probe
    const revokeP = revokePin(); // queued behind the running confirm
    runtime.getPlatformInfo = realProbe;
    release();

    const gate = await gateP;
    await revokeP;
    expect(gate.allowed).toBe(true);
    expect(events).toEqual(["dispatched-before-revoke"]);
    // The revoke still applied afterwards: the pin is gone for the NEXT op.
    expect((await enrollmentGate()).allowed).toBe(false);
  });
});

describe("periodic re-verification (hostReverifyMs)", () => {
  test("default 0 never challenges after pinning", async () => {
    const key = await genKey();
    await pairAndPin(key);
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("a fresh pin is not re-challenged within the interval", async () => {
    const key = await genKey();
    await pairAndPin(key); // pinnedAt = now, counts as the last verification
    store["hostReverifyMs"] = 3_600_000;
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("a stale pin is re-challenged on connect and success refreshes the clock", async () => {
    const key = await genKey();
    await pairAndPin(key);
    store["hostReverifyMs"] = 1000;
    (store["enclavePin"] as { pinnedAt: number }).pinnedAt = Date.now() - 10_000;
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    const frame = posted[posted.length - 1];
    expect(frame.type).toBe("enclave_challenge");
    await handleEnclaveFrame(await proofFrame(key, nonce, context));
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect(typeof st.lastVerifiedAt).toBe("number");
    expect((await enrollmentGate()).allowed).toBe(true);
    // The successful verification satisfies the interval: no new challenge.
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("a stale re-verify answered by the wrong key fails closed", async () => {
    const key = await genKey();
    const attacker = await genKey();
    await pairAndPin(key);
    store["hostReverifyMs"] = 1000;
    (store["enclavePin"] as { pinnedAt: number }).pinnedAt = Date.now() - 10_000;
    await onPortConnected();
    const { nonce, context } = lastChallenge();
    await handleEnclaveFrame(await proofFrame(attacker, nonce, context));
    expect((await getEnrollmentStatus()).state).toBe("compromised");
    expect((await enrollmentGate()).allowed).toBe(false);
  });

  test("an unanswered periodic prompt leaves the pinned state and gate unchanged", async () => {
    const key = await genKey();
    await pairAndPin(key);
    store["hostReverifyMs"] = 1000;
    (store["enclavePin"] as { pinnedAt: number }).pinnedAt = Date.now() - 10_000;
    await onPortConnected(); // challenge out
    // The user cancels the presence prompt: the host reports signing_failed.
    await handleEnclaveFrame({ type: "enclave_error", reason: "signing_failed" });
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("pinned");
    expect((await enrollmentGate()).allowed).toBe(true);
  });

  test("a newer lastVerifiedAt outweighs an old pinnedAt", async () => {
    const key = await genKey();
    await pairAndPin(key);
    store["hostReverifyMs"] = 1000;
    (store["enclavePin"] as { pinnedAt: number }).pinnedAt = Date.now() - 10_000;
    store["enclaveLastVerifiedAt"] = Date.now(); // verified just now
    const before = posted.length;
    await onPortConnected();
    expect(posted.length).toBe(before);
  });

  test("an outstanding challenge suppresses a duplicate periodic challenge", async () => {
    const key = await genKey();
    await pairAndPin(key);
    store["hostReverifyMs"] = 1000;
    (store["enclavePin"] as { pinnedAt: number }).pinnedAt = Date.now() - 10_000;
    await onPortConnected(); // first stale connect: challenge goes out
    const before = posted.length;
    await onPortConnected(); // second connect while unanswered: no duplicate
    expect(posted.length).toBe(before);
  });
});

describe("platform scoping (non-Enclave platforms)", () => {
  test("on linux, enrollment is unavailable: gate open, no ceremony, honest status", async () => {
    mockOs = "linux";
    expect((await enrollmentGate()).allowed).toBe(true); // requireEnrollment default true
    await onPortConnected();
    expect(posted.length).toBe(0); // no challenge ever issued
    const st = await getEnrollmentStatus();
    expect(st.platformSupported).toBe(false);
    expect(st.state).toBe("unpaired");
    expect(st.blocked).toBe(false);
  });

  test("on windows, pairing and verify actions refuse rather than challenge", async () => {
    mockOs = "win";
    const pair = await startPairing();
    expect(pair.ok).toBe(false);
    expect(pair.error).toContain("unavailable");
    const verify = await verifyPinnedNow();
    expect(verify.ok).toBe(false);
    expect(posted.length).toBe(0);
  });

  test("only the browser's probe decides: the host's unsupported claim cannot open a mac gate", async () => {
    // mockOs stays "mac". Even after the host answers unsupported_platform,
    // the gate must keep blocking - otherwise a substituted host could dodge
    // enrollment by lying about the platform.
    await onPortConnected();
    await handleEnclaveFrame({ type: "enclave_error", reason: "unsupported_platform" });
    expect((await enrollmentGate()).allowed).toBe(false);
    expect((await getEnrollmentStatus()).platformSupported).toBe(true);
  });

  test("a failing platform probe fails closed (gate still enforces)", async () => {
    (
      globalThis as unknown as { chrome: { runtime: { getPlatformInfo: () => Promise<never> } } }
    ).chrome.runtime.getPlatformInfo = () => Promise.reject(new Error("probe failed"));
    expect((await enrollmentGate()).allowed).toBe(false);
    expect((await getEnrollmentStatus()).platformSupported).toBe(true);
  });

  test("a compromised mark still blocks regardless of platform", async () => {
    mockOs = "linux";
    store["enclaveCompromised"] = { reason: "test", at: Date.now() };
    expect((await enrollmentGate()).allowed).toBe(false);
    // The status must report the truth so the UI renders the compromised
    // panel (with its revoke control), not the platform-N/A panel.
    const st = await getEnrollmentStatus();
    expect(st.state).toBe("compromised");
    expect(st.blocked).toBe(true);
  });
});
