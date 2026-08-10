// The native-link state machine (background/port.ts): the link is exactly
// one of connected / reconnect-scheduled / down, held as one value. These
// guards pin the two interleavings the old port/portOk/timer trio got
// wrong: a re-entrant connect that throws must not leave the OLD port
// half-alive behind a state that reads down, and the late disconnect of a
// port a re-entry already replaced must not tear down the live link.
//
// Residual gap: reconnect behavior against a real native host (Chrome
// killing the host process when the Port drops, backoff pacing) can only be
// proven in an isolated browser - the checks.yml browser job covers that.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

// Collaborator surfaces the port hands the fresh postFrame to. Mocked so
// the link lifecycle runs in isolation (dynamic import below, so these
// consts exist before the factories run).
const enrollment = {
  attachPort: vi.fn(),
  detachPort: vi.fn(),
  // Mirrors the real gate on the allowed path: the dispatch kickoff runs
  // inside the gate before it resolves.
  enrollmentGate: vi.fn((onAllowed?: () => void) => {
    onAllowed?.();
    return Promise.resolve({ allowed: true });
  }),
  handleEnclaveFrame: vi.fn(() => Promise.resolve()),
  isEnclaveFrame: vi.fn(() => false),
  onPortConnected: vi.fn(() => Promise.resolve()),
};
const clients = {
  attachPort: vi.fn(),
  detachPort: vi.fn(),
  isAdminFrame: vi.fn(() => false),
  handleAdminFrame: vi.fn(),
};
const kill = {
  attachPort: vi.fn(),
  detachPort: vi.fn(),
  isKillStatusFrame: vi.fn(() => false),
  handleKillFrame: vi.fn(() => Promise.resolve()),
  requestKillStatus: vi.fn(() => Promise.resolve()),
};
const auditLog = { attachPort: vi.fn(), detachPort: vi.fn() };
const presence = {
  attachPort: vi.fn(),
  detachPort: vi.fn(),
  isPresenceFrame: vi.fn(() => false),
  handlePresenceFrame: vi.fn(),
};
const dispatch = vi.fn((_req: unknown) => Promise.resolve({}));
const runtime = {
  connectNative: vi.fn<() => FakePort>(),
  lastError: undefined as { message?: string } | undefined,
};

vi.mock("@/lib/background/enrollment", () => enrollment);
vi.mock("@/lib/background/clients", () => clients);
vi.mock("@/lib/background/kill", () => kill);
vi.mock("@/lib/background/audit-log", () => auditLog);
vi.mock("@/lib/background/confirm/presence", () => presence);
vi.mock("@/lib/background/dispatch", () => ({ dispatch }));
vi.mock("wxt/browser", () => ({ browser: { runtime } }));

interface FakePort {
  postMessage: ReturnType<typeof vi.fn>;
  disconnect: ReturnType<typeof vi.fn>;
  onMessage: { addListener: (f: (msg: unknown) => void) => void };
  onDisconnect: { addListener: (f: (p: unknown) => void) => void };
  /** Fire this port's onDisconnect listeners (the host side dropping). */
  emitDisconnect: () => void;
  /** Fire this port's onMessage listeners (a frame the host delivered). */
  emitMessage: (msg: unknown) => void;
}

function makePort(): FakePort {
  const disconnectListeners: Array<(p: unknown) => void> = [];
  const messageListeners: Array<(msg: unknown) => void> = [];
  const port: FakePort = {
    postMessage: vi.fn(),
    disconnect: vi.fn(),
    onMessage: { addListener: (f) => messageListeners.push(f) },
    onDisconnect: { addListener: (f) => disconnectListeners.push(f) },
    emitDisconnect: () => {
      for (const f of [...disconnectListeners]) f(port);
    },
    emitMessage: (msg) => {
      for (const f of [...messageListeners]) f(msg);
    },
  };
  return port;
}

type PortModule = typeof import("@/lib/background/port");
let mod: PortModule;

beforeEach(async () => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.resetModules();
  mod = await import("@/lib/background/port");
});

afterEach(() => {
  vi.useRealTimers();
});

/** The postFrame the last connect handed the collaborators. */
function lastPostFrame(): (frame: object) => boolean {
  const call = enrollment.attachPort.mock.calls.at(-1);
  if (!call) throw new Error("attachPort was never called");
  return call[0] as (frame: object) => boolean;
}

describe("native link lifecycle", () => {
  test("a successful connect reports connected and wires every surface", () => {
    const port = makePort();
    runtime.connectNative.mockReturnValueOnce(port);
    mod.connectNative();
    expect(mod.isNativeConnected()).toBe(true);
    for (const m of [enrollment, clients, kill, auditLog, presence]) {
      expect(m.attachPort).toHaveBeenCalledTimes(1);
    }
    expect(kill.requestKillStatus).toHaveBeenCalledTimes(1);
    expect(lastPostFrame()({ type: "x" })).toBe(true);
    expect(port.postMessage).toHaveBeenCalledWith({ type: "x" });
  });

  test("a failed connect reports down and retries on the backoff timer", async () => {
    runtime.connectNative.mockImplementationOnce(() => {
      throw new Error("no host");
    });
    mod.connectNative();
    expect(mod.isNativeConnected()).toBe(false);
    const port = makePort();
    runtime.connectNative.mockReturnValueOnce(port);
    await vi.advanceTimersByTimeAsync(2000);
    expect(runtime.connectNative).toHaveBeenCalledTimes(2);
    expect(mod.isNativeConnected()).toBe(true);
  });

  test("a re-entrant connect that throws leaves NO half-alive old port", () => {
    // The invalid state the old port/portOk pair could represent: connect
    // succeeds (port A), a re-entrant connect throws, and A stayed assigned
    // while the module reported disconnected - frames kept flowing out of a
    // link that claimed to be down.
    const portA = makePort();
    runtime.connectNative.mockReturnValueOnce(portA);
    mod.connectNative();
    const postViaA = lastPostFrame();

    runtime.connectNative.mockImplementationOnce(() => {
      throw new Error("host vanished");
    });
    mod.connectNative();
    expect(mod.isNativeConnected()).toBe(false);
    // The old port was consumed by the transition, not orphaned.
    expect(portA.disconnect).toHaveBeenCalledTimes(1);
    // And the down state refuses to post - state and behavior agree.
    portA.postMessage.mockClear();
    expect(postViaA({ type: "x" })).toBe(false);
    expect(portA.postMessage).not.toHaveBeenCalled();
  });

  test("a replaced port's late disconnect cannot tear down the live link", async () => {
    const portA = makePort();
    const portB = makePort();
    runtime.connectNative.mockReturnValueOnce(portA).mockReturnValueOnce(portB);
    mod.connectNative();
    mod.connectNative(); // re-entry: B replaces A
    expect(mod.isNativeConnected()).toBe(true);
    expect(portA.disconnect).toHaveBeenCalledTimes(1);

    // The stale port's disconnect event arrives late (host side winding
    // down). It must be ignored: the live link stays up, no surface is
    // detached, no reconnect is scheduled.
    enrollment.detachPort.mockClear();
    portA.emitDisconnect();
    expect(mod.isNativeConnected()).toBe(true);
    expect(enrollment.detachPort).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2000);
    expect(runtime.connectNative).toHaveBeenCalledTimes(2); // no reconnect fired
  });

  test("the CURRENT port disconnecting detaches every surface and reconnects", async () => {
    const portA = makePort();
    runtime.connectNative.mockReturnValueOnce(portA);
    mod.connectNative();
    portA.emitDisconnect();
    expect(mod.isNativeConnected()).toBe(false);
    for (const m of [enrollment, clients, kill, auditLog, presence]) {
      expect(m.detachPort).toHaveBeenCalledTimes(1);
    }
    const portB = makePort();
    runtime.connectNative.mockReturnValueOnce(portB);
    await vi.advanceTimersByTimeAsync(2000);
    expect(mod.isNativeConnected()).toBe(true);
  });

  test("a failed re-entrant connect detaches every collaborator bound to the old port", async () => {
    // Codex blocking 2: teardownLink used to disconnect the old port but
    // leave the collaborators (presence, kill, ...) attached to it. A frame
    // Chrome had already queued on that port could then still reach presence,
    // whose stale attachment matched, and APPROVE while the link read down.
    // Teardown must detach the collaborators in the same transition.
    const portA = makePort();
    runtime.connectNative.mockReturnValueOnce(portA);
    mod.connectNative();
    for (const m of [enrollment, clients, kill, auditLog, presence]) m.detachPort.mockClear();

    runtime.connectNative.mockImplementationOnce(() => {
      throw new Error("host vanished");
    });
    mod.connectNative(); // re-entrant connect throws: teardown then reconnect
    expect(mod.isNativeConnected()).toBe(false);
    for (const m of [enrollment, clients, kill, auditLog, presence]) {
      expect(m.detachPort).toHaveBeenCalledTimes(1);
    }
    await vi.advanceTimersByTimeAsync(2000);
  });

  test("a frame arriving on a stale port is dropped before the demux", async () => {
    // The inbound twin of the disconnect identity gate: after a re-entrant
    // connect replaces port A with B, a frame Chrome still delivers on A must
    // not be routed to any collaborator - only the live port's frames are.
    const portA = makePort();
    const portB = makePort();
    runtime.connectNative.mockReturnValueOnce(portA).mockReturnValueOnce(portB);
    mod.connectNative();
    mod.connectNative(); // B replaces A
    presence.isPresenceFrame.mockReturnValue(true);

    portA.emitMessage({ type: "presence_proof" });
    expect(presence.handlePresenceFrame).not.toHaveBeenCalled();

    // The live port's frame IS routed.
    portB.emitMessage({ type: "presence_proof" });
    expect(presence.handlePresenceFrame).toHaveBeenCalledTimes(1);
  });

  test("an unrecognized policy_current push is dropped without touching the link", async () => {
    // ADR-0032 decision 8 pins the old-extension assumption: this router,
    // which knows nothing of policy frames, must ignore a policy_current
    // push - nothing posted back, the port never torn down - and keep
    // serving bridge requests on the same port. Without this, an old
    // extension against a policy-capable host would break at every connect.
    presence.isPresenceFrame.mockReturnValue(false);
    const port = makePort();
    runtime.connectNative.mockReturnValueOnce(port);
    mod.connectNative();

    port.emitMessage({ type: "policy_current", ok: true, baseline: "YmFzZQ==" });
    expect(port.postMessage).not.toHaveBeenCalled();
    expect(port.disconnect).not.toHaveBeenCalled();
    expect(mod.isNativeConnected()).toBe(true);

    // A well-formed BridgeReq on the same port still dispatches, and its
    // response goes out on the still-connected link.
    port.emitMessage({ id: 1, op: "tab_list", args: {} });
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(dispatch).toHaveBeenCalledWith(expect.objectContaining({ id: 1, op: "tab_list" }));
    await vi.advanceTimersByTimeAsync(0);
    expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({ id: 1, ok: true }));
  });
});
