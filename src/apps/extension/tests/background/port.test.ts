// The native-link state machine (background/port.ts): the link is exactly
// one of connected / reconnect-scheduled / down, held as one value, and every
// module bound to it attaches and detaches through the collaborator registry
// in the same transition. These guards pin the interleavings the old
// port/portOk/timer trio and the hand-kept attach lists got wrong: a
// re-entrant connect that throws must not leave the OLD port half-alive
// behind a state that reads down, a teardown must detach every collaborator
// (a presence proof once APPROVED on a torn-down link), and the late
// disconnect of a port a re-entry already replaced must not tear down the
// live link.
//
// Residual gap: reconnect behavior against a real native host (Chrome
// killing the host process when the Port drops, backoff pacing) can only be
// proven in an isolated browser - the checks.yml browser job covers that.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { Connection } from "@/lib/background/connection";

// The collaborator modules are mocked so the link lifecycle runs in isolation
// (dynamic import below, so these consts exist before the factories run).
// Each mock registers the same hook set the real module exports.
function mockCollaborator() {
  return {
    onAttach: vi.fn<(conn: Connection) => void>(),
    onDetach: vi.fn(),
    onFrame: vi.fn<(frame: unknown) => boolean>(() => false),
  };
}
const enrollment = {
  collaborator: mockCollaborator(),
  // Mirrors the real gate on the allowed path: the dispatch kickoff runs
  // inside the gate before it resolves.
  enrollmentGate: vi.fn((onAllowed?: () => void) => {
    onAllowed?.();
    return Promise.resolve({ allowed: true });
  }),
  onPortConnected: vi.fn(() => Promise.resolve()),
};
const clients = { collaborator: mockCollaborator() };
const kill = {
  collaborator: mockCollaborator(),
  requestKillStatus: vi.fn(() => Promise.resolve()),
};
const auditLog = { collaborator: mockCollaborator() };
const presence = { collaborator: mockCollaborator() };
const policySync = { collaborator: mockCollaborator() };
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
vi.mock("@/lib/background/policy-sync", () => policySync);
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

/** Connect on a fresh fake port and return it. */
function connect(): FakePort {
  const port = makePort();
  runtime.connectNative.mockReturnValueOnce(port);
  mod.connectNative();
  return port;
}

/** The Connection the last connect handed each registry entry, in registry order. */
function handedConnections(): Connection[][] {
  return mod.collaborators.map((c) => vi.mocked(c.onAttach).mock.calls.map((call) => call[0]));
}

function detachCounts(): number[] {
  return mod.collaborators.map((c) => vi.mocked(c.onDetach).mock.calls.length);
}

/** Every registry entry, once. */
function once(): number[] {
  return mod.collaborators.map(() => 1);
}

describe("native link lifecycle", () => {
  test("a successful connect hands ONE Connection to every registered collaborator, and it posts on the live port", () => {
    const port = connect();
    expect(mod.isNativeConnected()).toBe(true);
    const handed = handedConnections();
    expect(handed.map((h) => h.length)).toEqual(once());
    expect(new Set(handed.flat()).size).toBe(1);
    const conn = handed[0]?.[0];
    expect(conn?.post({ type: "x" })).toBe(true);
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

  // teardownLink once disconnected the old port but left the collaborators
  // (presence, kill, ...) attached to it. A frame Chrome
  // had already queued on that port could then still reach presence, whose
  // stale attachment matched, and APPROVE while the link read down. And the
  // old port/portOk pair could hold port A assigned while the module reported
  // disconnected, so frames kept flowing out of a link that claimed to be
  // down. Every teardown path must detach the whole registry in the same
  // transition and leave the old Connection unable to post anywhere.
  test.each([
    {
      name: "the current port disconnecting",
      teardown: (portA: FakePort) => {
        portA.emitDisconnect();
        return null;
      },
      connectedAfter: false,
    },
    {
      name: "a re-entrant connect that throws",
      teardown: () => {
        runtime.connectNative.mockImplementationOnce(() => {
          throw new Error("host vanished");
        });
        mod.connectNative();
        return null;
      },
      connectedAfter: false,
    },
    {
      name: "a re-entrant connect that succeeds",
      teardown: () => connect(),
      connectedAfter: true,
    },
  ])(
    "$name detaches every collaborator in the same transition and strands the old Connection",
    async ({ teardown, connectedAfter }) => {
      const portA = connect();
      const connA = handedConnections()[0]?.[0];
      if (!connA) throw new Error("connect handed no Connection");

      const portB = teardown(portA);
      expect(mod.isNativeConnected()).toBe(connectedAfter);
      expect(detachCounts()).toEqual(once());
      expect(portA.disconnect).toHaveBeenCalledTimes(1);
      // The torn-down Connection refuses, and the frame reaches neither pipe.
      portA.postMessage.mockClear();
      expect(connA.post({ type: "x" })).toBe(false);
      expect(portA.postMessage).not.toHaveBeenCalled();
      if (portB) expect(portB.postMessage).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(2000);
    },
  );

  test("a replaced port's late disconnect cannot tear down the live link", async () => {
    const portA = connect();
    connect(); // re-entry: B replaces A
    expect(mod.isNativeConnected()).toBe(true);
    expect(portA.disconnect).toHaveBeenCalledTimes(1);

    // The stale port's disconnect event arrives late (host side winding
    // down). It must be ignored: the live link stays up, no surface is
    // detached, no reconnect is scheduled.
    for (const c of mod.collaborators) vi.mocked(c.onDetach).mockClear();
    portA.emitDisconnect();
    expect(mod.isNativeConnected()).toBe(true);
    expect(detachCounts()).toEqual(mod.collaborators.map(() => 0));
    await vi.advanceTimersByTimeAsync(2000);
    expect(runtime.connectNative).toHaveBeenCalledTimes(2); // no reconnect fired
  });

  test("a frame arriving on a stale port is dropped before the demux", () => {
    // The inbound twin of the disconnect identity gate: after a re-entrant
    // connect replaces port A with B, a frame Chrome still delivers on A must
    // not be offered to any collaborator - only the live port's frames are.
    const portA = connect();
    const portB = connect(); // B replaces A
    presence.collaborator.onFrame.mockReturnValueOnce(true);

    portA.emitMessage({ type: "presence_proof" });
    for (const c of mod.collaborators) expect(c.onFrame).not.toHaveBeenCalled();

    // The live port's frame IS routed.
    portB.emitMessage({ type: "presence_proof" });
    expect(presence.collaborator.onFrame).toHaveBeenCalledTimes(1);
  });

  test("an unrecognized push frame is dropped without touching the link", async () => {
    // A push no collaborator claims and that is not a bridge request must be
    // ignored - nothing posted back, the port never torn down - and bridge
    // requests keep flowing on the same port. Without this, an extension one
    // release behind a frame-adding host would break at every connect.
    const port = connect();

    port.emitMessage({ type: "future_push", ok: true, payload: "YmFzZQ==" });
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

  test("a claimed control frame never reaches the request parse or the gates", () => {
    // Control frames route ahead of parseBridgeReq/enrollmentGate, so a
    // killed or unenrolled bridge still processes pushes and the dispatch
    // barrier can open on the very connection it gates. Nothing is posted
    // back and nothing reaches dispatch.
    policySync.collaborator.onFrame.mockReturnValueOnce(true);
    const port = connect();

    const frame = { type: "policy_current", ok: true, baseline: "YmFzZQ==" };
    port.emitMessage(frame);
    expect(policySync.collaborator.onFrame).toHaveBeenCalledWith(frame);
    expect(enrollment.enrollmentGate).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    expect(port.postMessage).not.toHaveBeenCalled();
  });

  test("a bridge response rides the connection its request arrived on, never a successor's", async () => {
    // Chrome spawns a fresh host process per port: the host that asked is
    // gone with its connection, and the successor never issued the id, so a
    // reply that settles after a reconnect must reach neither pipe.
    let finish!: () => void;
    dispatch.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = () => resolve({});
        }),
    );
    const portA = connect();
    portA.emitMessage({ id: 7, op: "tab_list", args: {} });
    expect(dispatch).toHaveBeenCalledTimes(1);

    const portB = connect(); // the host restarted mid-request
    finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(portA.postMessage).not.toHaveBeenCalled();
    expect(portB.postMessage).not.toHaveBeenCalled();
  });
});
