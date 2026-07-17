// The ADR-0025 trusted-client admin exchange, extension side: request/reply
// correlation over the native-messaging port, the fail-closed timeout, and
// the unsolicited-frame drops. The host side (allowlist rewrite + epoch bump)
// is covered by the Rust unit tests and the python e2e/adversarial suites.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  attachPort,
  detachPort,
  handleAdminFrame,
  isAdminFrame,
  requestClientList,
  revokeTrustedClient,
} from "@/lib/background/clients";

let posted: Array<Record<string, unknown>>;

beforeEach(() => {
  posted = [];
  detachPort(); // resolve any leftover pending from a prior test
  attachPort((frame) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  });
});

afterEach(() => {
  detachPort();
  vi.useRealTimers();
});

const listResult = {
  type: "client_list_result" as const,
  ok: true,
  enrolled: true,
  clients: [
    { name: "claude-code", anchor: { kind: "team_id", value: "3ZMH96L4V9" }, added_unix: 42 },
  ],
};

describe("frame classification", () => {
  test("recognizes exactly the two admin result tags", () => {
    expect(isAdminFrame(listResult)).toBe(true);
    expect(isAdminFrame({ type: "client_revoke_result", ok: true })).toBe(true);
    // Requests, enclave frames, and bridge traffic do not classify here.
    expect(isAdminFrame({ type: "client_list" })).toBe(false);
    expect(isAdminFrame({ type: "client_revoke", name: "x" })).toBe(false);
    expect(isAdminFrame({ type: "enclave_error", reason: "r" })).toBe(false);
    expect(isAdminFrame({ id: 1, op: "tab_list" })).toBe(false);
    expect(isAdminFrame(null)).toBe(false);
  });
});

describe("client list", () => {
  test("round-trips a successful list", async () => {
    const p = requestClientList();
    expect(posted).toEqual([{ type: "client_list" }]);
    handleAdminFrame(listResult);
    const view = await p;
    expect(view.ok).toBe(true);
    expect(view.enrolled).toBe(true);
    expect(view.clients?.[0]?.name).toBe("claude-code");
    expect(view.clients?.[0]?.anchor.kind).toBe("team_id");
  });

  test("surfaces a host-side failure (tamper case) as ok:false", async () => {
    const p = requestClientList();
    handleAdminFrame({
      type: "client_list_result",
      ok: false,
      enrolled: true,
      clients: [],
      error: "clients.json is missing but this machine has enrolled trusted clients",
    });
    const view = await p;
    expect(view.ok).toBe(false);
    expect(view.error).toContain("missing");
  });

  test("fails closed without a port and on a malformed reply", async () => {
    detachPort();
    expect((await requestClientList()).ok).toBe(false);

    attachPort((frame) => {
      posted.push(frame as Record<string, unknown>);
      return true;
    });
    const p = requestClientList();
    // Missing the required booleans/array: refused, never guessed at.
    handleAdminFrame({ type: "client_list_result" } as never);
    const view = await p;
    expect(view.ok).toBe(false);
    expect(view.error).toContain("malformed");
  });

  test("an unanswered request times out to a refusal (never hangs)", async () => {
    vi.useFakeTimers();
    const p = requestClientList();
    vi.advanceTimersByTime(10_001);
    const view = await p;
    expect(view.ok).toBe(false);
    expect(view.error).toContain("timed out");
  });

  test("port disconnect resolves the pending request as a refusal", async () => {
    const p = requestClientList();
    detachPort();
    const view = await p;
    expect(view.ok).toBe(false);
    expect(view.error).toContain("disconnected");
  });

  test("an unsolicited result is dropped without touching state", () => {
    // Nothing outstanding: the frame must be ignored (a replay, or an
    // injected frame the host-side filter somehow missed).
    handleAdminFrame(listResult);
    expect(posted).toEqual([]);
  });
});

describe("client revoke", () => {
  test("round-trips success and failure", async () => {
    const p = revokeTrustedClient("claude-code");
    expect(posted).toEqual([{ type: "client_revoke", name: "claude-code" }]);
    handleAdminFrame({ type: "client_revoke_result", ok: true });
    expect((await p).ok).toBe(true);

    const p2 = revokeTrustedClient("ghost");
    handleAdminFrame({
      type: "client_revoke_result",
      ok: false,
      error: "no trusted client named 'ghost'",
    });
    const r2 = await p2;
    expect(r2.ok).toBe(false);
    expect(r2.error).toContain("ghost");
  });

  test("only one revoke may be outstanding", async () => {
    const p = revokeTrustedClient("a");
    const second = await revokeTrustedClient("b");
    expect(second.ok).toBe(false);
    expect(second.error).toContain("in flight");
    handleAdminFrame({ type: "client_revoke_result", ok: true });
    expect((await p).ok).toBe(true);
  });
});
