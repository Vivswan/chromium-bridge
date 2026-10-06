// The options page's host-admin exchanges, extension side: request/reply correlation over the native-messaging
// port for the registration rows (status and repair share the host's one result tag), the policy restriction
// lane, and the host audit trail, the fail-closed deadline, and the unsolicited-frame drops. The host side (the
// resolver read, the fix, the restriction seam, the trail reader) is covered by the Rust unit tests.

import type { AuditTrailEntry, RegistrationRow } from "@chromium-bridge/shared/envelope.gen";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  collaborator,
  handleHostAdminFrame,
  repairRegistration,
  requestHostAudit,
  requestRegistrationStatus,
  restrictPolicy,
} from "@/lib/background/host-admin";
import { attach } from "./fake-connection";

let posted: Array<Record<string, unknown>>;

function reattach(): void {
  attach(collaborator, (frame) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  });
}

beforeEach(() => {
  posted = [];
  collaborator.onDetach();
  reattach();
});

afterEach(() => {
  collaborator.onDetach();
  vi.useRealTimers();
});

const ROWS: RegistrationRow[] = [
  {
    browser: "chrome",
    detected: true,
    state: { kind: "ok" },
    location: "/home/user/.config/google-chrome/NativeMessagingHosts/host.json",
  },
  {
    browser: "brave",
    detected: false,
    state: { kind: "stale", detail: "launch path missing" },
    location: "/home/user/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/host.json",
  },
];

const rowsResult = { type: "registration_status_result" as const, ok: true, browsers: ROWS };

const TRAIL: AuditTrailEntry[] = [
  { entry: "record", ts_ms: 3000, kind: "pair_client", fields: " surface=cli outcome=ok" },
  { entry: "unrecognized", text: "UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)" },
];

const trailResult = {
  type: "audit_read_result" as const,
  ok: true,
  entries: TRAIL,
  older: 1,
  path: "/run/user/1000/chromium-bridge/audit.log",
};

/** Narrow a discriminated view to its failure arm (throws if it succeeded). */
function failed(view: { ok: true } | { ok: false; error: string }): { ok: false; error: string } {
  if (view.ok) throw new Error("expected a failure view");
  return view;
}

describe("registration status and repair (one shared slot)", () => {
  // The two requests differ only in the frame they put on the wire; the host answers both with one tag.
  test.each([
    { name: "status", request: requestRegistrationStatus, frame: "registration_status" },
    { name: "repair", request: repairRegistration, frame: "registration_repair" },
  ])(
    "$name posts its frame and resolves with the rows the host reports",
    async ({ request, frame }) => {
      const p = request();
      expect(posted).toEqual([{ type: frame }]);
      handleHostAdminFrame(rowsResult);
      await expect(p).resolves.toEqual({ ok: true, browsers: ROWS });
    },
  );

  test("a host-side failure (no HOME, a failed repair target) is the host's error text, never rows", async () => {
    const p = repairRegistration();
    handleHostAdminFrame({
      type: "registration_status_result",
      ok: false,
      error: "brave: permission denied",
    });
    expect(failed(await p).error).toBe("brave: permission denied");
  });

  test("a mixture the typed producer cannot emit (ok with an error) is refused, never read as success", async () => {
    // Before the ok-split readers, both frames parsed and resolved ok:true, silently dropping the error.
    const status = requestRegistrationStatus();
    handleHostAdminFrame({
      type: "registration_status_result",
      ok: true,
      browsers: ROWS,
      error: "HOME is not set",
    });
    expect(failed(await status).error).toContain("malformed");
    const restrict = restrictPolicy({ evalMask: true });
    handleHostAdminFrame({ type: "policy_restrict_result", ok: true, error: "restriction failed" });
    expect(failed(await restrict).error).toContain("malformed");
  });

  test("status and repair share the slot: a second request while one is outstanding is refused", async () => {
    const first = requestRegistrationStatus();
    expect(failed(await repairRegistration()).error).toContain("in flight");
    handleHostAdminFrame(rowsResult);
    expect((await first).ok).toBe(true);
    expect(posted).toEqual([{ type: "registration_status" }]);
  });
});

describe("host audit trail", () => {
  test("posts a limitless audit_read (the CLI's default page) and resolves with the host's page", async () => {
    const p = requestHostAudit();
    expect(posted).toEqual([{ type: "audit_read" }]);
    handleHostAdminFrame(trailResult);
    await expect(p).resolves.toEqual({
      ok: true,
      entries: TRAIL,
      older: 1,
      path: "/run/user/1000/chromium-bridge/audit.log",
    });
  });

  test("an unreadable trail is the host's error text, and a page beside an error is refused", async () => {
    const unreadable = requestHostAudit();
    handleHostAdminFrame({
      type: "audit_read_result",
      ok: false,
      error: "cannot read audit.log: permission denied",
    });
    expect(failed(await unreadable).error).toBe("cannot read audit.log: permission denied");
    const mixed = requestHostAudit();
    handleHostAdminFrame({ ...trailResult, error: "e" });
    expect(failed(await mixed).error).toContain("malformed");
  });
});

describe("policy restriction", () => {
  test("posts exactly the overlay the page asked for and reads the verdict", async () => {
    const p = restrictPolicy({ pageEvalEnabled: false, disabledTools: ["page_eval"] });
    expect(posted).toEqual([
      {
        type: "policy_restrict",
        overlay: { pageEvalEnabled: false, disabledTools: ["page_eval"] },
      },
    ]);
    handleHostAdminFrame({ type: "policy_restrict_result", ok: true });
    await expect(p).resolves.toEqual({ ok: true });

    const refused = restrictPolicy({ pageEvalEnabled: true });
    handleHostAdminFrame({
      type: "policy_restrict_result",
      ok: false,
      error: "the overlay would relax the current effective policy",
    });
    expect(failed(await refused).error).toContain("relax");
  });
});

describe("the slots are independent", () => {
  // One request outstanding on the first slot, the second answered first: neither waits on the other.
  const slots = {
    status: { request: requestRegistrationStatus, reply: rowsResult },
    restrict: {
      request: () => restrictPolicy({ evalMask: true }),
      reply: { type: "policy_restrict_result" as const, ok: true },
    },
    audit: { request: requestHostAudit, reply: trailResult },
  };
  test.each([
    { first: "restrict", second: "status" },
    { first: "status", second: "audit" },
  ] as const)("a $first in flight does not block a $second", async ({ first, second }) => {
    const blocked = slots[first].request();
    const other = slots[second].request();
    handleHostAdminFrame(slots[second].reply);
    expect((await other).ok).toBe(true);
    handleHostAdminFrame(slots[first].reply);
    expect((await blocked).ok).toBe(true);
  });
});

describe("fail-closed: every unanswered or unusable exchange resolves to a refusal", () => {
  // One axis varies (how the reply fails to arrive or to parse); both exchanges take every row.
  const exchanges = [
    { name: "status", request: requestRegistrationStatus, reply: rowsResult },
    {
      name: "restrict",
      request: () => restrictPolicy({ cdpMode: false }),
      reply: { type: "policy_restrict_result" as const, ok: true },
    },
    { name: "audit", request: requestHostAudit, reply: trailResult },
  ];
  const failures = [
    {
      name: "no port",
      arrange: () => collaborator.onDetach(),
      act: (_reply: object) => {},
      error: "not connected",
    },
    {
      name: "a reply missing its required fields",
      arrange: () => {},
      act: (reply: object) =>
        handleHostAdminFrame({ type: (reply as { type: string }).type } as never),
      error: "malformed",
    },
    {
      name: "no reply before the deadline",
      arrange: () => vi.useFakeTimers(),
      act: () => vi.advanceTimersByTime(10_001),
      error: "timed out",
    },
    {
      name: "the port disconnects while the request is outstanding",
      arrange: () => {},
      act: () => collaborator.onDetach(),
      error: "disconnected",
    },
  ];
  test.each(exchanges.flatMap((e) => failures.map((f) => ({ ...f, exchange: e }))))(
    "$exchange.name: $name",
    async ({ exchange, arrange, act, error }) => {
      arrange();
      const p = exchange.request();
      act(exchange.reply);
      expect(failed(await p).error).toContain(error);
    },
  );

  test("an unsolicited result is dropped and the next request still round-trips", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    handleHostAdminFrame(rowsResult);
    handleHostAdminFrame({ type: "policy_restrict_result", ok: true });
    handleHostAdminFrame(trailResult);
    // The connection and the slots are untouched: a fresh request posts and settles on its own reply.
    const p = requestRegistrationStatus();
    expect(posted).toEqual([{ type: "registration_status" }]);
    handleHostAdminFrame(rowsResult);
    await expect(p).resolves.toEqual({ ok: true, browsers: ROWS });
  });
});
