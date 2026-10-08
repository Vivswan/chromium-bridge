// The options page's host-admin exchanges, extension side: request/reply correlation over the native-messaging
// port for the registration rows (status and repair share the host's one result tag), the policy restriction
// lane, and the host audit trail, the fail-closed deadline, and the unsolicited-frame drops. The host side (the
// resolver read, the fix, the restriction seam, the trail reader) is covered by the Rust unit tests.

import type { AuditTrailEntry, RegistrationRow } from "@genkan/shared/generated/envelope";
import { POLICY_DEFAULTS } from "@genkan/shared/generated/policy";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  collaborator,
  handleHostAdminFrame,
  repairRegistration,
  requestHostAudit,
  requestPolicyHistory,
  requestRegistrationStatus,
  restrictPolicy,
} from "@/lib/background/host-admin";
import {
  assertPresence,
  beginAct,
  handleWebAuthnFrame,
  resetWebAuthnForTests,
  collaborator as webauthn,
} from "@/lib/webauthn/exchange";
import { attach } from "./fake-connection";

let posted: Array<Record<string, unknown>>;

function reattach(): void {
  const post = (frame: object) => {
    posted.push(frame as Record<string, unknown>);
    return true;
  };
  attach(collaborator, post);
  attach(webauthn, post);
}

beforeEach(() => {
  posted = [];
  collaborator.onDetach();
  resetWebAuthnForTests();
  reattach();
});

afterEach(() => {
  collaborator.onDetach();
  resetWebAuthnForTests();
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
  { entry: "record", ts_ms: 3000, kind: "pair_client", fields: "surface=cli outcome=ok" },
  { entry: "unrecognized", text: "UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)" },
];

const trailResult = {
  type: "audit_read_result" as const,
  ok: true,
  entries: TRAIL,
  older: 1,
  path: "/run/user/1000/genkan/audit.log",
};

/** Narrow a discriminated view to its failure arm (throws if it succeeded). */
function failed(view: { ok: true } | { ok: false; error: string }): { ok: false; error: string } {
  if (view.ok) throw new Error("expected a failure view");
  return view;
}

describe("registration status and repair (one shared slot)", () => {
  // The requests differ only in the frame they put on the wire; the host answers all with one tag.
  test.each([
    { name: "status", request: requestRegistrationStatus, frame: { type: "registration_status" } },
    { name: "repair", request: () => repairRegistration(), frame: { type: "registration_repair" } },
    {
      name: "repair of named browsers",
      request: () => repairRegistration(["brave", "opera"]),
      frame: { type: "registration_repair", browsers: ["brave", "opera"] },
    },
  ])(
    "$name posts its frame and resolves with the rows the host reports",
    async ({ request, frame }) => {
      const p = request();
      expect(posted).toEqual([frame]);
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
  // A limitless read is the CLI's default page; a named limit is `audit --limit <n>` on the frame.
  test.each([
    { name: "limitless", request: () => requestHostAudit(), frame: { type: "audit_read" } },
    {
      name: "limit 600",
      request: () => requestHostAudit(600),
      frame: { type: "audit_read", limit: 600 },
    },
  ])(
    "a $name read posts its frame and resolves with the host's page",
    async ({ request, frame }) => {
      const p = request();
      expect(posted).toEqual([frame]);
      handleHostAdminFrame(trailResult);
      await expect(p).resolves.toEqual({
        ok: true,
        entries: TRAIL,
        older: 1,
        path: "/run/user/1000/genkan/audit.log",
      });
    },
  );

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

describe("the grant lanes behind the presence exchange", () => {
  const request = {
    type: "presence_request",
    challenge: "cHJlc2VuY2U",
    nonce: "nonce-0002",
    action: "set policy: pageEvalEnabled=on",
    allowed_credential_ids: ["Y3JlZC1h"],
  };
  const answer = {
    nonce: "nonce-0002",
    credential_id: "Y3JlZC1h",
    authenticator_data: "YXV0aA",
    client_data_json: "Y2Rq",
    signature: "c2ln",
  };

  test("a grant posts the overlay, is answered by the presence request, and its verdict follows the tap", async () => {
    const begun = beginAct({ type: "policy_set", overlay: { pageEvalEnabled: true } });
    expect(posted).toEqual([{ type: "policy_set", overlay: { pageEvalEnabled: true } }]);
    handleWebAuthnFrame(request as never);
    await expect(begun).resolves.toEqual({ ok: true, request });
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    handleHostAdminFrame({ type: "policy_set_result", ok: true });
    await expect(answered).resolves.toEqual({ ok: true });
  });

  test("a grant the host refuses before any request resolves with the host's words", async () => {
    const begun = beginAct({ type: "policy_set", overlay: { cdpMode: true } });
    handleHostAdminFrame({
      type: "policy_set_result",
      ok: false,
      error:
        "no host key on this machine; a policy grant is a signed baseline and refuses without one (pair first)",
    });
    expect(failed(await begun).error).toBe(
      "no host key on this machine; a policy grant is a signed baseline and refuses without one (pair first)",
    );
  });

  test("a rollback the host applies free resolves with no request; one that relaxes waits for the tap", async () => {
    const free = beginAct({ type: "policy_rollback", revision: 1 });
    expect(posted).toEqual([{ type: "policy_rollback", revision: 1 }]);
    handleHostAdminFrame({ type: "policy_rollback_result", ok: true });
    await expect(free).resolves.toEqual({ ok: true, request: null });

    const relaxing = beginAct({ type: "policy_rollback", revision: 2 });
    const rollbackRequest = {
      ...request,
      action: "roll policy back to revision 2: pageEvalEnabled=on",
    };
    handleWebAuthnFrame(rollbackRequest as never);
    await expect(relaxing).resolves.toEqual({ ok: true, request: rollbackRequest });
    const answered = assertPresence(answer);
    handleWebAuthnFrame({ type: "presence_result", ok: true });
    handleHostAdminFrame({
      type: "policy_rollback_result",
      ok: false,
      error: "the policy store changed while this write was pending",
    });
    expect(failed(await answered).error).toContain("changed while this write was pending");
  });

  test("a verdict the typed producer cannot emit is a refusal naming the frame, never a success", async () => {
    const begun = beginAct({ type: "policy_set", overlay: { cdpMode: true } });
    handleHostAdminFrame({ type: "policy_set_result", ok: true, error: "boom" } as never);
    expect(failed(await begun).error).toBe("malformed policy_set_result from host");
  });
});

describe("policy history", () => {
  test("round-trips the ring as the host reports it, and a refusal as its error", async () => {
    const entries = [
      {
        id: "a1",
        signed: true,
        overlay_active: false,
        superseded_unix: 20,
        held: { revision: 2, effective: POLICY_DEFAULTS },
      },
      { id: "b2", signed: false, overlay_active: true, superseded_unix: 21 },
    ];
    const p = requestPolicyHistory();
    expect(posted).toEqual([{ type: "policy_history" }]);
    handleHostAdminFrame({ type: "policy_history_result", ok: true, entries });
    await expect(p).resolves.toEqual({ ok: true, entries });
    // A record's revision and the policy it held are one value: a row carrying one without the other is not
    // the host's frame, so no reader downstream has to decide what half a record means.
    for (const held of [{ revision: 2 }, { effective: POLICY_DEFAULTS }]) {
      const half = requestPolicyHistory();
      handleHostAdminFrame({
        type: "policy_history_result",
        ok: true,
        entries: [{ ...entries[1], held }],
      } as never);
      expect(failed(await half).error).toBe("malformed policy_history_result from host");
    }
    const refused = requestPolicyHistory();
    handleHostAdminFrame({
      type: "policy_history_result",
      ok: false,
      error: "the policy history is unreadable",
    });
    expect(failed(await refused).error).toBe("the policy history is unreadable");
  });

  test("a row the host could not date is accepted as damaged; a timestamp past the JS-safe bound still fails the frame", async () => {
    // The host omits a timestamp it cannot represent (with what the record held) rather than emitting a number
    // the safe-integers reader rule refuses, so one damaged record no longer sinks every readable row. The rule
    // itself stays: a frame carrying such a number is not the host's.
    const dated = { id: "b2", signed: false, overlay_active: true, superseded_unix: 21 };
    const undated = { id: "c3", signed: true, overlay_active: false };
    const p = requestPolicyHistory();
    handleHostAdminFrame({ type: "policy_history_result", ok: true, entries: [undated, dated] });
    await expect(p).resolves.toEqual({ ok: true, entries: [undated, dated] });
    const past = requestPolicyHistory();
    handleHostAdminFrame({
      type: "policy_history_result",
      ok: true,
      entries: [{ ...dated, superseded_unix: Number.MAX_SAFE_INTEGER + 1 }],
    });
    expect(failed(await past).error).toBe("malformed policy_history_result from host");
  });
});

describe("fail-closed: every unanswered or unusable exchange resolves to a refusal", () => {
  // One axis varies (how the reply fails to arrive or to parse); every exchange takes every row.
  const exchanges = [
    { name: "status", request: requestRegistrationStatus, reply: rowsResult },
    {
      name: "restrict",
      request: () => restrictPolicy({ cdpMode: false }),
      reply: { type: "policy_restrict_result" as const, ok: true },
    },
    { name: "audit", request: requestHostAudit, reply: trailResult },
    {
      name: "history",
      request: requestPolicyHistory,
      reply: { type: "policy_history_result" as const, ok: true, entries: [] },
    },
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
