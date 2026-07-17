// The native-messaging boundary, exercised adversarially: parseBridgeReq must
// refuse anything that is not a well-formed, catalogued, correctly-argued
// bridge request - and must keep working for everything the host actually
// sends. This is the proof that the runtime validation fails closed.

import { describe, expect, test } from "bun:test";
import { BridgeReqSchema, BridgeRespSchema, parseBridgeReq } from "./envelope";

function refusal(msg: unknown): { id?: number | string; error: string } {
  const parsed = parseBridgeReq(msg);
  if (parsed.ok) throw new Error(`expected refusal, got ok for ${JSON.stringify(msg)}`);
  return parsed;
}

describe("parseBridgeReq accepts what the host sends", () => {
  test("a plain tab op", () => {
    const parsed = parseBridgeReq({ id: 1, op: "tab_focus", args: { tabId: 7 } });
    expect(parsed.ok).toBe(true);
    if (parsed.ok && parsed.req.op === "tab_focus") {
      expect(parsed.req.id).toBe(1);
      expect(parsed.req.args.tabId).toBe(7);
    }
  });

  test("optional envelope fields (tabId, browser) and empty args", () => {
    const parsed = parseBridgeReq({ id: 2, op: "page_text", tabId: 3, browser: "brave", args: {} });
    expect(parsed.ok).toBe(true);
  });

  test("a string id (forward-compat per the contract)", () => {
    const parsed = parseBridgeReq({ id: "req-9", op: "tab_list", args: {} });
    expect(parsed.ok).toBe(true);
  });

  test("optional args omitted (page_click with neither ref nor selector)", () => {
    // The contract allows it; the handler decides what missing targets mean.
    expect(parseBridgeReq({ id: 3, op: "page_click", args: {} }).ok).toBe(true);
  });
});

describe("parseBridgeReq refuses malformed envelopes", () => {
  test("non-objects", () => {
    for (const bad of [null, undefined, 42, "tab_list", [], true]) {
      const r = refusal(bad);
      expect(r.id).toBeUndefined();
      expect(r.error).toContain("malformed bridge request");
    }
  });

  test("missing id / op / args", () => {
    expect(refusal({ op: "tab_list", args: {} }).error).toContain("malformed");
    expect(refusal({ id: 1, args: {} }).error).toContain("malformed");
    expect(refusal({ id: 1, op: "tab_list" }).error).toContain("malformed");
  });

  test("mistyped id is refused and not echoed", () => {
    const r = refusal({ id: { evil: true }, op: "tab_list", args: {} });
    expect(r.id).toBeUndefined();
  });

  test("an id the schema rejects is never echoed back on the refusal", () => {
    // A fractional or unsafe-integer id fails BridgeIdSchema, so echoing it
    // would make the refusal response itself malformed.
    expect(refusal({ id: 1.5, op: "tab_list", args: {}, extra: 1 }).id).toBeUndefined();
    expect(refusal({ id: 2 ** 60, op: "tab_list", args: {} }).id).toBeUndefined();
  });

  test("unknown top-level fields are rejected (strict envelope)", () => {
    const r = refusal({ id: 1, op: "tab_list", args: {}, extra: "field" });
    expect(r.id).toBe(1);
    expect(r.error).toContain("malformed");
  });

  test("browser label outside the contract charset", () => {
    expect(refusal({ id: 1, op: "tab_list", args: {}, browser: "a b" }).error).toContain(
      "malformed",
    );
    expect(refusal({ id: 1, op: "tab_list", args: {}, browser: "x".repeat(33) }).error).toContain(
      "malformed",
    );
  });

  test("args outside the contract union", () => {
    const r = refusal({ id: 4, op: "tab_list", args: { notAnArg: 1 } });
    expect(r.id).toBe(4);
  });
});

describe("parseBridgeReq refuses bad ops and bad per-op args", () => {
  test("an op not in the catalogue", () => {
    const r = refusal({ id: 5, op: "steal_cookies", args: {} });
    expect(r.id).toBe(5);
    expect(r.error).toContain("unknown op");
  });

  test("a required arg missing", () => {
    const r = refusal({ id: 6, op: "page_eval", args: {} });
    expect(r.id).toBe(6);
    expect(r.error).toContain("invalid args for page_eval");
  });

  test("a required arg mistyped is caught at the envelope layer already", () => {
    // tabId is typed in the OpArgs union itself, so the envelope refuses it
    // before the per-op validator even runs.
    expect(refusal({ id: 7, op: "tab_focus", args: { tabId: "7" } }).error).toContain(
      "malformed bridge request",
    );
  });

  test("another op's args smuggled in", () => {
    // `url` is a legal OpArgs field, but not a page_eval field: the per-op
    // validator rejects it even though the envelope accepts the union.
    const r = refusal({ id: 8, op: "page_eval", args: { code: "1", url: "https://x.example" } });
    expect(r.error).toContain("invalid args for page_eval");
  });
});

describe("envelope schemas", () => {
  test("BridgeRespSchema accepts the extension's response shapes", () => {
    expect(BridgeRespSchema.safeParse({ id: 1, ok: true, data: { any: "thing" } }).success).toBe(
      true,
    );
    expect(BridgeRespSchema.safeParse({ id: 1, ok: false, error: "nope" }).success).toBe(true);
  });

  test("BridgeRespSchema rejects malformed responses", () => {
    expect(BridgeRespSchema.safeParse({ id: 1 }).success).toBe(false);
    expect(BridgeRespSchema.safeParse({ id: 1, ok: "yes" }).success).toBe(false);
    expect(BridgeRespSchema.safeParse({ id: 1, ok: true, extra: 1 }).success).toBe(false);
  });

  test("BridgeReqSchema rejects a fractional tabId", () => {
    expect(BridgeReqSchema.safeParse({ id: 1, op: "tab_list", tabId: 1.5, args: {} }).success).toBe(
      false,
    );
  });
});
