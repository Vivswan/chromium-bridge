// The confirmation payload union: each kind carries exactly its own fields, so
// the combinations the service never produces are PARSE errors at the window's
// trust boundary, not rendering decisions. The type-level side is pinned with a
// ts-expect-error directive: constructing an invalid combination fails to
// compile, not just to parse.

import { describe, expect, test } from "bun:test";
import { type ConfirmPayload, ConfirmPayloadSchema, isPresenceGated } from "../src/confirm";

const base = {
  id: "confirm_1",
  deadline: Date.now() + 30_000,
};

const page = {
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "detail",
};

describe("ConfirmPayloadSchema", () => {
  test("accepts each kind with exactly its fields", () => {
    for (const kind of ["click", "press", "select", "tab_close"] as const) {
      expect(ConfirmPayloadSchema.safeParse({ ...base, ...page, kind }).success).toBe(true);
    }
    for (const kind of ["eval", "upload"] as const) {
      expect(ConfirmPayloadSchema.safeParse({ ...base, ...page, kind }).success).toBe(true);
      expect(
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, presence: true }).success,
      ).toBe(true);
    }
    expect(
      ConfirmPayloadSchema.safeParse({
        ...base,
        kind: "policy_relax",
        origin: "",
        tabTitle: "",
        detail: "pageEvalEnabled",
      }).success,
    ).toBe(true);
  });

  test("presence exists only on the two presence-gated kinds", () => {
    // A payload claiming the presence route for a kind the presence
    // provider never serves is a schema error - the host-answered rendering
    // can never be smuggled onto a window-approved kind.
    for (const kind of ["click", "press", "select", "tab_close"] as const) {
      expect(
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, presence: true }).success,
      ).toBe(false);
    }
    expect(
      ConfirmPayloadSchema.safeParse({
        ...base,
        kind: "policy_relax",
        origin: "",
        tabTitle: "",
        detail: "x",
        presence: true,
      }).success,
    ).toBe(false);
    // And only as the literal true: the service never emits presence:false
    // (absence IS the not-gated state), so the dead arm is a parse error too.
    for (const kind of ["eval", "upload"] as const) {
      expect(
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, presence: false }).success,
      ).toBe(false);
    }
  });

  test('policy_relax is structurally page-less: origin/tabTitle are pinned to ""', () => {
    expect(
      ConfirmPayloadSchema.safeParse({
        ...base,
        kind: "policy_relax",
        origin: "https://example.com",
        tabTitle: "",
        detail: "x",
      }).success,
    ).toBe(false);
    expect(
      ConfirmPayloadSchema.safeParse({
        ...base,
        kind: "policy_relax",
        origin: "",
        tabTitle: "Example",
        detail: "x",
      }).success,
    ).toBe(false);
  });

  test("strict arms refuse unknown fields", () => {
    expect(
      ConfirmPayloadSchema.safeParse({ ...base, ...page, kind: "click", surprise: 1 }).success,
    ).toBe(false);
  });

  test("isPresenceGated reads the flag only where the union carries it", () => {
    const parse = (v: unknown) => ConfirmPayloadSchema.parse(v);
    expect(isPresenceGated(parse({ ...base, ...page, kind: "eval", presence: true }))).toBe(true);
    expect(isPresenceGated(parse({ ...base, ...page, kind: "eval" }))).toBe(false);
    expect(isPresenceGated(parse({ ...base, ...page, kind: "click" }))).toBe(false);
  });

  test("the TYPE rejects the same invalid combinations the schema does", () => {
    // Compile-time twins of the parse rejections above; each directive is a
    // type-level proof the invalid state is unrepresentable.
    // @ts-expect-error presence cannot ride a click payload
    const clickPresence: ConfirmPayload = { ...base, ...page, kind: "click", presence: true };
    // @ts-expect-error policy_relax pins origin to ""
    const policyWithPage: ConfirmPayload = {
      ...base,
      kind: "policy_relax",
      origin: "https://example.com",
      tabTitle: "",
      detail: "x",
    };
    const policyPresence: ConfirmPayload = {
      ...base,
      kind: "policy_relax",
      origin: "",
      tabTitle: "",
      detail: "x",
      // @ts-expect-error policy_relax cannot claim the presence route
      presence: true,
    };
    void [clickPresence, policyWithPage, policyPresence];
  });
});
