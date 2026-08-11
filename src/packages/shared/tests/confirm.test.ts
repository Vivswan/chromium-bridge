// The confirmation payload union (ADR-0027/0031/0032): each kind carries
// exactly its own fields, so the combinations the service never produces are
// PARSE errors at the window's trust boundary, not rendering decisions. The
// type-level side is pinned with @ts-expect-error: constructing an invalid
// combination fails to compile, not just to parse.

import { describe, expect, test } from "bun:test";
import { type ConfirmPayload, ConfirmPayloadSchema, isHardwareGated } from "../src/confirm";

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
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, hardware: true }).success,
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

  test("hardware exists only on the two presence-gated kinds", () => {
    // A payload claiming hardware attestation for a kind the presence
    // provider never serves is a schema error - the display-only rendering
    // can never be smuggled onto a window-approved kind.
    for (const kind of ["click", "press", "select", "tab_close"] as const) {
      expect(
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, hardware: true }).success,
      ).toBe(false);
    }
    expect(
      ConfirmPayloadSchema.safeParse({
        ...base,
        kind: "policy_relax",
        origin: "",
        tabTitle: "",
        detail: "x",
        hardware: true,
      }).success,
    ).toBe(false);
    // And only as the literal true: the service never emits hardware:false
    // (absence IS the not-gated state), so the dead arm is a parse error too.
    for (const kind of ["eval", "upload"] as const) {
      expect(
        ConfirmPayloadSchema.safeParse({ ...base, ...page, kind, hardware: false }).success,
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

  test("isHardwareGated reads the flag only where the union carries it", () => {
    const parse = (v: unknown) => ConfirmPayloadSchema.parse(v);
    expect(isHardwareGated(parse({ ...base, ...page, kind: "eval", hardware: true }))).toBe(true);
    expect(isHardwareGated(parse({ ...base, ...page, kind: "eval" }))).toBe(false);
    expect(isHardwareGated(parse({ ...base, ...page, kind: "click" }))).toBe(false);
  });

  test("the TYPE rejects the same invalid combinations the schema does", () => {
    // Compile-time twins of the parse rejections above; each directive is a
    // type-level proof the invalid state is unrepresentable.
    // @ts-expect-error hardware cannot ride a click payload
    const clickHardware: ConfirmPayload = { ...base, ...page, kind: "click", hardware: true };
    // @ts-expect-error policy_relax pins origin to ""
    const policyWithPage: ConfirmPayload = {
      ...base,
      kind: "policy_relax",
      origin: "https://example.com",
      tabTitle: "",
      detail: "x",
    };
    const policyHardware: ConfirmPayload = {
      ...base,
      kind: "policy_relax",
      origin: "",
      tabTitle: "",
      detail: "x",
      // @ts-expect-error policy_relax cannot claim hardware attestation
      hardware: true,
    };
    void [clickHardware, policyWithPage, policyHardware];
  });
});
