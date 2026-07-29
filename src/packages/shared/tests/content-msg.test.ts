// The SW <-> content-script messaging contract, exercised adversarially: the
// envelope must refuse any page-acting message without its full guard (the
// confirmation-to-act binding), and the reply envelope must refuse anything
// that is not one of its two arms. These schemas are the durable guards for
// the extension's confirm-to-act path - a drifted or absent field must become
// a refusal, never a silently skipped check.

import { describe, expect, test } from "bun:test";
import {
  ContentMsgSchema,
  InfoToastResultSchema,
  PageReplySchema,
  StorageReadResultSchema,
} from "../src/content-msg";

const PROBE = {
  tagName: "BUTTON",
  role: "button",
  type: "submit",
  hasHref: false,
  name: "Pay",
};

const GUARDED_OPS = [
  "page_snapshot",
  "page_fill",
  "page_text",
  "page_scroll",
  "page_wait_for",
  "page_eval",
  "storage_get",
  "page_press",
  "page_hover",
  "page_select",
] as const;

describe("ContentMsg: page-acting ops REQUIRE their guard", () => {
  test.each([...GUARDED_OPS])("%s without a guard is refused", (op) => {
    expect(ContentMsgSchema.safeParse({ op, args: {} }).success).toBe(false);
  });

  test.each([...GUARDED_OPS])("%s with a bound guard parses", (op) => {
    const parsed = ContentMsgSchema.safeParse({
      op,
      args: {},
      tabId: 7,
      guard: { expectOrigin: "https://example.com" },
    });
    expect(parsed.success).toBe(true);
  });

  test("an empty expectOrigin is refused (nothing to hold the act to)", () => {
    expect(
      ContentMsgSchema.safeParse({
        op: "page_snapshot",
        args: {},
        guard: { expectOrigin: "" },
      }).success,
    ).toBe(false);
  });

  test("page_click additionally requires the approved click descriptor", () => {
    const base = { op: "page_click", args: { selector: "#s" } };
    expect(
      ContentMsgSchema.safeParse({
        ...base,
        guard: { expectOrigin: "https://example.com" },
      }).success,
    ).toBe(false);
    expect(
      ContentMsgSchema.safeParse({
        ...base,
        guard: { expectOrigin: "https://example.com", clickExpect: PROBE },
      }).success,
    ).toBe(true);
    // A drifted descriptor (missing field) is refused too.
    expect(
      ContentMsgSchema.safeParse({
        ...base,
        guard: {
          expectOrigin: "https://example.com",
          clickExpect: { tagName: "BUTTON", role: "button" },
        },
      }).success,
    ).toBe(false);
  });

  test("page_screenshot never reaches the content script (not in the union)", () => {
    expect(
      ContentMsgSchema.safeParse({
        op: "page_screenshot",
        args: {},
        guard: { expectOrigin: "https://example.com" },
      }).success,
    ).toBe(false);
  });

  test("internal ops are the only guard-less messages", () => {
    expect(ContentMsgSchema.safeParse({ op: "ping" }).success).toBe(true);
    expect(
      ContentMsgSchema.safeParse({
        op: "_info_toast",
        args: { message: "heads up", cancelLabel: "Cancel" },
      }).success,
    ).toBe(true);
    expect(
      ContentMsgSchema.safeParse({
        op: "_probe_click",
        args: { selector: "#s" },
        tabId: 7,
      }).success,
    ).toBe(true);
  });

  test("unknown ops and non-objects are refused", () => {
    expect(ContentMsgSchema.safeParse({ op: "page_upload", args: {} }).success).toBe(false);
    expect(ContentMsgSchema.safeParse({ op: "", args: {} }).success).toBe(false);
    expect(ContentMsgSchema.safeParse(null).success).toBe(false);
    expect(ContentMsgSchema.safeParse("page_snapshot").success).toBe(false);
  });

  test("unknown envelope fields are refused (strict envelope)", () => {
    expect(
      ContentMsgSchema.safeParse({
        op: "page_snapshot",
        args: {},
        guard: { expectOrigin: "https://example.com" },
        extra: 1,
      }).success,
    ).toBe(false);
  });
});

describe("PageReply: one envelope, two arms, nothing else", () => {
  test("both arms parse", () => {
    expect(PageReplySchema.safeParse({ ok: true, data: { pong: true } }).success).toBe(true);
    expect(PageReplySchema.safeParse({ ok: true }).success).toBe(true); // eval returned nothing
    expect(PageReplySchema.safeParse({ ok: false, error: "boom" }).success).toBe(true);
  });

  test("legacy and drifted replies are refused", () => {
    expect(PageReplySchema.safeParse(false).success).toBe(false); // the old toast cancel
    expect(PageReplySchema.safeParse({}).success).toBe(false); // the old `data || {}`
    expect(PageReplySchema.safeParse({ __error: "boom" }).success).toBe(false);
    expect(PageReplySchema.safeParse({ ok: false }).success).toBe(false); // error-less failure
    expect(PageReplySchema.safeParse({ ok: true, data: 1, extra: 2 }).success).toBe(false);
  });
});

describe("InfoToastResult", () => {
  test("carries cancellation as structured data", () => {
    expect(InfoToastResultSchema.safeParse({ cancelled: true }).success).toBe(true);
    expect(InfoToastResultSchema.safeParse({ cancelled: false }).success).toBe(true);
    expect(InfoToastResultSchema.safeParse({}).success).toBe(false);
    expect(InfoToastResultSchema.safeParse(true).success).toBe(false);
  });
});

describe("StorageReadResult: exactly the three shapes readStorage produces", () => {
  test("the three valid shapes parse", () => {
    expect(StorageReadResultSchema.safeParse({ key: "k", found: false }).success).toBe(true);
    expect(StorageReadResultSchema.safeParse({ key: "k", found: true, value: "v" }).success).toBe(
      true,
    );
    expect(
      StorageReadResultSchema.safeParse({
        type: "local",
        entries: { a: "1" },
        count: 1,
        truncated: false,
        totalKeys: 1,
      }).success,
    ).toBe(true);
  });

  test("drifted shapes are refused (the egress mask fails closed on these)", () => {
    expect(StorageReadResultSchema.safeParse({ key: "k", found: 1, value: "secret" }).success).toBe(
      false,
    );
    expect(StorageReadResultSchema.safeParse({ found: true, value: "v" }).success).toBe(false);
    expect(StorageReadResultSchema.safeParse(null).success).toBe(false);
  });
});
