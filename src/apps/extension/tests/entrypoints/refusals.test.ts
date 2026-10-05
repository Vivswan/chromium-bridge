// A refused frame's reason is "<code>" or "<code>: <detail>" (Reason in src/packages/core/src/webauthn/refusal.rs),
// a cross-process shape this file cannot see: the detail lands in parentheses after the code's sentence, a
// code from a host newer than this extension gets the unknown-code sentence instead of showing bare, and the
// worker's own phrases pass through. Which codes exist is the generated RefusalCode union, not a test here.

import { describe, expect, test } from "vitest";
import { refusalSentence } from "@/entrypoints/options/refusals";

const t = (key: string, substitutions?: string[]) => `${key}[${substitutions?.join(",") ?? ""}]`;

describe("refusal sentences", () => {
  test.each([
    {
      reason: "store_error: disk full",
      expected: "webauthn.reason_store_error[store_error] (disk full)",
    },
    {
      reason: "authdata_reserved_flags",
      expected: "webauthn.reason_malformed_answer[authdata_reserved_flags]",
    },
    { reason: "some_future_code", expected: "webauthn.reason_unknown_code[some_future_code]" },
    { reason: "native host not connected", expected: "native host not connected" },
  ])("$reason renders as $expected", ({ reason, expected }) => {
    expect(refusalSentence(t as never, reason)).toBe(expected);
  });
});
