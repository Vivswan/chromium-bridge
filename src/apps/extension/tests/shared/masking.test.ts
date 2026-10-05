import { describe, expect, test } from "vitest";
import {
  maskCookieValue,
  maskErrorMessage,
  maskKeyName,
  maskNumber,
  maskPatterns,
  maskSensitive,
  maskString,
} from "@/lib/shared/masking";

const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij";
const HEX32 = "deadbeefdeadbeefdeadbeefdeadbeef";
// 40 chars, letters and digits, not hex, no separators.
const OPAQUE = "aB3dE6fH9jK2mN5pQ8rS1tU4vW7xY0zA3bC6dE9f";
const LETTERS40 = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn";

describe("maskPatterns", () => {
  test.each([
    ["a JWT", JWT, "••••[jwt]"],
    ["32 hex chars", HEX32, "••••[hex]"],
    ["a 12-digit run", "123456789012", "••••[num]"],
    ["a key=value assignment", "token=supersecretvalue", "••••[redacted]"],
    ["a 40-char opaque token", OPAQUE, "••••[token]"],
    ["an opaque token inside text", `id ${OPAQUE} end`, "id ••••[token] end"],
    ["40 letters with no digit", LETTERS40, LETTERS40],
    ["ordinary text", "hello world", "hello world"],
  ])("%s", (_case, input, expected) => {
    expect(maskPatterns(input)).toBe(expected);
  });

  test("the token rule stays linear on adversarial input (the nested-lookahead form was quadratic)", () => {
    // Letters but no digit, so it must come back unchanged, and fast enough that the test timeout does not fire.
    const adversarial = `${"a-".repeat(40000)}a`;
    expect(maskPatterns(adversarial)).toBe(adversarial);
  });
});

describe("maskString", () => {
  test.each([
    ["a short value passes through", "abc", "abc"],
    ["a JWT goes through the catalogue", JWT, "••••[jwt]"],
    ["hex goes through the catalogue", HEX32, "••••[hex]"],
    ["a bare credential-like string is fully masked", "session_tokenvalue", "••••[sensitive]"],
    [
      "whitespace disables the full mask",
      "please use token=secret12345 now",
      "please use ••••[redacted] now",
    ],
  ])("%s", (_case, input, expected) => {
    expect(maskString(input)).toBe(expected);
  });
});

describe("maskCookieValue (pattern-only, no full-mask)", () => {
  test.each([
    ["a number passes through", 42, 42],
    ["null passes through", null, null],
    ["a short string passes through", "abc", "abc"],
    ["a JWT goes through the catalogue", JWT, "••••[jwt]"],
    [
      "a credential-like string is NOT fully masked (maskString would)",
      "session_tokenvalue",
      "session_tokenvalue",
    ],
    ["an opaque session token goes through the catalogue", OPAQUE, "••••[token]"],
  ])("%s", (_case, input, expected) => {
    expect(maskCookieValue(input)).toBe(expected);
  });
});

describe("maskNumber", () => {
  test.each([
    ["a card-like integer", 123456789012, "••••[num]"],
    ["a small integer", 42, 42],
    ["a non-integer", 3.14, 3.14],
  ])("%s", (_case, input, expected) => {
    expect(maskNumber(input)).toBe(expected);
  });
});

describe("maskKeyName", () => {
  test.each([
    ["a sensitive name keeps a 2-char tail", "password", "••••rd"],
    ["an ordinary name passes through", "username", "username"],
  ])("%s", (_case, input, expected) => {
    expect(maskKeyName(input)).toBe(expected);
  });
});

describe("maskSensitive (recursive)", () => {
  test("masks values and renames sensitive keys through nested objects", () => {
    expect(
      maskSensitive({
        user: "alice",
        authToken: JWT,
        nested: { secret: HEX32, count: 3 },
      }),
    ).toEqual({
      user: "alice",
      "••••en": "••••[jwt]",
      nested: { "••••et": "••••[hex]", count: 3 },
    });
  });

  test("passes through primitives and arrays", () => {
    expect(maskSensitive(true)).toBe(true);
    expect(maskSensitive([1, 2])).toEqual([1, 2]);
  });
});

describe("maskErrorMessage (outer error egress)", () => {
  test.each([
    ["a secret in an Error message", new Error(`token ${JWT}`), "token ••••[jwt]"],
    ["a secret in a thrown string", `leak ${HEX32} end`, "leak ••••[hex] end"],
    ["an ordinary message", new Error("user denied: click submit"), "user denied: click submit"],
    ["undefined", undefined, "error"],
    ["null", null, "error"],
  ])("%s", (_case, input, expected) => {
    expect(maskErrorMessage(input)).toBe(expected);
  });
});
