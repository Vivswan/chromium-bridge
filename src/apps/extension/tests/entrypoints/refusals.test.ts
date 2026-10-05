// Every refusal code the host can put in a presence_result or enroll_result has a sentence on the options
// page: a cross-file consistency the TypeScript cannot express, since the roster lives in the Rust core
// (webauthn/refusal.rs, presence/mod.rs, native_host/presence.rs). A code added there without a row in
// refusals.ts would otherwise reach the user as a bare code.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { hasRefusalSentence, refusalSentence } from "@/entrypoints/options/refusals";

const CORE = resolve(__dirname, "../../../../packages/core/src");

/** The snake_case string literals inside a `fn code(&self) -> &'static str` body. */
function codesOf(file: string): string[] {
  const source = readFileSync(resolve(CORE, file), "utf8");
  const start = source.indexOf("fn code(&self) -> &'static str {");
  if (start === -1) throw new Error(`${file}: no code() roster`);
  // The function ends at the first closing brace back at its own indentation.
  const end = source.indexOf("\n    }\n", start);
  const body = source.slice(start, end);
  return [...body.matchAll(/"([a-z][a-z0-9_]*)"/g)].map((m) => m[1] ?? "");
}

/** The reasons native_host/presence.rs mints itself: bare, and the "<code>: <detail>" prefixes. */
function hostReasons(): string[] {
  const source = readFileSync(resolve(CORE, "native_host/presence.rs"), "utf8");
  const bare = [...source.matchAll(/(?:enroll|presence)_refused\("([a-z][a-z0-9_]*)"/g)];
  const prefixed = [
    ...source.matchAll(/(?:enroll|presence)_refused\(format!\("([a-z][a-z0-9_]*): /g),
  ];
  return [...bare, ...prefixed].map((m) => m[1] ?? "");
}

const t = (key: string, substitutions?: string[]) => `${key}[${substitutions?.join(",") ?? ""}]`;

describe("refusal sentences cover the host's roster", () => {
  const roster = [
    ...codesOf("webauthn/refusal.rs"),
    ...codesOf("presence/mod.rs"),
    ...hostReasons(),
  ];

  test("the roster was read (a moved fn or renamed helper would empty it)", () => {
    expect(roster.length).toBeGreaterThan(30);
    expect(roster).toContain("sign_count_not_increased");
    expect(roster).toContain("store_error");
  });

  test.each([...new Set(roster)])("%s has a sentence", (code) => {
    expect(hasRefusalSentence(code)).toBe(true);
  });

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
    // A code is never shown bare: it gets its sentence, or the unknown-code sentence; a phrase passes through.
    expect(refusalSentence(t as never, reason)).toBe(expected);
  });
});
