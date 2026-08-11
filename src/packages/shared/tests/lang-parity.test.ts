// The shared-language enum exists on both sides of the process boundary as
// hand-kept copies (ADR-0032 decision 7): language is browser-owned
// (decision 1), so it is NOT generated into the Rust core the way the policy
// schema is. UI_LANGUAGES in settings.ts is the TS-side canonical list (the
// settings schema, the runtime-message enum, and the pickers all derive from
// it); the host's copy lives in src/packages/core/src/lang.rs. A Rust test
// pins lang.rs against its own const; this test closes the cross-language
// gap by reading the lang.rs source and comparing the literals, so a value
// added or renamed on one side fails CI instead of silently desyncing the
// sync lane.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULTS, SettingsSchema, UI_LANGUAGES } from "../src/settings";

const langRs = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), "../../core/src/lang.rs"),
  "utf8",
);

/** The string literals of a Rust `&["a", "b", ...]` slice body. */
function rustStringList(body: string): string[] {
  return [...body.matchAll(/"([^"]*)"/g)].map((m) => m[1] ?? "");
}

describe("shared language enum parity (ADR-0032 decision 7)", () => {
  test("the settings schema accepts exactly the canonical UI_LANGUAGES", () => {
    for (const value of UI_LANGUAGES) {
      expect(SettingsSchema.shape.uiLanguage.safeParse(value).success).toBe(true);
    }
    for (const value of ["de", "zh", "EN", "", "auto "]) {
      expect(SettingsSchema.shape.uiLanguage.safeParse(value).success).toBe(false);
    }
  });

  test("core lang.rs UI_LANGUAGES matches the canonical list", () => {
    const m = langRs.match(/pub const UI_LANGUAGES: &\[&str\] = &\[([^\]]*)\];/);
    expect(m, "UI_LANGUAGES slice not found in lang.rs").toBeTruthy();
    expect(rustStringList(m?.[1] ?? "")).toEqual([...UI_LANGUAGES]);
  });

  test("core lang.rs DEFAULT_LANG matches the settings default", () => {
    const m = langRs.match(/const DEFAULT_LANG: &str = "([^"]*)";/);
    expect(m, "DEFAULT_LANG not found in lang.rs").toBeTruthy();
    expect(m?.[1]).toBe(DEFAULTS.uiLanguage);
  });
});
