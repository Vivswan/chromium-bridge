// Salvage semantics for the slimmed, browser-owned settings schema (ADR-0032
// Phase 5): reads from storage must never surface a shape the schema does not
// vouch for, and a bad field must not take the healthy fields down with it.
// The retired policy fields' legacy schemas are covered by
// legacy-settings.test.ts.

import { describe, expect, test } from "bun:test";
import { DEFAULTS, SettingsSchema, salvageSetting, salvageSettings } from "../src/settings";

describe("DEFAULTS", () => {
  test("derives from the schema (empty bag parses to the defaults)", () => {
    expect(SettingsSchema.parse({})).toEqual(DEFAULTS);
  });

  test("keeps exactly the browser-owned fields and their documented values", () => {
    expect(Object.keys(DEFAULTS).sort()).toEqual(["allowAllSites", "groupTabs", "uiLanguage"]);
    expect(DEFAULTS.allowAllSites).toBe(false);
    expect(DEFAULTS.groupTabs).toBe(true);
    expect(DEFAULTS.uiLanguage).toBe("en");
  });
});

describe("salvageSetting", () => {
  test("missing value falls back to the default", () => {
    expect(salvageSetting("groupTabs", undefined)).toBe(true);
  });

  test("valid value is kept", () => {
    expect(salvageSetting("allowAllSites", true)).toBe(true);
    expect(salvageSetting("uiLanguage", "zh_TW")).toBe("zh_TW");
  });

  test("mistyped value falls back to the default", () => {
    expect(salvageSetting("allowAllSites", "yes")).toBe(false);
    expect(salvageSetting("groupTabs", 1)).toBe(true);
    expect(salvageSetting("uiLanguage", "fr")).toBe("en");
  });
});

describe("salvageSettings", () => {
  test("a non-object bag yields the defaults", () => {
    expect(salvageSettings(null)).toEqual(DEFAULTS);
    expect(salvageSettings("junk")).toEqual(DEFAULTS);
  });

  test("field-by-field: bad fields fall back, healthy fields survive", () => {
    const salvaged = salvageSettings({
      allowAllSites: true,
      groupTabs: "corrupted",
      uiLanguage: "zh_CN",
      unknownKey: "ignored",
      // A retired policy field in the bag is an unknown key now: dropped,
      // never resurrected into Settings.
      pageEvalEnabled: false,
    });
    expect(salvaged.allowAllSites).toBe(true);
    expect(salvaged.groupTabs).toBe(DEFAULTS.groupTabs);
    expect(salvaged.uiLanguage).toBe("zh_CN");
    expect("unknownKey" in salvaged).toBe(false);
    expect("pageEvalEnabled" in salvaged).toBe(false);
  });
});
