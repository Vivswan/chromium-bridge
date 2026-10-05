// Salvage semantics for the browser-owned settings: a storage read never surfaces a shape the schema does
// not vouch for, and one bad field never takes the healthy fields down with it.

import { describe, expect, test } from "bun:test";
import { DEFAULTS, salvageSetting, salvageSettings } from "../src/settings";

describe("salvageSetting", () => {
  test.each([
    ["missing", "groupTabs", undefined, DEFAULTS.groupTabs],
    ["valid boolean", "allowAllSites", true, true],
    ["valid locale", "uiLanguage", "zh_TW", "zh_TW"],
    ["mistyped boolean", "allowAllSites", "yes", DEFAULTS.allowAllSites],
    ["number for a boolean", "groupTabs", 1, DEFAULTS.groupTabs],
    ["unsupported locale", "uiLanguage", "fr", DEFAULTS.uiLanguage],
  ] as const)("%s %s", (_case, key, stored, expected) => {
    expect(salvageSetting(key, stored)).toBe(expected);
  });
});

describe("salvageSettings", () => {
  test("a non-object bag yields the defaults", () => {
    expect(salvageSettings(null)).toEqual(DEFAULTS);
    expect(salvageSettings("junk")).toEqual(DEFAULTS);
  });

  test("bad fields fall back, healthy fields survive, unknown and retired keys are dropped", () => {
    const salvaged = salvageSettings({
      allowAllSites: true,
      groupTabs: "corrupted",
      uiLanguage: "zh_CN",
      unknownKey: "ignored",
      pageEvalEnabled: false, // a retired policy field is an unknown key now, never resurrected
    });
    expect(salvaged).toEqual({
      allowAllSites: true,
      groupTabs: DEFAULTS.groupTabs,
      uiLanguage: "zh_CN",
    });
  });
});
