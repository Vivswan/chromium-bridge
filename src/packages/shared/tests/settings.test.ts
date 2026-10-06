// Salvage semantics for the browser-owned settings: a storage read never surfaces a shape the schema does
// not vouch for, and one bad field never takes the healthy fields down with it.

import { describe, expect, test } from "bun:test";
import { DEFAULTS, salvageSettings } from "../src/settings";

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
