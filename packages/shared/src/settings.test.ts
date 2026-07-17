// Salvage semantics for the settings schema: reads from storage must never
// surface a shape the schema does not vouch for, and a bad field must not
// take the healthy fields down with it.

import { describe, expect, test } from "bun:test";
import { DEFAULTS, SettingsSchema, salvageSetting, salvageSettings } from "./settings";

describe("DEFAULTS", () => {
  test("derives from the schema (empty bag parses to the defaults)", () => {
    expect(SettingsSchema.parse({})).toEqual(DEFAULTS);
  });

  test("keeps the documented values", () => {
    expect(DEFAULTS.pageEvalEnabled).toBe(true);
    expect(DEFAULTS.confirmGraceMs).toBe(60000);
    expect(DEFAULTS.disabledTools).toEqual([]);
    expect(DEFAULTS.allowAllSites).toBe(false);
    expect(DEFAULTS.cdpMode).toBe(false);
    expect(DEFAULTS.fileUploadEnabled).toBe(false);
    expect(DEFAULTS.handleDialogEnabled).toBe(false);
    expect(DEFAULTS.requireEnrollment).toBe(true);
    expect(DEFAULTS.hostReverifyMs).toBe(0);
  });
});

describe("salvageSetting", () => {
  test("missing value falls back to the default", () => {
    expect(salvageSetting("confirmPageEval", undefined)).toBe(true);
  });

  test("valid value is kept", () => {
    expect(salvageSetting("confirmPageEval", false)).toBe(false);
    expect(salvageSetting("disabledTools", ["page_eval"])).toEqual(["page_eval"]);
  });

  test("mistyped value falls back to the default", () => {
    expect(salvageSetting("confirmPageEval", "yes")).toBe(true);
    expect(salvageSetting("confirmGraceMs", "60000")).toBe(60000);
    expect(salvageSetting("confirmGraceMs", -5)).toBe(60000);
    expect(salvageSetting("confirmGraceMs", 1.5)).toBe(60000);
    expect(salvageSetting("disabledTools", [1, 2])).toEqual([]);
    expect(salvageSetting("disabledTools", "page_eval")).toEqual([]);
  });
});

describe("salvageSettings", () => {
  test("a non-object bag yields the defaults", () => {
    expect(salvageSettings(null)).toEqual(DEFAULTS);
    expect(salvageSettings("junk")).toEqual(DEFAULTS);
  });

  test("field-by-field: bad fields fall back, healthy fields survive", () => {
    const salvaged = salvageSettings({
      cdpMode: true,
      confirmGraceMs: "corrupted",
      disabledTools: ["page_upload"],
      unknownKey: "ignored",
    });
    expect(salvaged.cdpMode).toBe(true);
    expect(salvaged.confirmGraceMs).toBe(DEFAULTS.confirmGraceMs);
    expect(salvaged.disabledTools).toEqual(["page_upload"]);
    expect("unknownKey" in salvaged).toBe(false);
  });
});
