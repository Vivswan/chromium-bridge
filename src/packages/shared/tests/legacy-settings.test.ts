// The permanent legacy settings module (ADR-0032 Phase 5): the 15 retired
// policy fields plus requireEnrollment, byte-identical to the pre-migration
// settings.ts semantics. These pins are LOAD-BEARING: the pre-cutover
// enforcement arm (effective-policy.ts) and the migration bag
// (legacy-import.ts) both read through this module, so a drifted default here
// silently changes what a pre-cutover install enforces and what the app's
// first-run import screen shows.

import { describe, expect, test } from "bun:test";
import {
  LEGACY_DEFAULTS,
  LegacySettingsSchema,
  salvageLegacySetting,
} from "../src/legacy-settings";
import { POLICY_DEFAULTS, POLICY_FIELDS } from "../src/policy.gen";

describe("LEGACY_DEFAULTS", () => {
  test("derives from the schema (empty bag parses to the defaults)", () => {
    expect(LegacySettingsSchema.parse({})).toEqual(LEGACY_DEFAULTS);
  });

  test("covers exactly the 15 policy fields plus requireEnrollment", () => {
    expect(Object.keys(LEGACY_DEFAULTS).sort()).toEqual(
      [...POLICY_FIELDS, "requireEnrollment"].sort(),
    );
  });

  test("keeps the shipped legacy values, byte for byte", () => {
    // The full pre-migration default set (the old settings.ts), pinned
    // exhaustively so no field can drift without failing here.
    expect(LEGACY_DEFAULTS).toEqual({
      cdpMode: false,
      fileUploadEnabled: false,
      handleDialogEnabled: false,
      pageEvalEnabled: true,
      confirmHighRiskClick: true,
      confirmPageEval: true,
      touchIdConfirm: true,
      confirmTabClose: true,
      warnPreciseSnapshot: true,
      evalMask: true,
      hostReverifyMs: 0,
      confirmGraceMs: 60000,
      clickToastTimeoutMs: 30000,
      evalToastTimeoutMs: 45000,
      disabledTools: [],
      requireEnrollment: true,
    });
  });

  test("pageEvalEnabled legacy default is TRUE while the policy deny baseline is FALSE", () => {
    // The load-bearing distinction (ADR-0032): the flip to deny happens only
    // at cutover, behind the dispatch barrier - never in the legacy arm.
    expect(LEGACY_DEFAULTS.pageEvalEnabled).toBe(true);
    expect(POLICY_DEFAULTS.pageEvalEnabled).toBe(false);
  });

  test("is deeply frozen (a mutated fallback throws instead of drifting)", () => {
    expect(() => {
      (LEGACY_DEFAULTS.disabledTools as string[]).push("page_eval");
    }).toThrow();
  });
});

describe("salvageLegacySetting", () => {
  test("missing value falls back to the legacy default", () => {
    expect(salvageLegacySetting("confirmPageEval", undefined)).toBe(true);
    expect(salvageLegacySetting("pageEvalEnabled", undefined)).toBe(true);
    expect(salvageLegacySetting("requireEnrollment", undefined)).toBe(true);
  });

  test("valid value is kept", () => {
    expect(salvageLegacySetting("confirmPageEval", false)).toBe(false);
    expect(salvageLegacySetting("disabledTools", ["page_eval"])).toEqual(["page_eval"]);
    expect(salvageLegacySetting("hostReverifyMs", 5000)).toBe(5000);
  });

  test("mistyped value falls back to the legacy default", () => {
    expect(salvageLegacySetting("confirmPageEval", "yes")).toBe(true);
    expect(salvageLegacySetting("confirmGraceMs", "60000")).toBe(60000);
    expect(salvageLegacySetting("confirmGraceMs", -5)).toBe(60000);
    expect(salvageLegacySetting("confirmGraceMs", 1.5)).toBe(60000);
    expect(salvageLegacySetting("disabledTools", [1, 2])).toEqual([]);
    expect(salvageLegacySetting("disabledTools", "page_eval")).toEqual([]);
  });

  test("disabledTools is UNBOUNDED, exactly like the old schema (enforcement must never truncate a deny-list)", () => {
    // Byte-identical to the shipped settings.ts: a pathological list passes
    // through verbatim. Truncating here would be the PERMISSIVE direction -
    // a real op past a cap would be silently re-enabled in the pre-cutover
    // enforcement arm. The migration bag applies its own wire-size bounds
    // at its own site (legacy-import.ts), never this schema.
    const oversizeEntry = "x".repeat(10_000);
    expect(salvageLegacySetting("disabledTools", [oversizeEntry, "page_eval"])).toEqual([
      oversizeEntry,
      "page_eval",
    ]);
    const huge = Array.from({ length: 500 }, (_, i) => `tool_${i}`);
    expect(salvageLegacySetting("disabledTools", huge)).toEqual(huge);
  });
});
