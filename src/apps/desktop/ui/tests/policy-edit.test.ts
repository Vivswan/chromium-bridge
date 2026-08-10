import { describe, expect, it } from "vitest";
import {
  changedFields,
  diffOverlay,
  draftErrors,
  draftFromValues,
  POLICY_FIELDS,
  parseTools,
  valuesFromDraft,
} from "../src/lib/policy-edit";
import type { PolicyValues } from "../src/lib/tauri";

// The deny baseline as a test fixture only (the app itself seeds from the
// policy_defaults command, never a hardcoded copy).
function values(overrides: Partial<PolicyValues> = {}): PolicyValues {
  return {
    cdpMode: false,
    fileUploadEnabled: false,
    handleDialogEnabled: false,
    pageEvalEnabled: false,
    confirmHighRiskClick: true,
    confirmPageEval: true,
    touchIdConfirm: true,
    confirmTabClose: true,
    warnPreciseSnapshot: true,
    evalMask: true,
    hostReverifyMs: 0,
    confirmGraceMs: 60_000,
    clickToastTimeoutMs: 30_000,
    evalToastTimeoutMs: 45_000,
    disabledTools: [],
    ...overrides,
  };
}

describe("the field catalogue", () => {
  it("covers exactly the 15 PolicyValues keys, each grouped once", () => {
    const names = POLICY_FIELDS.map((s) => s.name).sort();
    const keys = Object.keys(values()).sort();
    expect(names).toEqual(keys);
    expect(new Set(names).size).toBe(15);
  });
});

describe("draft round trip", () => {
  it("values -> draft -> values is the identity", () => {
    const v = values({
      pageEvalEnabled: true,
      hostReverifyMs: 12_345,
      disabledTools: ["page_eval", "page_upload"],
    });
    expect(valuesFromDraft(draftFromValues(v))).toEqual(v);
  });
});

describe("draftErrors", () => {
  it("accepts a clean draft", () => {
    expect(draftErrors(draftFromValues(values()))).toEqual([]);
  });

  it("refuses non-integer, negative, and unsafe millisecond input", () => {
    for (const bad of ["", "abc", "-5", "1.5", "1e3", "9007199254740992"]) {
      const draft = { ...draftFromValues(values()), confirmGraceMs: bad };
      expect(draftErrors(draft), bad).toEqual([{ field: "confirmGraceMs", kind: "ms" }]);
    }
    // The bound itself is fine (2^53 - 1, the JS-safe max the core enforces).
    const atBound = { ...draftFromValues(values()), confirmGraceMs: "9007199254740991" };
    expect(draftErrors(atBound)).toEqual([]);
  });

  it("bounds the disabled-tools list like the core (256 entries, 128 bytes each)", () => {
    const many = Array.from({ length: 257 }, (_, i) => `t${i}`).join(",");
    expect(draftErrors({ ...draftFromValues(values()), disabledTools: many })).toEqual([
      { field: "disabledTools", kind: "tool_count" },
    ]);
    const long = "a".repeat(129);
    expect(draftErrors({ ...draftFromValues(values()), disabledTools: long })).toEqual([
      { field: "disabledTools", kind: "tool_name" },
    ]);
    // Byte length, not character count: a 2-byte character (U+00E9) counts
    // as 2, so 65 of them (130 bytes) exceed the 128-byte bound at 65 chars.
    const twoByte = "\u00e9".repeat(65);
    expect(draftErrors({ ...draftFromValues(values()), disabledTools: twoByte })).toEqual([
      { field: "disabledTools", kind: "tool_name" },
    ]);
  });

  it('refuses flag-like tool names (the CLI argv layer\'s "--" rule)', () => {
    expect(draftErrors({ ...draftFromValues(values()), disabledTools: "--page-eval" })).toEqual([
      { field: "disabledTools", kind: "tool_name" },
    ]);
    // "--" only counts at the start of an entry, even after a spaced comma.
    expect(draftErrors({ ...draftFromValues(values()), disabledTools: "a--b, c" })).toEqual([]);
  });
});

describe("parseTools", () => {
  it("splits on commas, trims, and drops empties (empty text is the empty set)", () => {
    expect(parseTools("")).toEqual([]);
    expect(parseTools("  ")).toEqual([]);
    expect(parseTools("a, b ,,c,")).toEqual(["a", "b", "c"]);
  });
});

describe("diffOverlay", () => {
  it("carries exactly the changed fields", () => {
    const current = values();
    const edited = values({ pageEvalEnabled: true, confirmGraceMs: 30_000 });
    const overlay = diffOverlay(edited, current);
    expect(overlay).toEqual({ pageEvalEnabled: true, confirmGraceMs: 30_000 });
    expect(changedFields(overlay)).toEqual(["pageEvalEnabled", "confirmGraceMs"]);
  });

  it("is empty when nothing changed", () => {
    expect(changedFields(diffOverlay(values(), values()))).toEqual([]);
  });

  it("compares disabledTools as a set (order and duplicates carry no meaning)", () => {
    const current = values({ disabledTools: ["a", "b"] });
    expect(changedFields(diffOverlay(values({ disabledTools: ["b", "a"] }), current))).toEqual([]);
    expect(changedFields(diffOverlay(values({ disabledTools: ["a", "b", "b"] }), current))).toEqual(
      [],
    );
    expect(changedFields(diffOverlay(values({ disabledTools: ["a"] }), current))).toEqual([
      "disabledTools",
    ]);
  });
});
