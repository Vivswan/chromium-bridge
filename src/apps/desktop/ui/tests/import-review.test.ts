import { describe, expect, it } from "vitest";
import {
  adoptLane,
  importRows,
  importSignWarning,
  needsEnrollmentForImport,
} from "../src/lib/import-review";
import type { EnclaveStatusReport, ImportSuggestion, PolicyValues } from "../src/lib/tauri";

// The core's deny defaults, mirrored for the fixtures (the real screen gets
// them from the policy_defaults command, never hardcoded).
const DEFAULTS: PolicyValues = {
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
  confirmGraceMs: 60000,
  clickToastTimeoutMs: 30000,
  evalToastTimeoutMs: 45000,
  disabledTools: [],
};

function suggestion(
  values: Partial<PolicyValues>,
  mapped: string[],
  ignored: string[] = [],
): ImportSuggestion {
  const merged = { ...DEFAULTS, ...values };
  return {
    values: merged,
    // The overlay mirrors values field-for-field in the real payload; the
    // row helpers never read it, so the fixture reuses the merged values.
    overlay: { ...merged },
    mapped,
    ignored,
  };
}

describe("importRows", () => {
  it("builds one row per MAPPED field, in catalogue order", () => {
    const rows = importRows(
      suggestion({ pageEvalEnabled: true, confirmGraceMs: 30000 }, [
        "pageEvalEnabled",
        "confirmGraceMs",
      ]),
      DEFAULTS,
    );
    // Catalogue order, not bag order: pageEval (a grant) precedes the
    // timing field.
    expect(rows.map((r) => r.spec.name)).toEqual(["pageEvalEnabled", "confirmGraceMs"]);
    expect(rows.every((r) => r.changed)).toBe(true);
    expect(rows[0]?.suggested).toBe(true);
    expect(rows[0]?.fallback).toBe(false);
  });

  it("marks a mapped field that equals the default as unchanged", () => {
    const rows = importRows(
      suggestion({ fileUploadEnabled: false }, ["fileUploadEnabled"]),
      DEFAULTS,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.changed).toBe(false);
  });

  it("compares tool lists as sets (order carries no meaning)", () => {
    const withTools = importRows(suggestion({ disabledTools: ["b", "a"] }, ["disabledTools"]), {
      ...DEFAULTS,
      disabledTools: ["a", "b"],
    });
    expect(withTools[0]?.changed).toBe(false);
    const grew = importRows(suggestion({ disabledTools: ["a"] }, ["disabledTools"]), DEFAULTS);
    expect(grew[0]?.changed).toBe(true);
  });

  it("renders no rows for an empty mapping (unnamed fields stay defaults)", () => {
    expect(importRows(suggestion({}, []), DEFAULTS)).toEqual([]);
  });
});

describe("adoptLane (display mirror of the Rust grant_lane)", () => {
  const report = (key: EnclaveStatusReport["key"], supported: boolean): EnclaveStatusReport => ({
    v: 1,
    supported,
    key_label: "label",
    key,
    policy: null,
    detail: key === "invalid" || key === "error" ? "detail words" : undefined,
  });

  it("signs via the host where a key exists", () => {
    expect(adoptLane(report("present", true))).toEqual({ kind: "signed" });
  });

  it("floors ONLY genuine unenrollment (supported && key none)", () => {
    expect(adoptLane(report("none", true))).toEqual({ kind: "floor" });
    // key none on an unsupported platform is contradictory: blocked.
    expect(adoptLane(report("none", false)).kind).toBe("blocked");
  });

  it("blocks every ambiguous or unsupported state, carrying the host's words", () => {
    expect(adoptLane(report("invalid", true))).toEqual({
      kind: "blocked",
      detail: "detail words",
    });
    expect(adoptLane(report("error", true))).toEqual({ kind: "blocked", detail: "detail words" });
    expect(adoptLane(report("unsupported", false)).kind).toBe("blocked");
  });

  it("points the empty import state at enrollment ONLY when genuinely unenrolled", () => {
    // Decision 8 as amended: the extension sends only to a pinned host that
    // proved possession, so an unenrolled Mac never receives the offer.
    // Same rule as adoptLane's floor: key none AND supported hardware -
    // "pair in Browsers" is not followable advice without an enclave.
    expect(needsEnrollmentForImport(report("none", true))).toBe(true);
    expect(needsEnrollmentForImport(report("none", false))).toBe(false);
    // Every other key state has its own repair path; no enrollment claim.
    expect(needsEnrollmentForImport(report("present", true))).toBe(false);
    expect(needsEnrollmentForImport(report("invalid", true))).toBe(false);
    expect(needsEnrollmentForImport(report("error", true))).toBe(false);
    expect(needsEnrollmentForImport(report("unsupported", false))).toBe(false);
  });
});

describe("importSignWarning (the first-baseline dialog's import warning)", () => {
  it("warns that signing closes the never-used window when the store reads none", () => {
    // Signing revision 1 with NO import ever recorded permanently closes
    // the one-time window (the tombstone outlives even key disposal).
    expect(importSignWarning("none", undefined)).toEqual({ kind: "closes_window" });
  });

  it("warns that signing discards a RECORDED bag when the store reads present", () => {
    // The stronger warning: a real recorded snapshot is waiting for review,
    // and revision 1 would consume it unseen.
    expect(importSignWarning("present", undefined)).toEqual({ kind: "discards_pending" });
  });

  it("surfaces a failed probe instead of silently closing an unknown window", () => {
    expect(importSignWarning(undefined, "probe exploded")).toEqual({
      kind: "probe_failed",
      detail: "probe exploded",
    });
  });

  it("stays silent for consumed, store-level error, and in-flight states", () => {
    // consumed: the window is already closed, nothing left to lose.
    expect(importSignWarning("consumed", undefined)).toBeUndefined();
    // store-level error: the host fails closed (consume refuses, so the
    // signed write cannot land over an unreadable store).
    expect(importSignWarning("error", undefined)).toBeUndefined();
    // in-flight (no data, no error yet): claims nothing.
    expect(importSignWarning(undefined, undefined)).toBeUndefined();
  });
});
