import { describe, expect, it } from "vitest";
import { resolvedShownRows } from "../src/lib/audit-correlate";
import type { AuditKind, AuditLine, AuditRecord } from "../src/lib/commands.gen";

// Minimal record builder: v/ts_ms are irrelevant to correlation, so they are
// fixed; only kind + the correlation fields (cid, tool, name) matter here.
function rec(kind: AuditKind, fields: Partial<AuditRecord> = {}): AuditRecord {
  return { v: 1, ts_ms: 0, kind, ...fields };
}

const shown = (fields: Partial<AuditRecord>) => rec("confirm_shown", fields);
const allowed = (fields: Partial<AuditRecord>) => rec("confirm_allowed", fields);
const denied = (fields: Partial<AuditRecord>) => rec("confirm_denied", fields);

describe("resolvedShownRows: exact cid join", () => {
  it("a verdict resolves exactly its own shown row by cid", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      allowed({ cid: "A", tool: "eval", name: "https://x" }),
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set([0]));
  });

  it("a still-open confirmation (no verdict yet) stays unresolved", () => {
    const lines: AuditLine[] = [shown({ cid: "A", tool: "eval", name: "https://x" })];
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });

  it("a verdict whose cid matches no shown row resolves nothing", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      denied({ cid: "Z", tool: "eval", name: "https://x" }),
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });
});

describe("resolvedShownRows: the panic-latch bug is impossible", () => {
  // The bug: a panic-latch denial of a confirmation that never reached a
  // surface used to close an unrelated open confirm_shown row with the same
  // tool/name. Now every attempt mints one cid stamped on all its events, so a
  // pre-surface denial carries a DISTINCT cid that matches no shown row.
  it("a pre-surface denial (fresh cid, no matching shown) closes no open row", () => {
    const lines: AuditLine[] = [
      // A real confirmation is shown and still pending.
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      // The panic latch denies a DIFFERENT attempt that never showed a surface:
      // same subject, but its own distinct cid (no confirm_shown carries it).
      denied({ cid: "STRAY", tool: "eval", name: "https://x" }),
    ];
    // The open shown row is NOT resolved by the unrelated panic denial.
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });

  it("a cid-less denial still cannot touch a cid-carrying open shown row", () => {
    // Defensive: even a legacy-shaped cid-less denial (fallback lane) never
    // resolves a modern cid-carrying shown row.
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      denied({ tool: "eval", name: "https://x" }),
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });

  it("the shown row resolves only when ITS OWN verdict (same cid) arrives", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      denied({ cid: "STRAY", tool: "eval", name: "https://x" }), // pre-surface denial
      denied({ cid: "A", tool: "eval", name: "https://x" }), // A's real verdict
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set([0]));
  });
});

describe("resolvedShownRows: concurrent confirmations do not cross-correlate", () => {
  it("two identical-subject prompts (two browsers) resolve independently by cid", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      shown({ cid: "B", tool: "eval", name: "https://x" }),
      allowed({ cid: "B", tool: "eval", name: "https://x" }),
    ];
    // Only B's shown (index 1) is resolved; A (index 0) is still pending.
    expect(resolvedShownRows(lines)).toEqual(new Set([1]));
  });

  it("both resolve once each verdict arrives, matched by cid regardless of order", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      shown({ cid: "B", tool: "eval", name: "https://x" }),
      allowed({ cid: "B", tool: "eval", name: "https://x" }),
      denied({ cid: "A", tool: "eval", name: "https://x" }),
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set([0, 1]));
  });
});

describe("resolvedShownRows: pre-upgrade fallback (no cid)", () => {
  it("falls back to the subject heuristic when neither row carries a cid", () => {
    const lines: AuditLine[] = [
      shown({ tool: "eval", name: "https://x" }),
      denied({ tool: "eval", name: "https://x" }),
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set([0]));
  });

  it("the fallback closes the OLDEST open cid-less shown with the same subject", () => {
    const lines: AuditLine[] = [
      shown({ tool: "eval", name: "https://x" }), // 0
      shown({ tool: "eval", name: "https://x" }), // 1
      allowed({ tool: "eval", name: "https://x" }), // closes 0 (oldest)
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set([0]));
  });

  it("the two regimes never cross: a cid verdict ignores a cid-less shown", () => {
    const lines: AuditLine[] = [
      shown({ tool: "eval", name: "https://x" }), // pre-upgrade, no cid
      allowed({ cid: "A", tool: "eval", name: "https://x" }), // new verdict, cid
    ];
    // The cid verdict looks only in the id map (empty), so the cid-less shown
    // is left pending rather than falsely resolved.
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });

  it("and a cid-less verdict ignores a cid-carrying shown", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }), // new, cid
      denied({ tool: "eval", name: "https://x" }), // pre-upgrade verdict, no cid
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });

  it("a NEW pre-surface denial (with cid) cannot close a legacy cid-less shown row", () => {
    // The mixed-trail edge: an orphaned pre-upgrade cid-less shown row is open,
    // and a new panic-latch denial with the same subject lands after the
    // upgrade. Because the new denial carries a cid, it takes the exact-join
    // lane (matching nothing) and never falls into the subject fallback, so it
    // cannot resolve the unrelated legacy row.
    const lines: AuditLine[] = [
      shown({ tool: "eval", name: "https://x" }), // legacy, no cid, orphaned
      denied({ cid: "STRAY", tool: "eval", name: "https://x" }), // new pre-surface denial
    ];
    expect(resolvedShownRows(lines)).toEqual(new Set());
  });
});

describe("resolvedShownRows: unrecognized lines", () => {
  it("skips unrecognized lines without disturbing index correlation", () => {
    const lines: AuditLine[] = [
      shown({ cid: "A", tool: "eval", name: "https://x" }),
      { unrecognized: true },
      allowed({ cid: "A", tool: "eval", name: "https://x" }),
    ];
    // Index 0 (the shown) is resolved; the unrecognized line at index 1 does
    // not shift the resolved index.
    expect(resolvedShownRows(lines)).toEqual(new Set([0]));
  });
});
