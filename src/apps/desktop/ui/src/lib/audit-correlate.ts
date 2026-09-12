// Confirmation-row correlation for the audit panel (ADR-0030). Which
// confirm_shown rows a later confirm_allowed/confirm_denied resolves - the
// input to the pending/resolved rendering in AuditView. Pure and display-only:
// every enforcement decision stays in Rust; this only decides how honestly the
// ledger renders. Kept out of the React view so it is unit-testable on its own.

import type { AuditLine, AuditRecord } from "./commands.gen";

/** An audit line that failed strict parsing on the Rust side (order preserved,
 * shape replaced by this marker). Duplicated from the tauri facade so this
 * module stays free of the Tauri runtime import. */
function isUnrecognized(line: AuditLine): line is { unrecognized: true } {
  return "unrecognized" in line;
}

const subjectKey = (line: AuditRecord): string => `${line.tool ?? "-"}::${line.name ?? "-"}`;

/** Indices of confirm_shown rows a later verdict resolves, so amber "pending" means genuinely still waiting on
 * the user (a timeout settles as confirm_denied, so it resolves too). The join is the per-attempt `cid` the
 * extension stamps on every event of one confirmation attempt (ADR-0030): a verdict resolves exactly the shown
 * row carrying its id.
 *
 *   panic-latch denial, no surface ever shown   -> its cid matches no shown row: closes nothing
 *   two browsers, identical prompt, concurrent   -> distinct cids: neither verdict closes the other's row
 *   verdict without a cid (pre-upgrade record)   -> oldest open cid-less shown row with the same tool + name
 *
 * The two regimes never cross (a cid-carrying verdict only resolves a cid-carrying row, a cid-less one only a
 * cid-less row), so a trail written across an upgrade still renders. Unrecognized lines are skipped; AuditView
 * flags the whole trail as suspect when any exist. */
export function resolvedShownRows(lines: AuditLine[]): Set<number> {
  const resolved = new Set<number>();
  // cid -> index of its still-open confirm_shown row (the exact join).
  const openById = new Map<string, number>();
  // Fallback lane: FIFO of open cid-less confirm_shown rows, keyed by subject.
  const openBySubject: { idx: number; key: string }[] = [];
  lines.forEach((line, idx) => {
    if (isUnrecognized(line)) return;
    if (line.kind === "confirm_shown") {
      if (line.cid !== undefined) openById.set(line.cid, idx);
      else openBySubject.push({ idx, key: subjectKey(line) });
    } else if (line.kind === "confirm_allowed" || line.kind === "confirm_denied") {
      if (line.cid !== undefined) {
        // Exact join: resolve only the shown row carrying this same id.
        const at = openById.get(line.cid);
        if (at !== undefined) {
          resolved.add(at);
          openById.delete(line.cid);
        }
        return;
      }
      // No cid: a pre-upgrade verdict. Fall back to the oldest open cid-less
      // shown with the same subject; this never touches a cid-carrying row.
      const key = subjectKey(line);
      const at = openBySubject.findIndex((o) => o.key === key);
      if (at >= 0) {
        const shown = openBySubject[at];
        if (shown !== undefined) resolved.add(shown.idx);
        openBySubject.splice(at, 1);
      }
    }
  });
  return resolved;
}
