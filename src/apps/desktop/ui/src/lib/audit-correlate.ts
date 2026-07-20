// Confirmation-row correlation for the audit panel (ADR-0030). Which
// confirm_shown rows a later confirm_allowed/confirm_denied resolves - the
// input to the pending/resolved rendering in AuditView. Pure and display-only:
// every enforcement decision stays in Rust; this only decides how honestly the
// ledger renders. Kept out of the React view so it is unit-testable on its own.

import type { AuditLine, AuditRecord } from "./commands.gen";

/** An audit line that failed strict parsing on the Rust side (order preserved,
 * shape replaced by this marker). Duplicated from the tauri facade so this
 * module stays free of the Tauri runtime import. */
function isUnrecognized(line: AuditLine): line is { unrecognized: boolean } {
  return "unrecognized" in line;
}

const subjectKey = (line: AuditRecord): string => `${line.tool ?? "-"}::${line.name ?? "-"}`;

/** Indices of CONFIRM_SHOWN rows a later verdict resolves. Amber "pending" is
 * reserved for a confirmation genuinely still waiting on the user; a resolved
 * one still claiming to wait is stale-state dishonesty in the ledger. A timeout
 * settles as confirm_denied, so it correlates too.
 *
 * Primary join: the per-confirmation `cid` (ADR-0030). The extension mints one
 * collision-resistant id per confirmation attempt and stamps it on EVERY audit
 * event that attempt emits - its confirm_shown, its verdict, and even a denial
 * issued before any surface was shown. A verdict therefore resolves EXACTLY the
 * shown row carrying the same id, and only if one exists. This is what makes
 * the two failure modes of the old subject-only heuristic impossible:
 *   - a panic-latch denial of a confirmation that never reached a surface
 *     carries an id that matches no confirm_shown row, so it resolves nothing -
 *     it cannot close an unrelated open confirmation;
 *   - two browsers raising the identical prompt concurrently mint distinct
 *     random ids, so neither's verdict can close the other's row.
 *
 * Fallback (pre-upgrade records only): a verdict WITHOUT a cid falls back to
 * the old subject (tool + name) heuristic, closing the oldest still-open
 * cid-less shown row with the same subject. Every record written by the current
 * extension carries a cid, so this lane is reached only by genuinely old data
 * written before the id existed; the two regimes never cross - a cid-carrying
 * verdict only resolves a cid-carrying shown, a cid-less verdict only a cid-less
 * shown - so a trail written across an upgrade still renders, while a new
 * pre-surface denial (which has a cid) can never fall into the fallback and
 * close a legacy row. Unrecognized lines are skipped; when any exist, the page
 * already flags the whole trail as suspect above the table. */
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
