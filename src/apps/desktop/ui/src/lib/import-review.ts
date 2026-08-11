// Pure display helpers for the first-run legacy-import screen (ADR-0032
// decision 8): the review rows (legacy value vs deny default, per mapped
// field) and the display-side mirror of the Rust grant-lane decision. All
// display: the Rust side re-decides the lane and re-validates everything at
// write time.

import { POLICY_FIELDS, type PolicyFieldSpec } from "@/lib/policy-edit";
import type {
  EnclaveStatusReport,
  ImportSuggestion,
  PendingImportSurvey,
  PolicyValues,
} from "@/lib/tauri";

/** One reviewable field: the suggestion's value against the deny default. */
export interface ImportRow {
  spec: PolicyFieldSpec;
  /** The value Adopt would sign for this field. */
  suggested: boolean | number | string[];
  /** The deny default it replaces. */
  fallback: boolean | number | string[];
  /** Whether the suggestion departs from the default (tool lists compared
   * as sets, the policy convention). */
  changed: boolean;
}

function sameValue(a: boolean | number | string[], b: boolean | number | string[]): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.every((t) => b.includes(t)) && b.every((t) => a.includes(t));
  }
  return a === b;
}

/** The review rows: one per field the bag validly mapped, catalogue order.
 * Fields the bag did not name (or named unusably) stay at the defaults and
 * are not rows - the screen lists them summarily via `ignored`. */
export function importRows(suggestion: ImportSuggestion, defaults: PolicyValues): ImportRow[] {
  return POLICY_FIELDS.filter((spec) => suggestion.mapped.includes(spec.name)).map((spec) => {
    const suggested = suggestion.values[spec.name];
    const fallback = defaults[spec.name];
    return { spec, suggested, fallback, changed: !sameValue(suggested, fallback) };
  });
}

/** How Adopt would be authorized on this machine - the display-side mirror
 * of the Rust `grant_lane` (policy_cmds.rs), used only to word the confirm
 * dialog and banners; Rust re-decides at write time. */
export type AdoptLane =
  /** Enrolled: one Touch ID signs revision 1 via the bundled host. */
  | { kind: "signed" }
  /** Genuinely unenrolled (supported && key none): the app's documented
   * confirmation floor stores an UNSIGNED first baseline. */
  | { kind: "floor" }
  /** Every other key state: adopting is refused (fail closed); `detail`
   * carries the host's own words where it gave any. */
  | { kind: "blocked"; detail: string };

export function adoptLane(report: EnclaveStatusReport): AdoptLane {
  if (report.key === "present") return { kind: "signed" };
  if (report.key === "none" && report.supported) return { kind: "floor" };
  return { kind: "blocked", detail: report.detail ?? report.key };
}

/** Whether the import screen's empty ("none") state should point at
 * enrollment: the extension sends its snapshot only to a pinned host that
 * proved key possession (ADR-0032 decision 8 as amended), so on an
 * unenrolled Mac no offer can ever arrive until the user pairs. Only the
 * genuinely unenrolled state (`key none` AND enclave-supported hardware,
 * adoptLane's floor rule) qualifies: on unsupported hardware pairing is not
 * followable advice, and invalid/error key states have their own repair
 * paths and claim nothing here. */
export function needsEnrollmentForImport(report: EnclaveStatusReport): boolean {
  return report.key === "none" && report.supported;
}

/** What the first-baseline confirm dialog must say about the one-time legacy
 * import window (ADR-0032 decision 8) before revision 1 signs. */
export type ImportSignWarning =
  /** Store reads `none`: no receipt was ever recorded, and the tombstone
   * the first signed write leaves closes the window for good - a snapshot
   * arriving later can never be imported. */
  | { kind: "closes_window" }
  /** Store reads `present`: a REAL recorded bag is waiting for review, and
   * signing revision 1 consumes it unseen - the stronger warning. */
  | { kind: "discards_pending" }
  /** The probe itself failed (rejected, no data): the import state is
   * unknown, so the dialog says so instead of silently closing a window it
   * cannot vouch for. */
  | { kind: "probe_failed"; detail: string };

/** The warning for the first-baseline confirm dialog, from the pending-import
 * probe's state and error. `consumed` is already closed (nothing to say);
 * a store-level `error` state fails closed host-side (consume refuses, so
 * the signed write cannot land over it); an in-flight probe (no data, no
 * error yet) claims nothing. */
export function importSignWarning(
  state: PendingImportSurvey["state"] | undefined,
  probeError: string | undefined,
): ImportSignWarning | undefined {
  if (state === "none") return { kind: "closes_window" };
  if (state === "present") return { kind: "discards_pending" };
  if (state === undefined && probeError !== undefined) {
    return { kind: "probe_failed", detail: probeError };
  }
  return undefined;
}
