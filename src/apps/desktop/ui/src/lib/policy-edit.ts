// Pure edit-model helpers for the policy editor (SecurityView): the field
// catalogue's DISPLAY metadata, draft <-> values conversion, validation, and
// the changed-fields diff. Display and drafting only - which way a change
// points (tighten vs relax) is the Rust `policy_plan` command's business,
// computed from the core's direction table; the webview never classifies a
// direction itself.

import type { PolicyOverlay, PolicyValues } from "@/lib/tauri";
import type { MessageKey } from "@/locales/en";

export type PolicyFieldName = keyof PolicyValues;
export type PolicyGroup = "grants" | "confirmations" | "timing" | "tools";
export type PolicyFieldKind = PolicyFieldSpec["kind"];

/** The editor kind a field's VALUE TYPE dictates: booleans render the
 * toggle row, numbers the ms input, the string list the tools input. */
type PolicyFieldKindOf<V> = V extends boolean ? "bool" : V extends number ? "ms" : "tools";

/** One field's display spec, with `kind` tied to `PolicyValues[name]` at the
 * type level (a mapped union over the field names): a spec claiming the
 * wrong editor for its field - `cdpMode` with kind "ms", say - fails to
 * compile instead of rendering a boolean through the numeric input. */
export type PolicyFieldSpec = {
  [K in PolicyFieldName]: {
    name: K;
    kind: PolicyFieldKindOf<PolicyValues[K]>;
    group: PolicyGroup;
    labelKey: MessageKey;
  };
}[PolicyFieldName];

/** The 15 host-owned fields in catalogue order (mirrors the Rust
 * `PolicyField::ALL`), grouped for display. */
export const POLICY_FIELDS: readonly PolicyFieldSpec[] = [
  { name: "cdpMode", kind: "bool", group: "grants", labelKey: "security.field_cdp_mode" },
  {
    name: "fileUploadEnabled",
    kind: "bool",
    group: "grants",
    labelKey: "security.field_file_upload",
  },
  {
    name: "handleDialogEnabled",
    kind: "bool",
    group: "grants",
    labelKey: "security.field_handle_dialog",
  },
  { name: "pageEvalEnabled", kind: "bool", group: "grants", labelKey: "security.field_page_eval" },
  {
    name: "confirmHighRiskClick",
    kind: "bool",
    group: "confirmations",
    labelKey: "security.field_confirm_click",
  },
  {
    name: "confirmPageEval",
    kind: "bool",
    group: "confirmations",
    labelKey: "security.field_confirm_eval",
  },
  {
    name: "touchIdConfirm",
    kind: "bool",
    group: "confirmations",
    labelKey: "security.field_touch_id_confirm",
  },
  {
    name: "confirmTabClose",
    kind: "bool",
    group: "confirmations",
    labelKey: "security.field_confirm_tab_close",
  },
  {
    name: "warnPreciseSnapshot",
    kind: "bool",
    group: "confirmations",
    labelKey: "security.field_warn_snapshot",
  },
  { name: "evalMask", kind: "bool", group: "confirmations", labelKey: "security.field_eval_mask" },
  { name: "hostReverifyMs", kind: "ms", group: "timing", labelKey: "security.field_reverify_ms" },
  { name: "confirmGraceMs", kind: "ms", group: "timing", labelKey: "security.field_grace_ms" },
  {
    name: "clickToastTimeoutMs",
    kind: "ms",
    group: "timing",
    labelKey: "security.field_click_toast_ms",
  },
  {
    name: "evalToastTimeoutMs",
    kind: "ms",
    group: "timing",
    labelKey: "security.field_eval_toast_ms",
  },
  {
    name: "disabledTools",
    kind: "tools",
    group: "tools",
    labelKey: "security.field_disabled_tools",
  },
] as const;

/** The editor's in-progress state: booleans stay booleans, everything the
 * user types (ms fields, the tool list) stays a string until validated. */
export type PolicyDraft = {
  [K in PolicyFieldName]: PolicyValues[K] extends boolean ? boolean : string;
};

export function draftFromValues(v: PolicyValues): PolicyDraft {
  return {
    cdpMode: v.cdpMode,
    fileUploadEnabled: v.fileUploadEnabled,
    handleDialogEnabled: v.handleDialogEnabled,
    pageEvalEnabled: v.pageEvalEnabled,
    confirmHighRiskClick: v.confirmHighRiskClick,
    confirmPageEval: v.confirmPageEval,
    touchIdConfirm: v.touchIdConfirm,
    confirmTabClose: v.confirmTabClose,
    warnPreciseSnapshot: v.warnPreciseSnapshot,
    evalMask: v.evalMask,
    hostReverifyMs: String(v.hostReverifyMs),
    confirmGraceMs: String(v.confirmGraceMs),
    clickToastTimeoutMs: String(v.clickToastTimeoutMs),
    evalToastTimeoutMs: String(v.evalToastTimeoutMs),
    disabledTools: v.disabledTools.join(", "),
  };
}

/** Comma-separated tool list -> entries; empties dropped (the CLI's
 * parse_tool_list semantics, so "" is the empty set). */
export function parseTools(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

// The core's bounds, mirrored so a draft the host would refuse never leaves
// the editor (validate-before-prompt): JS_SAFE_INT_MAX, the disabledTools
// entry bounds (bytes, like the Rust check).
const MS_MAX = 9007199254740991;
const TOOLS_MAX_ENTRIES = 256;
const TOOL_NAME_MAX_BYTES = 128;

// The host refuses tool entries its comma-joined CLI transport cannot carry
// faithfully (validate_disabled_tools): commas, and edge whitespace by
// RUST's definition (char::is_whitespace = the Unicode White_Space set).
// parseTools' JS .trim() covers a slightly DIFFERENT set - it misses U+0085
// (NEL) - so an entry can survive the split+trim above and still carry
// host-trimmable whitespace at an edge. This pattern is the Rust set,
// spelled with escapes (the repo bans literal invisible unicode), so the
// editor refuses exactly what the host would and the sheet never opens on a
// draft the write seam refuses.
const RUST_WHITESPACE =
  "\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000";
const RUST_WHITESPACE_EDGE = new RegExp(`^[${RUST_WHITESPACE}]|[${RUST_WHITESPACE}]$`);

export type DraftErrorKind = "ms" | "tool_count" | "tool_name";

export interface DraftError {
  field: PolicyFieldName;
  kind: DraftErrorKind;
}

/** Structural validity only - the same facts the Rust side re-checks. A
 * non-empty result blocks apply BEFORE any plan call or dialog. */
export function draftErrors(d: PolicyDraft): DraftError[] {
  const errors: DraftError[] = [];
  const encoder = new TextEncoder();
  for (const spec of POLICY_FIELDS) {
    if (spec.kind === "ms") {
      const text = (d[spec.name] as string).trim();
      const value = Number(text);
      if (!/^\d+$/.test(text) || !Number.isSafeInteger(value) || value > MS_MAX) {
        errors.push({ field: spec.name, kind: "ms" });
      }
    } else if (spec.kind === "tools") {
      const tools = parseTools(d[spec.name] as string);
      if (tools.length > TOOLS_MAX_ENTRIES) {
        errors.push({ field: spec.name, kind: "tool_count" });
      } else if (
        // Byte bound mirrors the Rust check; the flag-like refusal mirrors
        // the CLI argv layer (a "--"-prefixed value is refused there); the
        // comma and Rust-edge-whitespace refusals mirror
        // validate_disabled_tools' transport-fidelity rule (the comma is
        // unreachable past parseTools' split, kept for self-documentation) -
        // so the free and signed lanes fail the same drafts, before any
        // dialog.
        tools.some(
          (t) =>
            encoder.encode(t).length > TOOL_NAME_MAX_BYTES ||
            t.startsWith("--") ||
            t.includes(",") ||
            RUST_WHITESPACE_EDGE.test(t),
        )
      ) {
        errors.push({ field: spec.name, kind: "tool_name" });
      }
    }
  }
  return errors;
}

/** A validated draft as concrete values. Call only after `draftErrors`
 * returned empty. */
export function valuesFromDraft(d: PolicyDraft): PolicyValues {
  return {
    cdpMode: d.cdpMode,
    fileUploadEnabled: d.fileUploadEnabled,
    handleDialogEnabled: d.handleDialogEnabled,
    pageEvalEnabled: d.pageEvalEnabled,
    confirmHighRiskClick: d.confirmHighRiskClick,
    confirmPageEval: d.confirmPageEval,
    touchIdConfirm: d.touchIdConfirm,
    confirmTabClose: d.confirmTabClose,
    warnPreciseSnapshot: d.warnPreciseSnapshot,
    evalMask: d.evalMask,
    hostReverifyMs: Number(d.hostReverifyMs.trim()),
    confirmGraceMs: Number(d.confirmGraceMs.trim()),
    clickToastTimeoutMs: Number(d.clickToastTimeoutMs.trim()),
    evalToastTimeoutMs: Number(d.evalToastTimeoutMs.trim()),
    disabledTools: parseTools(d.disabledTools),
  };
}

function sameToolSet(a: string[], b: string[]): boolean {
  return a.every((t) => b.includes(t)) && b.every((t) => a.includes(t));
}

/** The edits as an overlay: exactly the fields where `edited` differs from
 * `current` (disabledTools compared as a SET - order and duplicates carry no
 * meaning). An empty object means nothing changed. Spelled field by field,
 * the Rust diff_overlay posture: a new policy field is a loud type error
 * here, never a silently undiffed setting. */
export function diffOverlay(edited: PolicyValues, current: PolicyValues): PolicyOverlay {
  const overlay: PolicyOverlay = {};
  if (edited.cdpMode !== current.cdpMode) overlay.cdpMode = edited.cdpMode;
  if (edited.fileUploadEnabled !== current.fileUploadEnabled) {
    overlay.fileUploadEnabled = edited.fileUploadEnabled;
  }
  if (edited.handleDialogEnabled !== current.handleDialogEnabled) {
    overlay.handleDialogEnabled = edited.handleDialogEnabled;
  }
  if (edited.pageEvalEnabled !== current.pageEvalEnabled) {
    overlay.pageEvalEnabled = edited.pageEvalEnabled;
  }
  if (edited.confirmHighRiskClick !== current.confirmHighRiskClick) {
    overlay.confirmHighRiskClick = edited.confirmHighRiskClick;
  }
  if (edited.confirmPageEval !== current.confirmPageEval) {
    overlay.confirmPageEval = edited.confirmPageEval;
  }
  if (edited.touchIdConfirm !== current.touchIdConfirm) {
    overlay.touchIdConfirm = edited.touchIdConfirm;
  }
  if (edited.confirmTabClose !== current.confirmTabClose) {
    overlay.confirmTabClose = edited.confirmTabClose;
  }
  if (edited.warnPreciseSnapshot !== current.warnPreciseSnapshot) {
    overlay.warnPreciseSnapshot = edited.warnPreciseSnapshot;
  }
  if (edited.evalMask !== current.evalMask) overlay.evalMask = edited.evalMask;
  if (edited.hostReverifyMs !== current.hostReverifyMs) {
    overlay.hostReverifyMs = edited.hostReverifyMs;
  }
  if (edited.confirmGraceMs !== current.confirmGraceMs) {
    overlay.confirmGraceMs = edited.confirmGraceMs;
  }
  if (edited.clickToastTimeoutMs !== current.clickToastTimeoutMs) {
    overlay.clickToastTimeoutMs = edited.clickToastTimeoutMs;
  }
  if (edited.evalToastTimeoutMs !== current.evalToastTimeoutMs) {
    overlay.evalToastTimeoutMs = edited.evalToastTimeoutMs;
  }
  if (!sameToolSet(edited.disabledTools, current.disabledTools)) {
    overlay.disabledTools = edited.disabledTools;
  }
  return overlay;
}

/** The field names an overlay edits, in catalogue order. */
export function changedFields(overlay: PolicyOverlay): PolicyFieldName[] {
  return POLICY_FIELDS.filter((spec) => overlay[spec.name] !== undefined).map((spec) => spec.name);
}
