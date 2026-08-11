// The RETIRED legacy settings schema: the 15 policy fields ADR-0032 moved to
// the host-owned policy contract, plus `requireEnrollment` (retired outright;
// enrollment is simply required). Byte-identical to the pre-migration
// settings.ts semantics - same per-field schemas, same defaults, same salvage
// - because pre-cutover behavior must never drift from what shipped.
//
// PERMANENT, not transitional. Two consumers keep this module alive for as
// long as the extension exists (ADR-0032 decision 8):
//   - effective-policy.ts legacyPolicyValues: the pre-cutover enforcement
//     arm. An extension facing an old host never sees a policy push and
//     stays on these settings indefinitely, and a non-macOS install can
//     never receive a signed baseline at all, so it stays pre-cutover on
//     this schema forever.
//   - legacy-import.ts readLegacySettingsBag: the one-shot migration
//     snapshot (`legacy_settings { bag }`), which carries these fields plus
//     `requireEnrollment` as history.
// Nothing else may consume it: the live schema for the browser-owned
// settings is settings.ts, and post-cutover policy reads go through the
// generated policy contract (policy.gen.ts).
//
// The defaults deliberately DIFFER from POLICY_DEFAULTS where the legacy
// system was more permissive: pageEvalEnabled defaults TRUE here (today's
// shipped behavior) while the policy deny baseline is FALSE - the flip
// happens only at cutover, behind the dispatch barrier, never by editing
// this module.

import { z } from "zod";
import type { PolicyFieldName } from "./policy.gen";

export const LegacySettingsSchema = z.object({
  cdpMode: z.boolean().default(false),
  fileUploadEnabled: z.boolean().default(false),
  handleDialogEnabled: z.boolean().default(false),
  pageEvalEnabled: z.boolean().default(true),
  confirmHighRiskClick: z.boolean().default(true),
  confirmPageEval: z.boolean().default(true),
  touchIdConfirm: z.boolean().default(true),
  confirmTabClose: z.boolean().default(true),
  warnPreciseSnapshot: z.boolean().default(true),
  evalMask: z.boolean().default(true),
  hostReverifyMs: z.int().nonnegative().default(0),
  confirmGraceMs: z.int().nonnegative().default(60000),
  clickToastTimeoutMs: z.int().nonnegative().default(30000),
  evalToastTimeoutMs: z.int().nonnegative().default(45000),
  // Plain strings, not the op enum: entries matching no op are inert, while
  // an enum would make salvage drop the WHOLE list over one stale entry and
  // silently re-enable every disabled tool (fail-open, the wrong direction).
  // Deliberately UNBOUNDED, exactly like the old settings.ts: this schema
  // feeds the pre-cutover ENFORCEMENT read, where dropping or truncating a
  // deny-list entry is the permissive direction (a real op past a cap would
  // be silently re-enabled). The migration bag applies its own wire-size
  // bounds at its own site (legacy-import.ts), never here.
  disabledTools: z.array(z.string()).default([]),
  requireEnrollment: z.boolean().default(true),
});

export type LegacySettings = z.infer<typeof LegacySettingsSchema>;

export type LegacySettingKey = keyof LegacySettings;

// Compile-time pin: this schema covers EXACTLY the generated policy field
// catalogue plus requireEnrollment - a field added to or renamed in the
// policy contract fails here instead of silently diverging the legacy arm.
type LegacyFieldSet = PolicyFieldName | "requireEnrollment";
const _exhaustive: Record<LegacyFieldSet, unknown> = LegacySettingsSchema.shape;
const _noExtras: Record<LegacySettingKey, unknown> = {} as Record<LegacyFieldSet, unknown>;
void _exhaustive;
void _noExtras;

// Frozen (including the nested array), same discipline as settings.ts: a
// caller mutating a salvage fallback must throw instead of rewriting the
// defaults for everyone after it.
export const LEGACY_DEFAULTS: Readonly<LegacySettings> = deepFreeze(LegacySettingsSchema.parse({}));

function deepFreeze<T>(value: T): T {
  for (const inner of Object.values(value as object)) {
    if (typeof inner === "object" && inner !== null) deepFreeze(inner);
  }
  return Object.freeze(value);
}

/**
 * Validate one legacy field read from storage, falling back to the field's
 * legacy default when the stored value is missing or fails its schema - the
 * exact per-field validation the pre-migration getSetting applied.
 */
export function salvageLegacySetting<K extends LegacySettingKey>(
  key: K,
  value: unknown,
): LegacySettings[K] {
  const parsed = LegacySettingsSchema.shape[key].safeParse(value);
  return parsed.success ? (parsed.data as LegacySettings[K]) : LEGACY_DEFAULTS[key];
}
