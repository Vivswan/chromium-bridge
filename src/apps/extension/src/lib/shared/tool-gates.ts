// The tool -> master-gate-field map: which capability grant vetoes a tool
// regardless of its own per-tool switch. One home for both sides of that
// fact: the background enforcement (confirm/gate.ts, upload.ts, dialog.ts)
// indexes the effective policy through this map, and the options grid
// renders the effective capability from the same entries - so a new gated
// tool cannot gain an enforcement gate the grid does not know about, and the
// grid cannot claim a gate the background does not enforce. `satisfies` pins
// both axes: keys must be catalogue op names, values must name a policy
// field whose value is a plain boolean grant (BooleanPolicyField below, so
// enforcement's `=== true` reads stay type-honest and a gate can never point
// at a numeric or list field) AND a legacy setting key (the options page
// keeps rendering from legacy settings until Phase 5 slims settings.ts - at
// which point the SettingKey half of the intersection fails to compile here
// and forces the grid's own swap).

import type { OpName, PolicyFieldName, PolicyValues, SettingKey } from "@chromium-bridge/shared";

/** The policy fields whose value is a plain boolean: the only shape a master
 * gate may have. Derived from the generated PolicyValues, so the constraint
 * tracks the catalogue. */
type BooleanPolicyField = {
  [K in PolicyFieldName]: PolicyValues[K] extends boolean ? K : never;
}[PolicyFieldName];

export const TOOL_GATES = {
  page_eval: "pageEvalEnabled",
  page_upload: "fileUploadEnabled",
  page_handle_dialog: "handleDialogEnabled",
} as const satisfies Partial<Record<OpName, SettingKey & BooleanPolicyField>>;

export type GatedTool = keyof typeof TOOL_GATES;
export type GateSetting = (typeof TOOL_GATES)[GatedTool];

/** The master-gate setting for an op, or undefined when the op has none. */
export function toolGate(op: OpName): GateSetting | undefined {
  return (TOOL_GATES as Partial<Record<OpName, GateSetting>>)[op];
}
