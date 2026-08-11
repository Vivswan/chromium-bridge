// The tool -> master-gate-field map: which capability grant vetoes a tool
// regardless of its own per-tool switch. One home for that fact: the
// background enforcement (confirm/gate.ts, upload.ts, dialog.ts) indexes the
// effective policy through this map, so a gated tool cannot gain an
// enforcement gate the policy contract does not carry. `satisfies` pins both
// axes: keys must be catalogue op names, values must name a HOST-OWNED
// policy field (ADR-0032 - the options page no longer renders these; the
// app's policy editor does) whose value is a plain boolean grant
// (BooleanPolicyField below, so enforcement's `=== true` reads stay
// type-honest and a gate can never point at a numeric or list field).

import type { OpName, PolicyFieldName, PolicyValues } from "@chromium-bridge/shared";

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
} as const satisfies Partial<Record<OpName, BooleanPolicyField>>;

export type GatedTool = keyof typeof TOOL_GATES;
export type GateSetting = (typeof TOOL_GATES)[GatedTool];

/** The master-gate policy field for an op, or undefined when the op has none. */
export function toolGate(op: OpName): GateSetting | undefined {
  return (TOOL_GATES as Partial<Record<OpName, GateSetting>>)[op];
}
