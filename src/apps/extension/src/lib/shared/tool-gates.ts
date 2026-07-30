// The tool -> master-gate-setting map: which Security/Execution toggle vetoes
// a tool regardless of its own per-tool switch. One home for both sides of
// that fact: the background enforcement (confirm/gate.ts, upload.ts,
// dialog.ts) reads the setting through this map, and the options grid renders
// the effective capability from the same entries - so a new gated tool
// cannot gain an enforcement gate the grid does not know about, and the grid
// cannot claim a gate the background does not enforce. `satisfies` pins both
// axes: keys must be catalogue op names, values must be real setting keys.

import type { OpName, SettingKey } from "@chromium-bridge/shared";

export const TOOL_GATES = {
  page_eval: "pageEvalEnabled",
  page_upload: "fileUploadEnabled",
  page_handle_dialog: "handleDialogEnabled",
} as const satisfies Partial<Record<OpName, SettingKey>>;

export type GatedTool = keyof typeof TOOL_GATES;
export type GateSetting = (typeof TOOL_GATES)[GatedTool];

/** The master-gate setting for an op, or undefined when the op has none. */
export function toolGate(op: OpName): GateSetting | undefined {
  return (TOOL_GATES as Partial<Record<OpName, GateSetting>>)[op];
}
