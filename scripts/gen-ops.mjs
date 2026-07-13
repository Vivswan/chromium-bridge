// Generate extension/src/shared/ops.ts from contracts/tools.json (the single
// source of truth for the tool catalogue). Run `make gen` after editing the
// contract; CI checks the generated file is up to date.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const contract = JSON.parse(readFileSync(join(root, "contracts/tools.json"), "utf8"));

const items = contract.tools
  .map((t) => `  { op: ${JSON.stringify(t.name)}, desc: ${JSON.stringify(t.uiLabel)} },`)
  .join("\n");

// Collect the distinct values for each metadata field so the generated union
// types stay in sync with the contract (add a new risk level in tools.json and
// it appears here automatically).
const distinct = (key) =>
  [...new Set(contract.tools.map((t) => t[key]))]
    .sort()
    .map((v) => JSON.stringify(v))
    .join(" | ");

const riskUnion = distinct("risk");
const scopeUnion = distinct("scope");
const permissionUnion = distinct("permission");
const confirmationUnion = distinct("confirmation");

// op names are valid JS identifiers, so emit unquoted keys (matches Prettier's
// `quoteProps: "as-needed"` default). Each entry is emitted multiline so the
// generated file stays format-clean regardless of value lengths (Prettier keeps
// an object expanded when there's a newline right after the opening brace).
const meta = contract.tools
  .map(
    (t) =>
      `  ${t.name}: {\n` +
      `    risk: ${JSON.stringify(t.risk)},\n` +
      `    scope: ${JSON.stringify(t.scope)},\n` +
      `    permission: ${JSON.stringify(t.permission)},\n` +
      `    confirmation: ${JSON.stringify(t.confirmation)},\n` +
      `  },`
  )
  .join("\n");

const out = `// GENERATED from contracts/tools.json by scripts/gen-ops.mjs — DO NOT EDIT.
// Edit the contract, then run \`make gen\` (or \`node scripts/gen-ops.mjs\`).
//
// The tool catalogue, JS side: op names + Chinese UI labels for the options
// page, plus policy metadata (risk / scope / permission / confirmation).
// tools.rs is verified against the same contract in \`cargo test\`.

export interface ToolInfo {
  op: string;
  desc: string;
}

export const TOOLS: ToolInfo[] = [
${items}
];

// All op names, for enumeration / consistency checks.
export const OP_NAMES: string[] = TOOLS.map((t) => t.op);

// Policy metadata, mirrored from the contract. Consumed by the policy layer
// (background/policy.ts) — kept as plain data so it stays import-side-effect-free.
export type Risk = ${riskUnion};
export type Scope = ${scopeUnion};
export type Permission = ${permissionUnion};
export type Confirmation = ${confirmationUnion};

export interface ToolMeta {
  risk: Risk;
  scope: Scope;
  permission: Permission;
  confirmation: Confirmation;
}

export const TOOL_META: Record<string, ToolMeta> = {
${meta}
};
`;

writeFileSync(join(root, "extension/src/shared/ops.ts"), out);
console.log("generated extension/src/shared/ops.ts from contracts/tools.json");
