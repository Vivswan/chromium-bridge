// Generate the contract-derived TypeScript from contracts/ (the single source
// of truth). Run `just gen` after editing a contract; CI checks the generated
// files are up to date.
//
// Outputs:
//   packages/shared/src/ops.gen.ts       - tool catalogue: op names, UI labels,
//     policy metadata, per-op Zod arg validators (BridgeCommand is inferred
//     from them), and the OpArgs union schema for the request envelope.
//   packages/shared/src/identity.gen.ts  - the pinned extension ID (derived
//     from extension/manifest.json's `key`, Chrome's own id derivation) and
//     the native-messaging host id (from contracts/identity.json).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

interface ToolContract {
  name: string;
  uiLabel: string;
  risk: string;
  scope: string;
  permission: string;
  confirmation: string;
  inputSchema?: {
    properties?: Record<string, { type: string; description?: string }>;
    required?: string[];
  };
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const contract = JSON.parse(readFileSync(join(root, "contracts/tools.json"), "utf8")) as {
  tools: ToolContract[];
};

// Args that exist only for the MCP server: `browser` picks which connected
// browser a call routes to and is consumed there - it is never forwarded
// inside the bridge request's args (bridge-request.schema.json's OpArgs stays
// strict). Excluded here so the extension-facing shapes describe only what
// the extension can actually receive.
const ROUTING_ARGS = new Set(["browser"]);

const jsonTypeToZod = (jsonType: string): string => {
  switch (jsonType) {
    case "string":
      return "z.string()";
    case "integer":
      return "z.int()";
    case "number":
      return "z.number()";
    case "boolean":
      return "z.boolean()";
    default:
      throw new Error(`gen-ops: unsupported JSON Schema type ${JSON.stringify(jsonType)}`);
  }
};

// The generator understands `type` + `description` and nothing else. Any
// other keyword (enum, minimum, pattern, ...) would be silently dropped from
// the generated validator - weaker validation than the contract claims - so
// its appearance must fail generation until support is added here AND in the
// per-op equivalence assertions (ops.gen.test.ts).
const SUPPORTED_PROP_KEYWORDS = new Set(["type", "description"]);

const assertSupportedProp = (tool: string, key: string, prop: Record<string, unknown>): void => {
  for (const keyword of Object.keys(prop)) {
    if (!SUPPORTED_PROP_KEYWORDS.has(keyword)) {
      throw new Error(
        `gen-ops: ${tool}.${key} uses unsupported inputSchema keyword ${JSON.stringify(keyword)}`,
      );
    }
  }
};

// Emit an object key: bare when it is a valid JS identifier (matches Biome's
// quoteProperties: "as-needed", keeping gen output format-stable), quoted
// otherwise.
const emitKey = (key: string): string =>
  /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key);

// ---- ops.gen.ts pieces ------------------------------------------------------

const opNames = contract.tools.map((t) => JSON.stringify(t.name)).join(",\n  ");

const toolItems = contract.tools
  .map((t) => `  { op: ${JSON.stringify(t.name)}, desc: ${JSON.stringify(t.uiLabel)} },`)
  .join("\n");

// Distinct values for each metadata field, so the unions stay in sync with
// the contract (add a new risk level in tools.json and it appears here).
const distinct = (key: "risk" | "scope" | "permission" | "confirmation") =>
  [...new Set(contract.tools.map((t) => t[key]))]
    .sort()
    .map((v) => JSON.stringify(v))
    .join(" | ");

const meta = contract.tools
  .map(
    (t) =>
      `  ${emitKey(t.name)}: {\n` +
      `    risk: ${JSON.stringify(t.risk)},\n` +
      `    scope: ${JSON.stringify(t.scope)},\n` +
      `    permission: ${JSON.stringify(t.permission)},\n` +
      `    confirmation: ${JSON.stringify(t.confirmation)},\n` +
      `  },`,
  )
  .join("\n");

// Per-op Zod arg validators, derived from each tool's inputSchema. Required
// props stay required; the rest are `.optional()`. strictObject: an op must
// not smuggle another op's fields (the host's payload builders send exactly
// the declared fields, so this rejects only forged or drifted traffic).
const argSchema = (t: ToolContract): string => {
  const props = t.inputSchema?.properties ?? {};
  const required = new Set(t.inputSchema?.required ?? []);
  for (const [k, prop] of Object.entries(props)) assertSupportedProp(t.name, k, prop);
  const fields = Object.keys(props)
    .filter((k) => !ROUTING_ARGS.has(k))
    .map((k) => {
      const prop = props[k];
      if (!prop) throw new Error(`gen-ops: missing property schema for ${k}`);
      const zod = jsonTypeToZod(prop.type);
      return `${emitKey(k)}: ${zod}${required.has(k) ? "" : ".optional()"}`;
    });
  return fields.length ? `z.strictObject({ ${fields.join(", ")} })` : "z.strictObject({})";
};

const argSchemas = contract.tools.map((t) => `  ${emitKey(t.name)}: ${argSchema(t)},`).join("\n");

// The envelope-level OpArgs union: every tool's props merged, all optional
// (per-op required-ness is the per-op validators' job). A prop declared by
// two tools must agree on its type, otherwise the union is ill-formed.
const unionProps = new Map<string, string>();
for (const t of contract.tools) {
  const props = t.inputSchema?.properties ?? {};
  for (const [k, prop] of Object.entries(props)) {
    if (ROUTING_ARGS.has(k)) continue;
    const zod = jsonTypeToZod(prop.type);
    const prior = unionProps.get(k);
    if (prior !== undefined && prior !== zod) {
      throw new Error(
        `gen-ops: conflicting types for arg ${JSON.stringify(k)}: ${prior} vs ${zod}`,
      );
    }
    unionProps.set(k, zod);
  }
}
const opArgsFields = [...unionProps.entries()]
  .map(([k, zod]) => `  ${emitKey(k)}: ${zod}.optional(),`)
  .join("\n");

const opsOut = `// GENERATED from contracts/tools.json by scripts/gen-ops.ts - DO NOT EDIT.
// Edit the contract, then run \`just gen\`.
//
// The tool catalogue, TS side: op names + Chinese UI labels for the options
// page, policy metadata (risk / scope / permission / confirmation), and the
// per-op Zod arg validators the extension enforces at the native-messaging
// boundary. BridgeCommand (the discriminated request union) is INFERRED from
// the validators, so the compile-time types and the runtime checks cannot
// drift apart. Rust tools/catalogue.rs is verified against the same contract
// in \`cargo test\`.

import { z } from "zod";

export const OP_NAMES = [
  ${opNames},
] as const;

export type OpName = (typeof OP_NAMES)[number];

const OP_NAME_SET: ReadonlySet<string> = new Set(OP_NAMES);

export function isOpName(op: string): op is OpName {
  return OP_NAME_SET.has(op);
}

export interface ToolInfo {
  op: OpName;
  desc: string;
}

export const TOOLS: readonly ToolInfo[] = [
${toolItems}
];

// Policy metadata, mirrored from the contract. Consumed by the policy layer
// (background/policy.ts) - kept as plain data so it stays import-side-effect-free.
export type Risk = ${distinct("risk")};
export type Scope = ${distinct("scope")};
export type Permission = ${distinct("permission")};
export type Confirmation = ${distinct("confirmation")};

export interface ToolMeta {
  risk: Risk;
  scope: Scope;
  permission: Permission;
  confirmation: Confirmation;
}

export const TOOL_META: Readonly<Record<OpName, ToolMeta>> = {
${meta}
};

// Per-op arg validators, derived from each tool's inputSchema (minus the
// server-consumed \`browser\` routing arg). The extension parses an inbound
// request's args against its op's validator before dispatching - fail closed.
export const OP_ARG_SCHEMAS = {
${argSchemas}
} as const satisfies Readonly<Record<OpName, z.ZodType>>;

// Per-op request shapes, inferred from the validators. Discriminated on \`op\`,
// so consumers (background/dispatch.ts) narrow the args to exactly the fields
// that tool accepts. envelope.ts intersects this with the request envelope to
// form BridgeReq.
export type BridgeCommand = {
  [K in OpName]: { op: K; args: z.infer<(typeof OP_ARG_SCHEMAS)[K]> };
}[OpName];

// The envelope-level args bag: the union of every tool's inputSchema props,
// all optional (the per-op validators enforce required-ness). Structurally
// equivalent to bridge-request.schema.json's $defs/OpArgs - the equivalence
// test in packages/shared enforces that against the contract file.
export const OpArgsSchema = z.strictObject({
${opArgsFields}
});

export type OpArgs = z.infer<typeof OpArgsSchema>;
`;

writeFileSync(join(root, "packages/shared/src/ops.gen.ts"), opsOut);
console.log("generated packages/shared/src/ops.gen.ts from contracts/tools.json");

// ---- identity.gen.ts ----------------------------------------------------------

const manifest = JSON.parse(readFileSync(join(root, "extension/manifest.json"), "utf8")) as {
  key?: unknown;
};
if (typeof manifest.key !== "string" || manifest.key.length === 0) {
  throw new Error("gen-ops: extension/manifest.json has no public key");
}
// Chrome's id derivation: sha256 of the DER key, first 16 bytes, hex mapped
// onto a-p. Same computation as scripts/check-extension-id.ts.
const hex = createHash("sha256")
  .update(Buffer.from(manifest.key, "base64"))
  .digest("hex")
  .slice(0, 32);
const extensionId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");

const identity = JSON.parse(readFileSync(join(root, "contracts/identity.json"), "utf8")) as {
  nativeMessagingHostId?: unknown;
};
const hostId = identity.nativeMessagingHostId;
// Chrome's charset for host names: dot-separated segments of [a-z0-9_], so
// no leading/trailing dots and no empty segments.
if (typeof hostId !== "string" || !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(hostId)) {
  throw new Error(
    "gen-ops: contracts/identity.json nativeMessagingHostId violates Chrome's charset",
  );
}

const identityOut = `// GENERATED by scripts/gen-ops.ts - DO NOT EDIT. Run \`just gen\`.
//
// The bridge's identity constants. PINNED_EXTENSION_ID is DERIVED from
// extension/manifest.json's \`key\` (Chrome's own id derivation), so it cannot
// drift from the manifest; NATIVE_HOST_ID comes from contracts/identity.json.
// scripts/check-extension-id.ts verifies the installers and the Rust host
// against the same sources.

// The extension ID Chrome derives from the manifest \`key\`. The native-
// messaging host manifest pins this in \`allowed_origins\`, so a build without
// the pinned key is rejected by the host.
export const PINNED_EXTENSION_ID = ${JSON.stringify(extensionId)};

// The native-messaging host id: what the extension passes to connectNative,
// what the Rust host expects, and the host manifest's name/filename stem.
export const NATIVE_HOST_ID = ${JSON.stringify(hostId)};
`;

writeFileSync(join(root, "packages/shared/src/identity.gen.ts"), identityOut);
console.log(
  "generated packages/shared/src/identity.gen.ts from manifest key + contracts/identity.json",
);
