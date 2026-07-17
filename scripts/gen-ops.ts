// Generate the contract-derived TypeScript from the Rust core, the canonical
// contract source (ADR-0028). Runs the core's `emit_contract` example to get
// the contract as JSON, then writes the src/packages/shared *.gen.ts modules.
// Run `just gen` after editing the catalogue/taxonomy in src/packages/core; CI
// regenerates and fails if the checked-in files are stale.
//
// Outputs:
//   src/packages/shared/src/ops.gen.ts       - tool catalogue: op names, policy
//     metadata, per-op Zod arg validators (BridgeCommand is inferred from
//     them), and the OpArgs union schema for the request envelope.
//   src/packages/shared/src/errors.gen.ts    - the stable cross-process error
//     codes and their metadata (category, retryable, default message).
//   src/packages/shared/src/protocol.gen.ts  - the internal bridge protocol
//     version and the capability groupings for connection-time negotiation.
//   src/packages/shared/src/identity.gen.ts  - the pinned extension ID (derived
//     from the manifest key, Chrome's own id derivation), the manifest key
//     itself (injected into the manifest by src/apps/extension/wxt.config.ts), and the
//     native-messaging host id.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

interface ContractTool {
  name: string;
  risk: string;
  scope: string;
  permission: string;
  confirmation: string;
  description: string;
  inputSchema?: {
    properties?: Record<string, { type: string; description?: string }>;
    required?: string[];
  };
}

interface ContractError {
  code: string;
  category: string;
  retryable: boolean;
  message: string;
}

interface ContractCapability {
  id: string;
  description: string;
  permissions: string[];
  tools: string[];
}

interface Contract {
  protocolVersion: number;
  identity: {
    nativeMessagingHostId: string;
    extensionManifestKey: string;
    pinnedExtensionId: string;
  };
  tools: ContractTool[];
  errors: ContractError[];
  capabilities: ContractCapability[];
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// The Rust core is the source: run its contract emitter. `-q` keeps cargo's
// own output off the pipe; a compile error still lands on stderr and fails
// loudly here.
const emitted = Bun.spawnSync(
  ["cargo", "run", "-q", "-p", "chromium-bridge-core", "--example", "emit_contract"],
  { cwd: root, stderr: "inherit" },
);
if (!emitted.success) {
  throw new Error(`gen-ops: cargo emit_contract failed with status ${emitted.exitCode}`);
}
const contract = JSON.parse(emitted.stdout.toString()) as Contract;

// Args that exist only for the MCP server: `browser` picks which connected
// browser a call routes to and is consumed there - it is never forwarded
// inside the bridge request's args. Excluded here so the extension-facing
// shapes describe only what the extension can actually receive.
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
// the generated validator - weaker validation than the catalogue claims - so
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

// Distinct values for each metadata field, so the unions stay in sync with
// the catalogue (add a new risk level in catalogue.rs and it appears here).
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
const argSchema = (t: ContractTool): string => {
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

const opsOut = `// GENERATED from the Rust core (src/packages/core/src/tools/catalogue.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run \`just gen\`.
//
// The tool catalogue, TS side: op names, policy metadata (risk / scope /
// permission / confirmation), and the per-op Zod arg validators the extension
// enforces at the native-messaging boundary. BridgeCommand (the discriminated
// request union) is INFERRED from the validators, so the compile-time types
// and the runtime checks cannot drift apart.

import { z } from "zod";

export const OP_NAMES = [
  ${opNames},
] as const;

export type OpName = (typeof OP_NAMES)[number];

const OP_NAME_SET: ReadonlySet<string> = new Set(OP_NAMES);

export function isOpName(op: string): op is OpName {
  return OP_NAME_SET.has(op);
}

// Policy metadata, mirrored from the catalogue. Consumed by the policy layer
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
// all optional (the per-op validators enforce required-ness).
export const OpArgsSchema = z.strictObject({
${opArgsFields}
});

export type OpArgs = z.infer<typeof OpArgsSchema>;
`;

writeFileSync(join(root, "src/packages/shared/src/ops.gen.ts"), opsOut);
console.log("generated src/packages/shared/src/ops.gen.ts from the Rust catalogue");

// ---- errors.gen.ts ----------------------------------------------------------

const errorCodes = contract.errors.map((e) => JSON.stringify(e.code)).join(",\n  ");
const errorMeta = contract.errors
  .map(
    (e) =>
      `  ${emitKey(e.code)}: {\n` +
      `    category: ${JSON.stringify(e.category)},\n` +
      `    retryable: ${e.retryable},\n` +
      `    message: ${JSON.stringify(e.message)},\n` +
      `  },`,
  )
  .join("\n");

const errorsOut = `// GENERATED from the Rust core (src/packages/core/src/error.rs ERROR_SPECS) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the taxonomy, then run \`just gen\`.
//
// The stable cross-process error codes. The Rust server assigns them via
// CallError::code(); the extension reports its own failures with the same
// codes so neither side can invent one the other has never heard of.

export const ERROR_CODES = [
  ${errorCodes},
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export type ErrorCategory = ${[...new Set(contract.errors.map((e) => e.category))]
  .sort()
  .map((v) => JSON.stringify(v))
  .join(" | ")};

export interface ErrorMeta {
  category: ErrorCategory;
  /** Whether retrying the same call can plausibly succeed unchanged. */
  retryable: boolean;
  /** The user/model-facing default message for the code. */
  message: string;
}

export const ERROR_META: Readonly<Record<ErrorCode, ErrorMeta>> = {
${errorMeta}
};
`;

writeFileSync(join(root, "src/packages/shared/src/errors.gen.ts"), errorsOut);
console.log("generated src/packages/shared/src/errors.gen.ts from the Rust taxonomy");

// ---- protocol.gen.ts --------------------------------------------------------

const capabilityItems = contract.capabilities
  .map(
    (c) =>
      `  {\n` +
      `    id: ${JSON.stringify(c.id)},\n` +
      `    permissions: [${c.permissions.map((p) => JSON.stringify(p)).join(", ")}],\n` +
      `    tools: [${c.tools.map((t) => JSON.stringify(t)).join(", ")}],\n` +
      `  },`,
  )
  .join("\n");

const protocolOut = `// GENERATED from the Rust core (src/packages/core/src/protocol.rs and
// src/packages/core/src/tools/capabilities.rs) by scripts/gen-ops.ts - DO NOT EDIT.
// Run \`just gen\`.

// The INTERNAL bridge protocol version (MCP server <-> native host <->
// extension). Not the MCP JSON-RPC version and not the extension release
// version; bumped only when the bridge wire contract changes incompatibly.
export const BRIDGE_PROTOCOL_VERSION = ${contract.protocolVersion};

// The capability groupings for connection-time negotiation: each capability
// covers a set of tools sharing a Chrome permission. On connect the extension
// advertises which capability ids are actually available; a tool is callable
// only if its capability is advertised.
export interface CapabilityInfo {
  id: string;
  permissions: readonly string[];
  tools: readonly string[];
}

export const CAPABILITIES: readonly CapabilityInfo[] = [
${capabilityItems}
];
`;

writeFileSync(join(root, "src/packages/shared/src/protocol.gen.ts"), protocolOut);
console.log("generated src/packages/shared/src/protocol.gen.ts from the Rust core");

// ---- identity.gen.ts ----------------------------------------------------------

const { extensionManifestKey, nativeMessagingHostId, pinnedExtensionId } = contract.identity;
if (typeof extensionManifestKey !== "string" || extensionManifestKey.length === 0) {
  throw new Error("gen-ops: the emitted contract has no extensionManifestKey");
}
// Chrome's id derivation: sha256 of the DER key, first 16 bytes, hex mapped
// onto a-p. Same computation as scripts/check-extension-id.ts.
const hex = createHash("sha256")
  .update(Buffer.from(extensionManifestKey, "base64"))
  .digest("hex")
  .slice(0, 32);
const extensionId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");

// The Rust core also pins the derived id as a constant (identity.rs, used by
// the registration engine's allowed_origins). It must be exactly what the
// key derives, or the pin has drifted from the key.
if (pinnedExtensionId !== extensionId) {
  throw new Error(
    `gen-ops: identity.rs PINNED_EXTENSION_ID=${pinnedExtensionId} but the key derives ${extensionId}`,
  );
}

// Chrome's charset for host names: dot-separated segments of [a-z0-9_], so
// no leading/trailing dots and no empty segments.
if (
  typeof nativeMessagingHostId !== "string" ||
  !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(nativeMessagingHostId)
) {
  throw new Error("gen-ops: nativeMessagingHostId violates Chrome's charset");
}

const identityOut = `// GENERATED from the Rust core (src/packages/core/src/identity.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Run \`just gen\`.
//
// The bridge's identity constants. PINNED_EXTENSION_ID is DERIVED from
// EXTENSION_MANIFEST_KEY (Chrome's own id derivation), so it cannot drift
// from the generated manifest. scripts/check-extension-id.ts verifies the
// installers and the built manifest against the same values.

// The extension ID Chrome derives from the manifest \`key\`. The native-
// messaging host manifest pins this in \`allowed_origins\`, so a build without
// the pinned key is rejected by the host.
export const PINNED_EXTENSION_ID = ${JSON.stringify(extensionId)};

// The extension's pinned manifest \`key\` (base64 DER public key).
// src/apps/extension/wxt.config.ts injects it into the generated manifest.
export const EXTENSION_MANIFEST_KEY =
  ${JSON.stringify(extensionManifestKey)};

// The native-messaging host id: what the extension passes to connectNative,
// what the Rust host expects, and the host manifest's name/filename stem.
export const NATIVE_HOST_ID = ${JSON.stringify(nativeMessagingHostId)};
`;

writeFileSync(join(root, "src/packages/shared/src/identity.gen.ts"), identityOut);
console.log("generated src/packages/shared/src/identity.gen.ts from the Rust core");
