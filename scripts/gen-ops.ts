// Generate the contract-derived TypeScript from the Rust core, the canonical
// contract source (ADR-0028). Runs the core's `emit_contract` example to get
// the contract as JSON, then writes the src/packages/shared *.gen.ts modules.
// Run `moon run gen` after editing the catalogue/taxonomy in src/packages/core; CI
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
//   src/packages/shared/src/audit.gen.ts     - the extension-owned audit kinds
//     the host forwards into its on-disk trail (the audit_event whitelist).
//   src/packages/shared/src/enclave.gen.ts   - the enclave signing contract:
//     domain-separation strings, challenge field bounds, key/signature byte
//     lengths, and the enclave_error reason-code union.
//   src/packages/shared/src/enclave-fixture.gen.ts - golden vectors for the
//     signed-message encoding: Rust-built message bytes and deterministic
//     software-P256 proofs the extension's test suite replays through its
//     WebCrypto verifier.
//   src/packages/shared/src/policy.gen.ts    - the host-owned policy contract
//     (ADR-0032): the signing domain, the field catalogue with per-field
//     permissive directions, the strict document/values validators, the
//     deny-baseline defaults, and the per-field salvage helper.

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
  mcpProtocolVersion: string;
  mcpMetaKeys: {
    protocolVersion: string;
    clientCapabilities: string;
    serverInfo: string;
  };
  auditForwardedKinds: string[];
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
// scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run \`moon run gen\`.
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
// scripts/gen-ops.ts - DO NOT EDIT. Edit the taxonomy, then run \`moon run gen\`.
//
// The stable error codes of the cross-process taxonomy. Today only the Rust
// server assigns them, and only a subset: CallError failures map to their
// codes via CallError::code(). The extension reports its failures as
// free-form strings (see port.ts sendResponse), which the host surfaces as
// EXECUTION_FAILED. Of the unassigned codes, PROTOCOL_MISMATCH awaits the
// version/capability handshake wiring (docs/compatibility.md); the others
// would need structured error reporting from the extension in place of
// those free-form strings. These constants exist for TS consumers of the
// taxonomy and are currently unconsumed.

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

// The MCP revision is a date string pinned by the spec; anything else means
// the emitter and this generator disagree about the field.
if (!/^\d{4}-\d{2}-\d{2}$/.test(contract.mcpProtocolVersion)) {
  throw new Error(
    `gen-ops: mcpProtocolVersion ${JSON.stringify(contract.mcpProtocolVersion)} is not a date string`,
  );
}

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
// Run \`moon run gen\`.

// The INTERNAL bridge protocol version (MCP server <-> native host <->
// extension). Not the MCP JSON-RPC version and not the extension release
// version; bumped only when the bridge wire contract changes incompatibly.
export const BRIDGE_PROTOCOL_VERSION = ${contract.protocolVersion};

// The newest MCP JSON-RPC protocol revision the Rust server serves
// (protocol.rs MCP_PROTOCOL_VERSION, per docs/adr/0034): advertised by
// \`server/discover\` in \`supportedVersions\`.
export const MCP_PROTOCOL_VERSION = ${JSON.stringify(contract.mcpProtocolVersion)};

// The \`_meta\` key strings of the stateless era (ADR-0034), single-sourced
// from protocol.rs. Every stateless request's \`params._meta\` MUST carry
// BOTH the protocol version and the client capabilities (an empty object
// suffices); the server/discover result carries the server identity under
// the serverInfo key.
export const MCP_META_PROTOCOL_VERSION = ${JSON.stringify(contract.mcpMetaKeys.protocolVersion)};
export const MCP_META_CLIENT_CAPABILITIES = ${JSON.stringify(contract.mcpMetaKeys.clientCapabilities)};
export const MCP_META_SERVER_INFO = ${JSON.stringify(contract.mcpMetaKeys.serverInfo)};

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
// scripts/gen-ops.ts - DO NOT EDIT. Run \`moon run gen\`.
//
// The bridge's identity constants. PINNED_EXTENSION_ID is DERIVED from
// EXTENSION_MANIFEST_KEY (Chrome's own id derivation), so it cannot drift
// from the generated manifest. scripts/check-extension-id.ts verifies the
// built manifest against the same values.

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

// ---- audit.gen.ts -------------------------------------------------------------
// Self-contained: consumes only contract.auditForwardedKinds.

const forwardedKinds = contract.auditForwardedKinds;
if (!Array.isArray(forwardedKinds) || forwardedKinds.length === 0) {
  throw new Error("gen-ops: the emitted contract has no auditForwardedKinds");
}
for (const kind of forwardedKinds) {
  // The kinds are serde snake_case wire names; anything else means the
  // emitter and this generator disagree about the field.
  if (typeof kind !== "string" || !/^[a-z][a-z0-9_]*$/.test(kind)) {
    throw new Error(
      `gen-ops: auditForwardedKinds carries a non-snake_case kind ${JSON.stringify(kind)}`,
    );
  }
}
if (new Set(forwardedKinds).size !== forwardedKinds.length) {
  throw new Error("gen-ops: auditForwardedKinds carries a duplicate kind");
}

const auditOut = `// GENERATED from the Rust core (src/packages/core/src/audit.rs
// EXTENSION_AUDIT_KINDS) by scripts/gen-ops.ts - DO NOT EDIT. Edit the kind
// list, then run \`moon run gen\`.
//
// The audit kinds the host accepts over the extension's audit_event control
// frame (audit::extension_kind, ADR-0030). The extension's forwarding set
// (background/audit-log.ts) and the forwarded prefix of its audit-ring
// vocabulary (shared/enclave.ts AUDIT_EVENT_KINDS) build on this, so the two
// sides of the forwarding boundary cannot drift apart.

export const AUDIT_FORWARDED_KINDS = [
  ${forwardedKinds.map((k) => JSON.stringify(k)).join(",\n  ")},
] as const;

export type AuditForwardedKind = (typeof AUDIT_FORWARDED_KINDS)[number];
`;

writeFileSync(join(root, "src/packages/shared/src/audit.gen.ts"), auditOut);
console.log("generated src/packages/shared/src/audit.gen.ts from the Rust audit whitelist");
// ---- enclave.gen.ts + enclave-fixture.gen.ts --------------------------------
// Self-contained section: the enclave signing contract has its own Rust
// emitter (examples/emit_enclave_contract.rs) so this block shares no state
// with the emit_contract flow above.

interface EnclaveVector {
  domain: "challenge" | "presence";
  nonce: string;
  context: string | null;
  messageHex: string;
  sigB64: string;
}

interface EnclaveContract {
  challengeDomain: string;
  presenceDomain: string;
  maxNonceLen: number;
  maxContextLen: number;
  pubkeyLen: number;
  sigLen: number;
  reasonCodes: string[];
  fixture: {
    pubkeyB64: string;
    keyIdHex: string;
    vectors: EnclaveVector[];
  };
}

const enclaveEmitted = Bun.spawnSync(
  ["cargo", "run", "-q", "-p", "chromium-bridge-core", "--example", "emit_enclave_contract"],
  { cwd: root, stderr: "inherit" },
);
if (!enclaveEmitted.success) {
  throw new Error(
    `gen-ops: cargo emit_enclave_contract failed with status ${enclaveEmitted.exitCode}`,
  );
}
const enclave = JSON.parse(enclaveEmitted.stdout.toString()) as EnclaveContract;

// Structural sanity only - the values themselves are the Rust side's to
// choose. Anything malformed here would generate a silently weaker verifier,
// so fail generation instead.
for (const domain of [enclave.challengeDomain, enclave.presenceDomain]) {
  if (typeof domain !== "string" || domain.length === 0 || domain.includes("\0")) {
    throw new Error(`gen-ops: malformed enclave domain string ${JSON.stringify(domain)}`);
  }
}
if (enclave.challengeDomain === enclave.presenceDomain) {
  throw new Error("gen-ops: the enclave challenge and presence domains must differ");
}
for (const bound of [
  enclave.maxNonceLen,
  enclave.maxContextLen,
  enclave.pubkeyLen,
  enclave.sigLen,
]) {
  if (!Number.isInteger(bound) || bound <= 0) {
    throw new Error(`gen-ops: enclave bound ${JSON.stringify(bound)} is not a positive integer`);
  }
}
if (
  enclave.reasonCodes.length === 0 ||
  new Set(enclave.reasonCodes).size !== enclave.reasonCodes.length
) {
  throw new Error("gen-ops: the enclave reason codes must be non-empty and distinct");
}
if (enclave.fixture.vectors.length === 0) {
  throw new Error("gen-ops: the enclave golden fixture has no vectors");
}
for (const v of enclave.fixture.vectors) {
  if (!/^([0-9a-f]{2})+$/.test(v.messageHex)) {
    throw new Error(`gen-ops: fixture vector for nonce ${JSON.stringify(v.nonce)} has bad hex`);
  }
}
if (!/^[0-9a-f]{64}$/.test(enclave.fixture.keyIdHex)) {
  throw new Error("gen-ops: the fixture key id is not a lowercase-hex SHA-256");
}

// String emitter for every emitted enclave string: JSON.stringify plus \u
// escapes for everything non-ASCII, so a non-ASCII value (deliberate in the
// multi-byte UTF-8 vectors, accidental anywhere else) keeps the generated
// file plain ASCII instead of tripping the typography gate downstream.
const emitAsciiString = (s: string): string =>
  JSON.stringify(s).replace(
    /[\u0080-\uffff]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );

const reasonCodes = enclave.reasonCodes.map((r) => emitAsciiString(r)).join(",\n  ");

const enclaveOut = `// GENERATED from the Rust core (src/packages/core/src/enclave/challenge.rs,
// pubkey.rs, der.rs, and mod.rs REASON_CODES) by scripts/gen-ops.ts - DO NOT
// EDIT. Edit the enclave module, then run \`moon run gen\`.
//
// The enclave signing contract, TS side: the constants the extension's
// WebCrypto verifier (background/enclave-verify.ts) and the enrollment state
// machine (background/enrollment.ts) enforce. The signed-message ALGORITHM
// (NUL-separated domain || nonce || context, ECDSA P-256/SHA-256) is pinned
// separately by the golden vectors in enclave-fixture.gen.ts.

// Domain-separation prefixes: enrollment challenge signatures (ADR-0021) and
// per-action user-presence signatures (ADR-0031) sign under distinct domains,
// so the two statement types can never be replayed as one another.
export const CHALLENGE_DOMAIN = ${emitAsciiString(enclave.challengeDomain)};
export const PRESENCE_DOMAIN = ${emitAsciiString(enclave.presenceDomain)};

// Host-enforced bounds on challenge fields, in UTF-8 bytes (Rust's
// MAX_NONCE_LEN / MAX_CONTEXT_LEN). The verifier rejects anything outside
// them before touching the crypto.
export const MAX_NONCE_BYTES = ${enclave.maxNonceLen};
export const MAX_CONTEXT_BYTES = ${enclave.maxContextLen};

// Wire byte lengths of the proof fields: the X9.63 uncompressed P-256 point
// and the raw IEEE P1363 r||s signature.
export const PUBKEY_LEN = ${enclave.pubkeyLen};
export const SIG_LEN = ${enclave.sigLen};

// The closed set of enclave_error.reason codes the host can emit
// (reason_code in src/packages/core/src/enclave/mod.rs; append-only). The
// enrollment state machine branches on these - its compromise latch fires on
// a subset - so an unrecognized code must degrade to a refusal, never match.
export const ENCLAVE_REASON_CODES = [
  ${reasonCodes},
] as const;

export type EnclaveReasonCode = (typeof ENCLAVE_REASON_CODES)[number];

const ENCLAVE_REASON_SET: ReadonlySet<string> = new Set(ENCLAVE_REASON_CODES);

export function isEnclaveReasonCode(reason: string): reason is EnclaveReasonCode {
  return ENCLAVE_REASON_SET.has(reason);
}

// Fingerprint of the PUBLIC golden-fixture signing key (FIXTURE_KEY_BYTES /
// FIXTURE_KEY_ID in src/packages/core/src/enclave/mod.rs). Its private
// scalar is checked into the repo, so anyone can sign fresh challenges with
// it: it must never become an enrollment identity. The pairing verifier
// (background/enclave-verify.ts) and the stored-pin validators (enclave.ts)
// refuse it fail-closed; the host refuses it in EnrollmentKey::public_key.
export const ENCLAVE_FIXTURE_KEY_ID =
  ${JSON.stringify(enclave.fixture.keyIdHex)};
`;

writeFileSync(join(root, "src/packages/shared/src/enclave.gen.ts"), enclaveOut);
console.log("generated src/packages/shared/src/enclave.gen.ts from the Rust enclave module");

const vectorItems = enclave.fixture.vectors
  .map(
    (v) =>
      `  {\n` +
      `    domain: ${JSON.stringify(v.domain)},\n` +
      `    nonce: ${emitAsciiString(v.nonce)},\n` +
      `    context: ${v.context === null ? "null" : emitAsciiString(v.context)},\n` +
      `    messageHex: ${JSON.stringify(v.messageHex)},\n` +
      `    sigB64: ${JSON.stringify(v.sigB64)},\n` +
      `  },`,
  )
  .join("\n");

const fixtureOut = `// GENERATED from the Rust core (examples/emit_enclave_contract.rs, over
// src/packages/core/src/enclave/) by scripts/gen-ops.ts - DO NOT EDIT.
// Run \`moon run gen\`.
//
// Golden vectors pinning the cross-language enclave crypto contract: each
// message is built by the Rust challenge_message/presence_message and each
// signature is a deterministic (RFC 6979) software-P256 proof routed through
// the host's DER -> P1363 converter, over the PUBLIC fixture key. The
// extension test suite replays these through its WebCrypto verifier
// (tests/background/enclave-golden.test.ts), so a Rust-side encoding change
// regenerates this file (check-gen) and a lagging TS verifier fails the
// replay. The key protects nothing and is deny-listed as an enrollment
// identity on both sides (ENCLAVE_FIXTURE_KEY_ID in enclave.gen.ts).
//
// Test-only data: import it via "@chromium-bridge/shared/testing", never
// from the production barrel.

export interface EnclaveGoldenVector {
  /** Which domain-separation prefix the message was built under. */
  domain: "challenge" | "presence";
  nonce: string;
  /** null = the Rust side signed with no context (None). */
  context: string | null;
  /** The exact bytes the signature covers, hex-encoded. */
  messageHex: string;
  /** Raw ${enclave.sigLen}-byte IEEE P1363 signature over messageHex, base64. */
  sigB64: string;
}

export interface EnclaveGoldenFixture {
  /** Base64 of the ${enclave.pubkeyLen}-byte X9.63 uncompressed public point. */
  pubkeyB64: string;
  /** Lowercase-hex SHA-256 of the raw pubkey bytes (the key_id). */
  keyIdHex: string;
  vectors: readonly EnclaveGoldenVector[];
}

export const ENCLAVE_GOLDEN_FIXTURE: EnclaveGoldenFixture = {
  pubkeyB64: ${JSON.stringify(enclave.fixture.pubkeyB64)},
  keyIdHex: ${JSON.stringify(enclave.fixture.keyIdHex)},
  vectors: [
${vectorItems}
  ],
};
`;

writeFileSync(join(root, "src/packages/shared/src/enclave-fixture.gen.ts"), fixtureOut);
console.log(
  "generated src/packages/shared/src/enclave-fixture.gen.ts from the Rust enclave module",
);

// ---- policy.gen.ts -----------------------------------------------------------
// Self-contained section (the enclave pattern): the policy contract has its
// own Rust emitter (examples/emit_policy_contract.rs). The one deliberate
// cross-reference is the domain-separation check against the enclave
// contract parsed above: the policy signing domain must be a THIRD domain,
// distinct from both enclave domains, or a policy signature could be
// replayed as an enrollment or presence proof.

const POLICY_DIRECTION_TAGS = [
  "truePermissive",
  "falsePermissive",
  "growsPermissive",
  "growsPermissiveZeroTop",
  "shrinksPermissiveSet",
] as const;

type PolicyDirectionTag = (typeof POLICY_DIRECTION_TAGS)[number];

interface PolicyContractField {
  name: string;
  direction: PolicyDirectionTag;
}

interface PolicyContract {
  policyDomain: string;
  docVersion: number;
  revisionMax: number;
  disabledToolsMaxEntries: number;
  disabledToolNameMaxBytes: number;
  fields: PolicyContractField[];
  defaults: Record<string, unknown>;
  docDefaults: { v: number; revision: number; touched: unknown[] };
}

const policyEmitted = Bun.spawnSync(
  ["cargo", "run", "-q", "-p", "chromium-bridge-core", "--example", "emit_policy_contract"],
  { cwd: root, stderr: "inherit" },
);
if (!policyEmitted.success) {
  throw new Error(
    `gen-ops: cargo emit_policy_contract failed with status ${policyEmitted.exitCode}`,
  );
}
const policy = JSON.parse(policyEmitted.stdout.toString()) as PolicyContract;

// Structural sanity only - the values themselves are the Rust side's to
// choose. Anything malformed here would generate a silently weaker validator
// or a mislabeled direction table, so fail generation instead.
if (
  typeof policy.policyDomain !== "string" ||
  policy.policyDomain.length === 0 ||
  policy.policyDomain.includes("\0") ||
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the NUL-free, ASCII-only domain check is the point
  !/^[\x01-\x7f]+$/.test(policy.policyDomain)
) {
  throw new Error(`gen-ops: malformed policy domain string ${JSON.stringify(policy.policyDomain)}`);
}
if (
  policy.policyDomain === enclave.challengeDomain ||
  policy.policyDomain === enclave.presenceDomain
) {
  throw new Error("gen-ops: the policy domain must differ from both enclave domains");
}
if (!Number.isInteger(policy.docVersion) || policy.docVersion <= 0) {
  throw new Error(
    `gen-ops: policy docVersion ${JSON.stringify(policy.docVersion)} is not a positive integer`,
  );
}
if (policy.revisionMax !== Number.MAX_SAFE_INTEGER) {
  throw new Error(
    `gen-ops: policy revisionMax ${JSON.stringify(policy.revisionMax)} is not Number.MAX_SAFE_INTEGER`,
  );
}
if (
  !Number.isInteger(policy.disabledToolsMaxEntries) ||
  policy.disabledToolsMaxEntries <= 0 ||
  !Number.isInteger(policy.disabledToolNameMaxBytes) ||
  policy.disabledToolNameMaxBytes <= 0
) {
  throw new Error("gen-ops: the disabledTools bounds must be positive integers");
}
if (!Array.isArray(policy.fields) || policy.fields.length !== 15) {
  throw new Error(`gen-ops: expected 15 policy fields, got ${policy.fields?.length}`);
}
for (const field of policy.fields) {
  if (typeof field.name !== "string" || !/^[a-z][A-Za-z0-9]*$/.test(field.name)) {
    throw new Error(`gen-ops: policy field name ${JSON.stringify(field.name)} is not camelCase`);
  }
  if (!(POLICY_DIRECTION_TAGS as readonly string[]).includes(field.direction)) {
    throw new Error(
      `gen-ops: policy field ${field.name} carries unknown direction ${JSON.stringify(field.direction)}`,
    );
  }
}
const policyFieldNames = policy.fields.map((f) => f.name);
if (new Set(policyFieldNames).size !== policyFieldNames.length) {
  throw new Error("gen-ops: the policy field names must be distinct");
}
if (
  Object.keys(policy.defaults).length !== policyFieldNames.length ||
  !policyFieldNames.every((name) => name in policy.defaults)
) {
  throw new Error("gen-ops: the policy defaults keys must be exactly the field names");
}
if (policy.docDefaults.v !== policy.docVersion) {
  throw new Error("gen-ops: the default policy document disagrees with docVersion");
}

// The direction tag determines a field's value shape - a boolean pole is a
// boolean field, a grow direction is a millisecond count, the shrink-set
// direction is the tool list - and the emitted default must already inhabit
// it. A mismatch means the Rust catalogue and this derivation disagree, so
// fail generation rather than emit a validator that rejects the defaults.
const policyZodType = (field: PolicyContractField): string => {
  const dflt = policy.defaults[field.name];
  switch (field.direction) {
    case "truePermissive":
    case "falsePermissive":
      if (typeof dflt !== "boolean") {
        throw new Error(`gen-ops: policy field ${field.name} has a non-boolean default`);
      }
      return "z.boolean()";
    case "growsPermissive":
    case "growsPermissiveZeroTop":
      if (!Number.isInteger(dflt) || (dflt as number) < 0) {
        throw new Error(`gen-ops: policy field ${field.name} has a non-integer default`);
      }
      return "z.int().nonnegative()";
    case "shrinksPermissiveSet":
      if (!Array.isArray(dflt) || !dflt.every((t) => typeof t === "string")) {
        throw new Error(`gen-ops: policy field ${field.name} has a non-string-array default`);
      }
      return `z.array(z.string().min(1).max(${policy.disabledToolNameMaxBytes})).max(${policy.disabledToolsMaxEntries})`;
  }
};

const policyDefaultsJson = JSON.stringify(policy.defaults);
if (!/^[\x20-\x7e]*$/.test(policyDefaultsJson)) {
  throw new Error("gen-ops: the policy defaults carry non-ASCII content");
}

const policyFieldNameItems = policyFieldNames.map((n) => JSON.stringify(n)).join(",\n  ");
const policyDirectionItems = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${JSON.stringify(f.direction)},`)
  .join("\n");
const policyValueFields = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${policyZodType(f)},`)
  .join("\n");
const policyDefaultItems = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${JSON.stringify(policy.defaults[f.name])},`)
  .join("\n");

const policyOut = `// GENERATED from the Rust core (src/packages/core/src/policy/mod.rs and the
// POLICY_DOMAIN in src/packages/core/src/enclave/challenge.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the policy module, then run
// \`moon run gen\`.
//
// The host-owned policy contract, TS side (ADR-0032): the signing domain,
// the field catalogue with each field's declared permissive direction, the
// strict Zod validators for the signed document and its detached values,
// the deny-baseline defaults, the strict stored-policy parser, and the
// import-bag salvage helper. The
// extension recomputes every relax/restrict comparison from the direction
// table itself - it never trusts a host's claim about which way a change
// points - and verifies signed baselines under POLICY_DOMAIN against its
// pinned key before strict-parsing the same bytes with PolicyDocSchema.

import { z } from "zod";

// Domain-separation prefix for policy signatures: the enrollment key signs
// UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes. A third domain, distinct from
// the enclave challenge and presence domains (generation fails otherwise),
// so a policy signature can never be replayed as an enrollment or
// per-action presence proof, nor either of those as a policy.
export const POLICY_DOMAIN = ${JSON.stringify(policy.policyDomain)};

// The policy document schema version. PolicyDocSchema pins it as a literal:
// a newer document is rejected rather than misinterpreted, the same
// fail-closed posture as the Rust parser's deny_unknown_fields.
export const POLICY_DOC_VERSION = ${policy.docVersion};

// The JS-safe integer bound (2^53 - 1) on the document's revision counter
// and (Rust-side, via the same JS_SAFE_INT_MAX) its millisecond fields, so
// both sides' parsers read the same numbers.
export const POLICY_REVISION_MAX = ${policy.revisionMax};

// Bounds on disabledTools (Rust DISABLED_TOOLS_MAX_ENTRIES /
// DISABLED_TOOL_NAME_MAX_BYTES), enforced by the schemas below so the two
// sides' parsers stay equivalent and no list can outgrow the host store's
// read cap. The Rust bound counts bytes, this one UTF-16 code units; tool
// names are ASCII identifiers, where the two agree, and elsewhere the Rust
// side is the stricter, fail-closed one.
export const DISABLED_TOOLS_MAX_ENTRIES = ${policy.disabledToolsMaxEntries};
export const DISABLED_TOOL_NAME_MAX_BYTES = ${policy.disabledToolNameMaxBytes};

// The host-owned policy fields, in the catalogue's declaration order. An
// unknown name never parses (touched entries ride z.enum over this list),
// so a touched set cannot smuggle a field the catalogue does not own.
export const POLICY_FIELDS = [
  ${policyFieldNameItems},
] as const;

export type PolicyFieldName = (typeof POLICY_FIELDS)[number];

const POLICY_FIELD_SET: ReadonlySet<string> = new Set(POLICY_FIELDS);

export function isPolicyFieldName(field: string): field is PolicyFieldName {
  return POLICY_FIELD_SET.has(field);
}

// A field's declared permissive pole (Rust Direction): the value direction
// that grants capability. "truePermissive"/"falsePermissive" are the
// boolean poles; "growsPermissive" millisecond windows grant as they grow;
// "growsPermissiveZeroTop" is hostReverifyMs's custom order (0 = never
// re-verify = MOST permissive, topping the scale); "shrinksPermissiveSet"
// is disabledTools (dropping an entry re-enables a tool).
export type PolicyDirection =
  | "truePermissive"
  | "falsePermissive"
  | "growsPermissive"
  | "growsPermissiveZeroTop"
  | "shrinksPermissiveSet";

export const POLICY_DIRECTIONS: Readonly<Record<PolicyFieldName, PolicyDirection>> = {
${policyDirectionItems}
};

// The 15 field values, detached from the document's scoping fields (Rust
// PolicyValues): the shape comparisons and the effective policy work in.
export const PolicyValuesSchema = z.strictObject({
${policyValueFields}
});

export type PolicyValues = z.infer<typeof PolicyValuesSchema>;

// The signed policy document (Rust PolicyDoc): the exact bytes the enclave
// signature covers, strict-parsed only AFTER the signature verifies.
// \`touched\` is the set of fields the producing write explicitly edited,
// inside the signed bytes so a fresh signature warrants relaxation on
// exactly those fields, never on the document at large.
export const PolicyDocSchema = z.strictObject({
  v: z.literal(${policy.docVersion}),
  revision: z.int().nonnegative().max(POLICY_REVISION_MAX),
  touched: z.array(z.enum(POLICY_FIELDS)),
${policyValueFields}
});

export type PolicyDoc = z.infer<typeof PolicyDocSchema>;

// Frozen (including the nested array): salvage hands these instances out as
// fallbacks, so a caller mutating its "copy" must throw instead of quietly
// rewriting the defaults for everyone after it.
export const POLICY_DEFAULTS: Readonly<PolicyValues> = deepFreeze(
  PolicyValuesSchema.parse({
${policyDefaultItems}
  }),
);

function deepFreeze<T>(value: T): T {
  for (const inner of Object.values(value as object)) {
    if (typeof inner === "object" && inner !== null) deepFreeze(inner);
  }
  return Object.freeze(value);
}

/**
 * Per-field salvage for the LEGACY-SETTINGS IMPORT BAG ONLY (ADR-0032
 * decision 8 / phase 4): the snapshotted chrome.storage bag rides
 * \`legacy_settings\` to the app's first-run import screen, where a corrupt
 * field falling back to its deny-baseline default is SHOWN to the user and
 * signed under their tap - never silently enforced. A value that fails its
 * own schema falls back to that field's default without discarding the
 * healthy fields around it, and unknown keys are dropped.
 *
 * NEVER parse the stored effective policy with this. Per-field default
 * fallback moves a corrupt field toward its permissive pole relative to a
 * user-restricted policy - a relaxation lever made of garbage, exactly the
 * "garbage in, defaults out" behavior ADR-0032 decision 4 forbids. The
 * stored effective policy is read with parseStoredPolicyValues below.
 */
export function salvagePolicyValues(stored: unknown): PolicyValues {
  const bag: Record<string, unknown> =
    typeof stored === "object" && stored !== null ? (stored as Record<string, unknown>) : {};
  return Object.fromEntries(
    Object.entries(PolicyValuesSchema.shape).map(([key, schema]) => {
      const parsed = schema.safeParse(bag[key]);
      return [key, parsed.success ? parsed.data : POLICY_DEFAULTS[key as PolicyFieldName]];
    }),
  ) as PolicyValues;
}

/**
 * Strict parse of the extension's stored effective policy - phase 3's
 * ratchet anchor and every stored-effective read use THIS. Returns the
 * exact values on a valid bag and \`null\` on ANY failure (a corrupt field,
 * a non-object, an extra key). \`null\` means "no stored effective": the
 * deny baseline applies and there is no ratchet state to anchor on
 * (ADR-0032 decision 4) - never a salvage, which would hand a corrupted
 * store a relaxation.
 */
export function parseStoredPolicyValues(stored: unknown): PolicyValues | null {
  const parsed = PolicyValuesSchema.safeParse(stored);
  return parsed.success ? parsed.data : null;
}
`;

writeFileSync(join(root, "src/packages/shared/src/policy.gen.ts"), policyOut);
console.log("generated src/packages/shared/src/policy.gen.ts from the Rust policy module");
