// Generate the contract-derived TypeScript from the Rust core, the canonical contract source, by running the
// core's emitter examples. Run `moon run gen` after editing the catalogue, taxonomy, enclave, or policy module
// in src/packages/core; CI regenerates and fails on a stale diff.
//
//   emit_contract          -> ops.gen.ts, errors.gen.ts, protocol.gen.ts, identity.gen.ts, audit.gen.ts
//   emit_enclave_contract  -> enclave.gen.ts, enclave-fixture.gen.ts
//   emit_policy_contract   -> policy.gen.ts

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { convert, prepare } from "./gen-envelope";

interface ContractTool {
  name: string;
  risk: string;
  scope: string;
  permission: string;
  confirmation: string;
  /** The policy fields (wire names) that must be true for the tool to run. */
  grants: string[];
  description: string;
  /** The schemars schema of the tool's args struct, as the extension receives the args. */
  argsSchema: unknown;
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
  /** The host's user-facing constants (what the docs state and the CLI prints); HostSchema parses it. */
  host: unknown;
}

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// `-q` keeps cargo's own output off the pipe; a compile error still lands on stderr and fails loudly here.
const emitted = Bun.spawnSync(
  ["cargo", "run", "--frozen", "-q", "-p", "chromium-bridge-core", "--example", "emit_contract"],
  { cwd: root, stderr: "inherit" },
);
if (!emitted.success) {
  throw new Error(`gen-ops: cargo emit_contract failed with status ${emitted.exitCode}`);
}
const contract = JSON.parse(emitted.stdout.toString()) as Contract;

// Bare when a valid JS identifier, quoted otherwise: Biome's quoteProperties "as-needed" would reformat anything else.
const emitKey = (key: string): string =>
  /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : JSON.stringify(key);

// ---- ops.gen.ts pieces ------------------------------------------------------

const opNames = contract.tools.map((t) => JSON.stringify(t.name)).join(",\n  ");

// The unions follow the catalogue: a new risk level in catalogue.rs appears here unasked.
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

// Each tool's args schema goes through the envelope generator's fail-closed rules (scripts/gen-envelope.ts), so a
// struct the rules cannot model faithfully aborts generation here too.
const preparedArgs = new Map<string, Record<string, unknown>>();
for (const t of contract.tools) {
  const prepared = prepare(t.argsSchema, `$.tools.${t.name}.args`);
  if (typeof prepared !== "object" || prepared === null || Array.isArray(prepared)) {
    throw new Error(`gen-ops: ${t.name} args schema did not prepare to an object schema`);
  }
  preparedArgs.set(t.name, prepared as Record<string, unknown>);
}
const preparedArgsOf = (t: ContractTool): Record<string, unknown> => {
  const prepared = preparedArgs.get(t.name);
  if (prepared === undefined) throw new Error(`gen-ops: no prepared args for ${t.name}`);
  return prepared;
};

const argSchemas = contract.tools
  .map((t) => `  ${emitKey(t.name)}: ${convert(preparedArgsOf(t), `${t.name} args`)},`)
  .join("\n");

// A prop declared by two tools must agree on its schema, otherwise the OpArgs union is ill-formed.
const unionProps = new Map<string, unknown>();
for (const t of contract.tools) {
  const props = preparedArgsOf(t).properties as Record<string, unknown>;
  for (const [k, prop] of Object.entries(props)) {
    const prior = unionProps.get(k);
    if (prior !== undefined && JSON.stringify(prior) !== JSON.stringify(prop)) {
      throw new Error(
        `gen-ops: conflicting schemas for arg ${JSON.stringify(k)}: ` +
          `${JSON.stringify(prior)} vs ${JSON.stringify(prop)}`,
      );
    }
    unionProps.set(k, prop);
  }
}
const opArgsFields = [...unionProps.entries()]
  .map(([k, prop]) => `  ${emitKey(k)}: ${convert(prop, `OpArgs.${k}`)}.optional(),`)
  .join("\n");

// Emitted with a compile-time pin against the policy contract, so a grant can only ever name a boolean policy field.
const grants = contract.tools
  .map((t) => `  ${emitKey(t.name)}: [${t.grants.map((g) => JSON.stringify(g)).join(", ")}],`)
  .join("\n");

const opsOut = `// GENERATED from the Rust core (src/packages/core/src/tools/catalogue.rs and
// args.rs) by scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run
// \`moon run gen\`.
//
// The tool catalogue, TS side. The per-op Zod validators derive from the same Rust args structs the Rust reader
// parses, and BridgeCommand is INFERRED from them, so the compile-time types and the runtime checks cannot drift.

import { z } from "zod";
import type { PolicyFieldName, PolicyValues } from "./policy.gen";

export const OP_NAMES = [
  ${opNames},
] as const;

export type OpName = (typeof OP_NAMES)[number];

const OP_NAME_SET: ReadonlySet<string> = new Set(OP_NAMES);

export function isOpName(op: string): op is OpName {
  return OP_NAME_SET.has(op);
}

// Plain data, so importing it has no side effect.
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

// A grant may only name a boolean policy field, so enforcement's \`=== true\` reads stay type-honest.
type BooleanPolicyField = {
  [K in PolicyFieldName]: PolicyValues[K] extends boolean ? K : never;
}[PolicyFieldName];

// A tool's own grants (Tool::grants in catalogue.rs), every one required true for the tool to run. The extension's
// handlers check only these; the host is the cdpMode gate (Tool::required_grants adds it for every debugger-backed
// tool).
export const TOOL_GRANTS = {
${grants}
} as const satisfies Readonly<Record<OpName, readonly BooleanPolicyField[]>>;

// The extension parses an inbound request's args against its op's validator before dispatching, fail closed.
export const OP_ARG_SCHEMAS = {
${argSchemas}
} as const satisfies Readonly<Record<OpName, z.ZodType>>;

// Discriminated on \`op\`, so a consumer narrows the args to exactly the fields that tool accepts. envelope.ts
// intersects this with the request envelope to form BridgeReq.
export type BridgeCommand = {
  [K in OpName]: { op: K; args: z.infer<(typeof OP_ARG_SCHEMAS)[K]> };
}[OpName];

// Every tool's args props, all optional; the per-op validators enforce required-ness.
export const OpArgsSchema = z
  .object({
${opArgsFields}
  })
  .strict();

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
// Only the Rust server assigns these codes: the extension reports its failures as free-form strings, which the host
// surfaces as EXECUTION_FAILED.

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

// The MCP revision is a date string by spec; anything else means the emitter and this generator disagree.
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

// The INTERNAL bridge protocol version (MCP server <-> native host <-> extension), bumped only when the bridge wire
// contract changes incompatibly. Not the MCP JSON-RPC version, not the extension release version.
export const BRIDGE_PROTOCOL_VERSION = ${contract.protocolVersion};

// The newest MCP JSON-RPC revision the Rust server serves, advertised by \`server/discover\` in \`supportedVersions\`.
export const MCP_PROTOCOL_VERSION = ${JSON.stringify(contract.mcpProtocolVersion)};

// Every stateless request's \`params._meta\` MUST carry BOTH the protocol version and the client capabilities (an
// empty object suffices); the server/discover result carries the server identity under the serverInfo key.
export const MCP_META_PROTOCOL_VERSION = ${JSON.stringify(contract.mcpMetaKeys.protocolVersion)};
export const MCP_META_CLIENT_CAPABILITIES = ${JSON.stringify(contract.mcpMetaKeys.clientCapabilities)};
export const MCP_META_SERVER_INFO = ${JSON.stringify(contract.mcpMetaKeys.serverInfo)};

// Each capability covers the tools sharing one Chrome permission. On connect the extension advertises which ids are
// available; a tool is callable only if its capability is advertised.
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
// Chrome's id derivation: sha256 of the DER key, first 16 bytes, hex mapped onto a-p.
const hex = createHash("sha256")
  .update(Buffer.from(extensionManifestKey, "base64"))
  .digest("hex")
  .slice(0, 32);
const extensionId = [...hex]
  .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
  .join("");

// identity.rs pins the derived id too (the registration engine's allowed_origins); a drift from the key fails here.
if (pinnedExtensionId !== extensionId) {
  throw new Error(
    `gen-ops: identity.rs PINNED_EXTENSION_ID=${pinnedExtensionId} but the key derives ${extensionId}`,
  );
}

// Chrome's charset for host names: dot-separated segments of [a-z0-9_].
if (
  typeof nativeMessagingHostId !== "string" ||
  !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(nativeMessagingHostId)
) {
  throw new Error("gen-ops: nativeMessagingHostId violates Chrome's charset");
}

const identityOut = `// GENERATED from the Rust core (src/packages/core/src/identity.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Run \`moon run gen\`.
//
// PINNED_EXTENSION_ID is DERIVED from EXTENSION_MANIFEST_KEY by Chrome's own id derivation, so it cannot drift from
// the generated manifest; scripts/check-extension-id.ts verifies the built manifest against the same values.

// The native-messaging host manifest pins this in \`allowed_origins\`, so a build without the key is rejected.
export const PINNED_EXTENSION_ID = ${JSON.stringify(extensionId)};

// The manifest \`key\` (base64 DER public key); src/apps/extension/wxt.config.ts injects it into the manifest.
export const EXTENSION_MANIFEST_KEY =
  ${JSON.stringify(extensionManifestKey)};

// What the extension passes to connectNative, what the Rust host expects, and the host manifest's name stem.
export const NATIVE_HOST_ID = ${JSON.stringify(nativeMessagingHostId)};
`;

writeFileSync(join(root, "src/packages/shared/src/identity.gen.ts"), identityOut);
console.log("generated src/packages/shared/src/identity.gen.ts from the Rust core");

// ---- audit.gen.ts -------------------------------------------------------------

const forwardedKinds = contract.auditForwardedKinds;
if (!Array.isArray(forwardedKinds) || forwardedKinds.length === 0) {
  throw new Error("gen-ops: the emitted contract has no auditForwardedKinds");
}
for (const kind of forwardedKinds) {
  // serde snake_case wire names; anything else means the emitter and this generator disagree.
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
// The audit kinds the host accepts over the audit_event control frame (audit::extension_kind). The extension's
// forwarding set (background/audit-log.ts) and its ring vocabulary (shared/enclave.ts) build on this, so the two
// sides of the forwarding boundary cannot drift apart.

export const AUDIT_FORWARDED_KINDS = [
  ${forwardedKinds.map((k) => JSON.stringify(k)).join(",\n  ")},
] as const;

export type AuditForwardedKind = (typeof AUDIT_FORWARDED_KINDS)[number];
`;

writeFileSync(join(root, "src/packages/shared/src/audit.gen.ts"), auditOut);
console.log("generated src/packages/shared/src/audit.gen.ts from the Rust audit whitelist");

// ---- host.gen.ts ---------------------------------------------------------------
// Structural sanity only; the values are the Rust side's.

const envName = z.string().regex(/^[A-Z][A-Z0-9_]*$/);
const lowerWords = z
  .array(z.string().regex(/^[a-z][a-z0-9-]*$/))
  .min(1)
  .refine((words) => new Set(words).size === words.length, "repeats a value");
const HostSchema = z.strictObject({
  keychainLabel: z.string().regex(/^[a-z0-9]+(\.[a-z0-9-]+)+$/),
  lockFilename: z.string().regex(/^[a-z0-9][a-z0-9.-]*\.lock$/),
  clientNameEnv: envName,
  logLevelEnv: envName,
  logLevels: lowerWords,
  logFormatEnv: envName,
  logFormats: lowerWords,
  auditDefaultLimit: z.int().positive(),
  browserKeys: lowerWords,
});
const hostParsed = HostSchema.safeParse(contract.host);
if (!hostParsed.success) {
  throw new Error(
    `gen-ops: the emitted host contract is malformed:\n${z.prettifyError(hostParsed.error)}`,
  );
}
const {
  keychainLabel,
  lockFilename,
  clientNameEnv,
  logLevelEnv,
  logLevels,
  logFormatEnv,
  logFormats,
  auditDefaultLimit,
  browserKeys,
} = hostParsed.data;
const wordList = (words: string[]): string => words.map((w) => JSON.stringify(w)).join(", ");

const hostOut = `// GENERATED from the Rust core (enclave/mod.rs KEY_LABEL, ipc/lockfile.rs
// LOCK_FILENAME, mcp_server.rs CLIENT_NAME_ENV, log.rs, audit.rs
// DEFAULT_AUDIT_LIMIT, browsers.rs Browser::ALL) by scripts/gen-ops.ts - DO NOT
// EDIT. Run \`moon run gen\`.
//
// The host's user-facing constants. scripts/check-docs-literals.ts holds the docs to these, so a rename in the Rust
// core fails the docs gate instead of leaving a troubleshooting page quietly wrong.

// The keychain label of the enclave signing key.
export const KEYCHAIN_LABEL = ${JSON.stringify(keychainLabel)};

// The lock file under the per-user runtime directory.
export const LOCK_FILENAME = ${JSON.stringify(lockFilename)};

// The env var a harness may set to name itself in logs and the audit surface.
export const CLIENT_NAME_ENV = ${JSON.stringify(clientNameEnv)};

// The stderr threshold env var and its accepted values, least to most verbose.
export const LOG_LEVEL_ENV = ${JSON.stringify(logLevelEnv)};
export const LOG_LEVELS = [${wordList(logLevels)}] as const;

// The audit line format env var and its accepted values, the default first.
export const LOG_FORMAT_ENV = ${JSON.stringify(logFormatEnv)};
export const LOG_FORMATS = [${wordList(logFormats)}] as const;

// How many records \`audit\` prints without \`--limit\`.
export const AUDIT_DEFAULT_LIMIT = ${auditDefaultLimit};

// The browser CLI keys (\`--browser\`), in report order.
export const BROWSER_KEYS = [${wordList(browserKeys)}] as const;
`;

writeFileSync(join(root, "src/packages/shared/src/host.gen.ts"), hostOut);
console.log("generated src/packages/shared/src/host.gen.ts from the Rust core");
// ---- enclave.gen.ts + enclave-fixture.gen.ts --------------------------------
// Its own Rust emitter (examples/emit_enclave_contract.rs); shares no state with the emit_contract flow above.

interface EnclaveVector {
  nonce: string;
  context: string | null;
  messageHex: string;
  sigB64: string;
}

interface PolicyVector {
  docB64: string;
  messageHex: string;
  sigB64: string;
}

interface EnclaveContract {
  challengeDomain: string;
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
  policyFixture: {
    policyDomain: string;
    vectors: PolicyVector[];
  };
}

const enclaveEmitted = Bun.spawnSync(
  [
    "cargo",
    "run",
    "--frozen",
    "-q",
    "-p",
    "chromium-bridge-core",
    "--example",
    "emit_enclave_contract",
  ],
  { cwd: root, stderr: "inherit" },
);
if (!enclaveEmitted.success) {
  throw new Error(
    `gen-ops: cargo emit_enclave_contract failed with status ${enclaveEmitted.exitCode}`,
  );
}
const enclave = JSON.parse(enclaveEmitted.stdout.toString()) as EnclaveContract;

// Structural sanity only; anything malformed would generate a silently weaker verifier, so generation fails.
if (
  typeof enclave.challengeDomain !== "string" ||
  enclave.challengeDomain.length === 0 ||
  enclave.challengeDomain.includes("\0")
) {
  throw new Error(
    `gen-ops: malformed enclave domain string ${JSON.stringify(enclave.challengeDomain)}`,
  );
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
// Each policy vector is a POLICY_DOMAIN message over its own document bytes: hex(domain) || 00 || hex(doc), doc JSON.
if (enclave.policyFixture.vectors.length === 0) {
  throw new Error("gen-ops: the policy golden fixture has no vectors");
}
const policyDomainHex = `${Buffer.from(enclave.policyFixture.policyDomain, "utf8").toString("hex")}00`;
for (const v of enclave.policyFixture.vectors) {
  if (!/^([0-9a-f]{2})+$/.test(v.messageHex)) {
    throw new Error("gen-ops: a policy fixture vector has bad message hex");
  }
  const docBytes = Buffer.from(v.docB64, "base64");
  if (v.messageHex !== policyDomainHex + docBytes.toString("hex")) {
    throw new Error("gen-ops: a policy fixture message is not domain || 0x00 || doc bytes");
  }
  JSON.parse(docBytes.toString("utf8"));
}

// \u-escapes everything non-ASCII (deliberate in the multi-byte UTF-8 vectors), so the generated file stays plain
// ASCII for the typography gate.
const emitAsciiString = (s: string): string =>
  JSON.stringify(s).replace(
    /[\u0080-\uffff]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );

const reasonCodes = enclave.reasonCodes.map((r) => emitAsciiString(r)).join(",\n  ");

const enclaveOut = `// GENERATED from the Rust core (src/packages/core/src/enclave/challenge.rs,
// pubkey.rs, and mod.rs REASON_CODES) by scripts/gen-ops.ts - DO NOT EDIT.
// Edit the enclave module, then run \`moon run gen\`.
//
// The host-key signing contract, TS side: the constants the WebCrypto verifier (background/enclave-verify.ts) and the
// enrollment state machine (background/enrollment.ts) enforce. The signed-message ALGORITHM is pinned separately by
// the golden vectors in enclave-fixture.gen.ts.

// The host-key challenge domain; the policy signature has its own (policy.gen.ts), so neither replays as the other.
export const CHALLENGE_DOMAIN = ${emitAsciiString(enclave.challengeDomain)};

// Host-enforced bounds on challenge fields, in UTF-8 bytes; the verifier rejects anything outside them before the crypto.
export const MAX_NONCE_BYTES = ${enclave.maxNonceLen};
export const MAX_CONTEXT_BYTES = ${enclave.maxContextLen};

// The X9.63 uncompressed P-256 point and the raw IEEE P1363 r||s signature.
export const PUBKEY_LEN = ${enclave.pubkeyLen};
export const SIG_LEN = ${enclave.sigLen};

// The closed, append-only set of enclave_error.reason codes (reason_code in src/packages/core/src/enclave/mod.rs).
// The enrollment state machine's compromise latch fires on a subset, so an unrecognized code must degrade to a
// refusal, never match.
export const ENCLAVE_REASON_CODES = [
  ${reasonCodes},
] as const;

export type EnclaveReasonCode = (typeof ENCLAVE_REASON_CODES)[number];

const ENCLAVE_REASON_SET: ReadonlySet<string> = new Set(ENCLAVE_REASON_CODES);

export function isEnclaveReasonCode(reason: string): reason is EnclaveReasonCode {
  return ENCLAVE_REASON_SET.has(reason);
}

// Fingerprint of the PUBLIC golden-fixture key (FIXTURE_KEY_ID in src/packages/core/src/enclave/mod.rs). Its private
// scalar is checked into the repo, so it must never become an enrollment identity: the pairing verifier
// (background/enclave-verify.ts), the stored-pin validators (enclave.ts), and the host all refuse it.
export const ENCLAVE_FIXTURE_KEY_ID =
  ${JSON.stringify(enclave.fixture.keyIdHex)};
`;

writeFileSync(join(root, "src/packages/shared/src/enclave.gen.ts"), enclaveOut);
console.log("generated src/packages/shared/src/enclave.gen.ts from the Rust enclave module");

const vectorItems = enclave.fixture.vectors
  .map(
    (v) =>
      `  {\n` +
      `    nonce: ${emitAsciiString(v.nonce)},\n` +
      `    context: ${v.context === null ? "null" : emitAsciiString(v.context)},\n` +
      `    messageHex: ${JSON.stringify(v.messageHex)},\n` +
      `    sigB64: ${JSON.stringify(v.sigB64)},\n` +
      `  },`,
  )
  .join("\n");

const policyVectorItems = enclave.policyFixture.vectors
  .map(
    (v) =>
      `  {\n` +
      `    docB64: ${JSON.stringify(v.docB64)},\n` +
      `    messageHex: ${JSON.stringify(v.messageHex)},\n` +
      `    sigB64: ${JSON.stringify(v.sigB64)},\n` +
      `  },`,
  )
  .join("\n");

const fixtureOut = `// GENERATED from the Rust core (examples/emit_enclave_contract.rs, over
// src/packages/core/src/enclave/) by scripts/gen-ops.ts - DO NOT EDIT.
// Run \`moon run gen\`.
//
// Golden vectors pinning the cross-language enclave crypto contract: Rust-built message bytes with deterministic
// (RFC 6979) P-256 signatures, replayed through the extension's WebCrypto verifier, so a Rust-side encoding change
// that outruns the TS verifier fails the replay. The key protects nothing and is deny-listed as an enrollment
// identity on both sides (ENCLAVE_FIXTURE_KEY_ID in enclave.gen.ts). Test-only: production code never imports this.

export interface EnclaveGoldenVector {
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

// Signed policy baselines over the same fixture key: each message is POLICY_DOMAIN || 0x00 || the exact document
// bytes, and docB64 is those bytes as the wire \`baseline\` carries them.

export interface PolicyGoldenVector {
  /** Base64 of the exact signed document bytes (the wire \`baseline\`). */
  docB64: string;
  /** The exact bytes the signature covers, hex-encoded. */
  messageHex: string;
  /** Raw ${enclave.sigLen}-byte IEEE P1363 signature over messageHex, base64. */
  sigB64: string;
}

export interface PolicyGoldenFixture {
  /** The same public fixture key the enclave vectors use. */
  pubkeyB64: string;
  keyIdHex: string;
  vectors: readonly PolicyGoldenVector[];
}

export const POLICY_GOLDEN_FIXTURE: PolicyGoldenFixture = {
  pubkeyB64: ${JSON.stringify(enclave.fixture.pubkeyB64)},
  keyIdHex: ${JSON.stringify(enclave.fixture.keyIdHex)},
  vectors: [
${policyVectorItems}
  ],
};
`;

writeFileSync(join(root, "src/packages/shared/src/enclave-fixture.gen.ts"), fixtureOut);
console.log(
  "generated src/packages/shared/src/enclave-fixture.gen.ts from the Rust enclave module",
);

// ---- policy.gen.ts -----------------------------------------------------------
// Its own Rust emitter (examples/emit_policy_contract.rs). The one cross-reference is the domain-separation check
// against the enclave contract above: the policy domain must differ from the host-key challenge domain, or a
// policy signature could be replayed as a challenge proof.

// The direction tags each value kind may carry (Rust BoolPole / MsOrder / the set order), so generation refuses an
// unknown tag with a clear message instead of emitting a table the typed TS object rejects.
const POLICY_KIND_DIRECTIONS = {
  bool: ["truePermissive", "falsePermissive"],
  ms: ["growsPermissive", "growsPermissiveZeroTop"],
  toolSet: ["shrinksPermissiveSet"],
} as const;

type PolicyKindTag = keyof typeof POLICY_KIND_DIRECTIONS;
type PolicyDirectionTag = (typeof POLICY_KIND_DIRECTIONS)[PolicyKindTag][number];

interface PolicyContractField {
  name: string;
  kind: PolicyKindTag;
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
  [
    "cargo",
    "run",
    "--frozen",
    "-q",
    "-p",
    "chromium-bridge-core",
    "--example",
    "emit_policy_contract",
  ],
  { cwd: root, stderr: "inherit" },
);
if (!policyEmitted.success) {
  throw new Error(
    `gen-ops: cargo emit_policy_contract failed with status ${policyEmitted.exitCode}`,
  );
}
const policy = JSON.parse(policyEmitted.stdout.toString()) as PolicyContract;

// Structural sanity only; anything malformed would generate a silently weaker validator, so generation fails.
if (
  typeof policy.policyDomain !== "string" ||
  policy.policyDomain.length === 0 ||
  policy.policyDomain.includes("\0") ||
  // biome-ignore lint/suspicious/noControlCharactersInRegex: the NUL-free, ASCII-only domain check is the point
  !/^[\x01-\x7f]+$/.test(policy.policyDomain)
) {
  throw new Error(`gen-ops: malformed policy domain string ${JSON.stringify(policy.policyDomain)}`);
}
if (policy.policyDomain === enclave.challengeDomain) {
  throw new Error("gen-ops: the policy domain must differ from the enclave challenge domain");
}
// The fixture vectors must sign under this domain, or a golden replay would verify bytes the real push never carries.
if (policy.policyDomain !== enclave.policyFixture.policyDomain) {
  throw new Error("gen-ops: the policy fixture signs under a different domain than the contract");
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
if (!Array.isArray(policy.fields) || policy.fields.length === 0) {
  throw new Error("gen-ops: the policy contract carries no fields");
}
for (const field of policy.fields) {
  if (typeof field.name !== "string" || !/^[a-z][A-Za-z0-9]*$/.test(field.name)) {
    throw new Error(`gen-ops: policy field name ${JSON.stringify(field.name)} is not camelCase`);
  }
  if (!Object.hasOwn(POLICY_KIND_DIRECTIONS, field.kind)) {
    throw new Error(
      `gen-ops: policy field ${field.name} carries unknown kind ${JSON.stringify(field.kind)}`,
    );
  }
  if (!(POLICY_KIND_DIRECTIONS[field.kind] as readonly string[]).includes(field.direction)) {
    throw new Error(
      `gen-ops: policy field ${field.name} (${field.kind}) carries unknown direction ${JSON.stringify(field.direction)}`,
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

// The emitted default must already inhabit the field's Zod shape, or the validator would reject the defaults.
const policyZodType = (field: PolicyContractField): string => {
  const dflt = policy.defaults[field.name];
  switch (field.kind) {
    case "bool":
      if (typeof dflt !== "boolean") {
        throw new Error(`gen-ops: policy field ${field.name} has a non-boolean default`);
      }
      return "z.boolean()";
    case "ms":
      if (!Number.isInteger(dflt) || (dflt as number) < 0) {
        throw new Error(`gen-ops: policy field ${field.name} has a non-integer default`);
      }
      return "z.int().nonnegative()";
    case "toolSet":
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
const policyFieldNamesOfKind = (kind: PolicyKindTag): string =>
  policy.fields
    .filter((f) => f.kind === kind)
    .map((f) => `  ${JSON.stringify(f.name)},`)
    .join("\n");
const policyFieldKindCases = (kind: PolicyKindTag): string =>
  policy.fields
    .filter((f) => f.kind === kind)
    .map((f) => `    case ${JSON.stringify(f.name)}:`)
    .join("\n");
const policyDirectionItems = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${JSON.stringify(f.direction)},`)
  .join("\n");
const policyValueFields = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${policyZodType(f)},`)
  .join("\n");
const policyOverlayFields = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${policyZodType(f)}.optional(),`)
  .join("\n");
const policyDefaultItems = policy.fields
  .map((f) => `  ${emitKey(f.name)}: ${JSON.stringify(policy.defaults[f.name])},`)
  .join("\n");

const policyOut = `// GENERATED from the Rust core (src/packages/core/src/policy/mod.rs and the
// POLICY_DOMAIN in src/packages/core/src/enclave/challenge.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the policy module, then run
// \`moon run gen\`.
//
// The host-owned policy contract, TS side. The extension recomputes every relax/restrict comparison from the
// direction table itself, never trusting a host's claim about which way a change points, and verifies a signed
// baseline under POLICY_DOMAIN against its pinned key before strict-parsing the same bytes with PolicyDocSchema.

import { z } from "zod";

// The host key signs UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes. Distinct from the host-key challenge domain, so a
// policy signature can never be replayed as a challenge proof, nor a proof as a policy.
export const POLICY_DOMAIN = ${JSON.stringify(policy.policyDomain)};

// PolicyDocSchema pins this as a literal: a newer document is rejected rather than misinterpreted.
export const POLICY_DOC_VERSION = ${policy.docVersion};

// The JS-safe integer bound (2^53 - 1) on the revision counter and, Rust-side via JS_SAFE_INT_MAX, the millisecond
// fields, so both parsers read the same numbers.
export const POLICY_REVISION_MAX = ${policy.revisionMax};

// Bounds on disabledTools, so no list can outgrow the host store's read cap. The Rust bound counts bytes, this one
// UTF-16 code units; tool names are ASCII identifiers, where the two agree, and elsewhere Rust is the stricter side.
export const DISABLED_TOOLS_MAX_ENTRIES = ${policy.disabledToolsMaxEntries};
export const DISABLED_TOOL_NAME_MAX_BYTES = ${policy.disabledToolNameMaxBytes};

// In the catalogue's declaration order. touched entries ride z.enum over this list, so a touched set cannot smuggle
// a field the catalogue does not own.
export const POLICY_FIELDS = [
  ${policyFieldNameItems},
] as const;

export type PolicyFieldName = (typeof POLICY_FIELDS)[number];

const POLICY_FIELD_SET: ReadonlySet<string> = new Set(POLICY_FIELDS);

export function isPolicyFieldName(field: string): field is PolicyFieldName {
  return POLICY_FIELD_SET.has(field);
}

// The fields by value kind (Rust FieldKind) and the refinement from a name to its kind-typed handle, so a boolean
// comparison can only ever read a boolean field.
export const BOOL_POLICY_FIELDS = [
${policyFieldNamesOfKind("bool")}
] as const;

export const MS_POLICY_FIELDS = [
${policyFieldNamesOfKind("ms")}
] as const;

export const TOOL_SET_POLICY_FIELDS = [
${policyFieldNamesOfKind("toolSet")}
] as const;

export type BoolPolicyField = (typeof BOOL_POLICY_FIELDS)[number];
export type MsPolicyField = (typeof MS_POLICY_FIELDS)[number];
export type ToolSetPolicyField = (typeof TOOL_SET_POLICY_FIELDS)[number];

export type PolicyFieldKind =
  | { kind: "bool"; field: BoolPolicyField }
  | { kind: "ms"; field: MsPolicyField }
  | { kind: "toolSet"; field: ToolSetPolicyField };

export function policyFieldKind(field: PolicyFieldName): PolicyFieldKind {
  switch (field) {
${policyFieldKindCases("bool")}
      return { kind: "bool", field };
${policyFieldKindCases("ms")}
      return { kind: "ms", field };
${policyFieldKindCases("toolSet")}
      return { kind: "toolSet", field };
  }
}

// A field's permissive pole (Rust Direction), typed by kind so the table cannot pair a field with a direction of
// another kind.
//   bool    -> "truePermissive" | "falsePermissive" (a skipped confirmation is a grant)
//   ms      -> "growsPermissive" (a longer window grants) | "growsPermissiveZeroTop" (0 = never re-verify = MOST permissive)
//   toolSet -> "shrinksPermissiveSet" (dropping an entry re-enables a tool)
export type BoolPole = "truePermissive" | "falsePermissive";
export type MsOrder = "growsPermissive" | "growsPermissiveZeroTop";
export type PolicyDirection = BoolPole | MsOrder | "shrinksPermissiveSet";

export const POLICY_DIRECTIONS: Readonly<
  Record<BoolPolicyField, BoolPole> &
    Record<MsPolicyField, MsOrder> &
    Record<ToolSetPolicyField, "shrinksPermissiveSet">
> = {
${policyDirectionItems}
};

// The field values without the document's scoping fields (Rust PolicyValues): what comparisons and the effective
// policy work in.
export const PolicyValuesSchema = z.strictObject({
${policyValueFields}
});

export type PolicyValues = z.infer<typeof PolicyValuesSchema>;

// The signed policy document (Rust PolicyDoc), strict-parsed only AFTER the signature verifies. \`touched\` sits
// inside the signed bytes so a fresh signature warrants relaxation on exactly those fields, never the document at large.
export const PolicyDocSchema = z.strictObject({
  v: z.literal(${policy.docVersion}),
  revision: z.int().nonnegative().max(POLICY_REVISION_MAX),
  touched: z.array(z.enum(POLICY_FIELDS)),
${policyValueFields}
});

export type PolicyDoc = z.infer<typeof PolicyDocSchema>;

// The unsigned restriction overlay (Rust PolicyOverlay), every field optional under the document's bounds. Strict,
// unlike the loose control-frame wrappers: an overlay field the catalogue does not own fails the whole frame parse.
// Whether a parsed overlay actually RESTRICTS is the consumer's direction check, never this shape's.
export const PolicyOverlaySchema = z.strictObject({
${policyOverlayFields}
});

export type PolicyOverlay = z.infer<typeof PolicyOverlaySchema>;

// Deep-frozen: the pre-cutover posture hands this instance out as the effective policy, so a caller mutating its
// "copy" must throw instead of rewriting the defaults for everyone after it.
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
`;

writeFileSync(join(root, "src/packages/shared/src/policy.gen.ts"), policyOut);
console.log("generated src/packages/shared/src/policy.gen.ts from the Rust policy module");
