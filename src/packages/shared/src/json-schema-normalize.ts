// Structural JSON Schema comparison for the envelope asymmetry gate
// (scripts/check-envelope-parity.ts).
//
// The canonical wire contract is the Rust types in
// src/packages/core/src/protocol.rs (ADR-0028): the BridgeReq / BridgeResp
// envelope pair, and the host-handled control frames (EnclaveControl and
// AdminControl, the latter embedding allowlist::ClientEntry). The extension
// enforces two-layer validators: a base GENERATED from the Rust schemas
// (envelope-wire.gen.ts, via scripts/gen-envelope.ts) wrapped by a
// hand-written asymmetry layer (envelope.ts for the envelopes, enclave.ts
// for the control frames). Both sides derive a JSON Schema (schemars on the
// Rust side, z.toJSONSchema on the wrapped Zod side), and this module
// reduces the two to one canonical structural form so the diff that remains
// is a real contract difference - with the base generated, that means the
// hand-written layer drifted: property sets, base types, required-ness,
// additionalProperties, bounds, patterns, and formats are compared verbatim,
// and resolving a mismatch means changing one of the two parsers, not this
// module.
//
// The two parsers DELIBERATELY differ in a few places (each decision is
// documented on the field in protocol.rs / envelope.ts / enclave.ts). Every
// such asymmetry is PINNED, per origin: at each reconciled path the node must
// deep-equal the exact form approved for the schema's own origin (rust or
// zod) in RECONCILED_FIELDS below, and is refused loudly otherwise. A
// mismatch there is either real drift or a deliberate contract change that
// must update this table - it can never be compared away, not even by both
// sides converging on the canonical form. The rules:
//
//   R1 (annotations, everywhere): $schema/$id/$comment/title/description/
//      examples constrain nothing and are stripped. `format` is NOT an
//      annotation here: it carries schemars' integer-width claim, so it is
//      contract material and only erased via an exact R4 form.
//   R2 (any-schema, everywhere): the boolean schema `true` and the empty
//      schema `{}` both mean "anything"; canonicalize to `{}`.
//   R3 (args narrowing, request only): the Rust envelope carries `args`
//      free-form (validated per-op downstream); the extension narrows it to
//      the OpArgs union before per-op validation. The rust side must be
//      exactly the any-schema, the zod side an object schema (its per-op
//      content is enforced by ops.gen.test.ts); anything else is refused.
//   R4 (reconciled fields): each remaining asymmetry is an entry in
//      RECONCILED_FIELDS naming the exact rust-side form, the exact
//      zod-side form, and the canonical replacement. See each entry for the
//      why.
//   R5 (loose control frames, control-frame kinds only): the Rust side of
//      every object node must still carry serde's deny_unknown_fields
//      (additionalProperties: false) - the host refuses unknown fields on
//      these security frames - while the Zod side is a documented
//      looseObject (the host may add fields; the extension's decisions come
//      from the validated fields plus cryptographic verification, never
//      from a frame merely having the right shape - see enclave.ts). Each
//      origin's exact form is required and then erased, so a Rust frame
//      going loose or a Zod frame going strict is refused, not compared
//      away.
//
// Deliberately NOT exported from the package index: this is contract-check
// infrastructure, not API.

// Keys that annotate a schema without constraining instances (R1).
const ANNOTATION_KEYS = new Set(["$schema", "$id", "$comment", "title", "description", "examples"]);

// The subset of those that are also harmless BESIDE a $ref: $id and $schema
// are excluded because they alter $ref resolution (base URI / dialect).
const REF_SIBLING_ANNOTATION_KEYS = new Set(["$comment", "title", "description", "examples"]);

/** Which envelope a schema describes; selects the path-scoped rules. */
export type EnvelopeKind = "request" | "response" | ControlFrameKind;

/** The control frames under the gate (ADR-0021/0025/0030/0031): one kind per
 * `type` tag, extracted from the internally-tagged EnclaveControl /
 * AdminControl enum schemas by splitTaggedUnionSchema. Host->extension
 * frames are diffed against their Zod mirrors; extension->host frames are
 * normalized rust-side only, so the R5 strictness walk still refuses a
 * variant that loses deny_unknown_fields anywhere. */
export const CONTROL_FRAME_KINDS = [
  "enclave_challenge",
  "enclave_proof",
  "enclave_error",
  "enclave_revoke",
  "enclave_revoked",
  "presence_challenge",
  "presence_proof",
  "presence_error",
  "client_list",
  "client_list_result",
  "client_revoke",
  "client_revoke_result",
  "kill_status",
  "kill_engage",
  "kill_release",
  "kill_status_result",
  "audit_event",
] as const;

export type ControlFrameKind = (typeof CONTROL_FRAME_KINDS)[number];

const CONTROL_FRAME_KIND_SET: ReadonlySet<string> = new Set(CONTROL_FRAME_KINDS);

function isControlFrameKind(kind: EnvelopeKind): kind is ControlFrameKind {
  return CONTROL_FRAME_KIND_SET.has(kind);
}

/** Which derivation produced the schema; each reconciled field only erases
 * the form approved for that origin, so one parser silently adopting the
 * other's shape still fails the diff. */
export type SchemaOrigin = "rust" | "zod";

type JsonObject = { [key: string]: unknown };

// One deliberate parser asymmetry (R4): the node at this path must
// deep-equal its origin's approved form (post-R1/R2, children normalized)
// and is then replaced by `canonical`; anything else is refused loudly.
type Reconciliation = { rust: JsonObject; zod: JsonObject; canonical: JsonObject };

const JS_SAFE = Number.MAX_SAFE_INTEGER;

// The correlation id. The server is the sole assigner (a monotonic u64
// counter, so schemars claims uint64 >= 0); the extension accepts
// integer-or-string for forward compatibility but hardens the integer arm
// to the JS-safe range (see BridgeReq::id in protocol.rs and envelope.ts).
const ID_FIELD: Reconciliation = {
  rust: { type: "integer", format: "uint64", minimum: 0 },
  zod: {
    anyOf: [{ type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE }, { type: "string" }],
  },
  canonical: { type: "integer" },
};

// serde's Option<String> null-arm (writers omit absent fields:
// skip_serializing_if) where Zod's .optional() only accepts absence.
const OPTIONAL_STRING: Reconciliation = {
  rust: { type: ["string", "null"] },
  zod: { type: "string" },
  canonical: { type: "string" },
};

// Same null-arm asymmetry for Option<bool> (kill_status_result.killed).
const OPTIONAL_BOOL: Reconciliation = {
  rust: { type: ["boolean", "null"] },
  zod: { type: "boolean" },
  canonical: { type: "boolean" },
};

// The Zod side refuses the empty string early on fields the host always
// sends non-empty (base64/hex key material, validated client labels); the
// Rust side leaves that to the consumer (signature verification, label
// validation) - the same split as the request's op field.
const NONEMPTY_STRING: Reconciliation = {
  rust: { type: "string" },
  zod: { type: "string", minLength: 1 },
  canonical: { type: "string" },
};

// The signed-statement frames enclave_proof and presence_proof share one
// field set (sig, key_id, pubkey; see protocol.rs for the encoding).
const PROOF_FIELDS: Readonly<Record<string, Reconciliation>> = {
  "$.properties.sig": NONEMPTY_STRING,
  "$.properties.key_id": NONEMPTY_STRING,
  "$.properties.pubkey": NONEMPTY_STRING,
};

// allowlist::Anchor is serde adjacently-tagged, so schemars emits one
// object variant per kind with a pinned `const`; the Zod mirror spells the
// same instance set as a single object with a two-value kind enum (plus
// the non-empty guard on value). Both accept exactly the same wire values
// modulo the asymmetries pinned here and the R5 looseness.
const ANCHOR_FIELD: Reconciliation = {
  rust: {
    oneOf: [
      {
        type: "object",
        properties: { kind: { type: "string", const: "hash" }, value: { type: "string" } },
        required: ["kind", "value"],
      },
      {
        type: "object",
        properties: { kind: { type: "string", const: "team_id" }, value: { type: "string" } },
        required: ["kind", "value"],
      },
    ],
  },
  zod: {
    type: "object",
    properties: {
      kind: { type: "string", enum: ["hash", "team_id"] },
      value: { type: "string", minLength: 1 },
    },
    required: ["kind", "value"],
  },
  canonical: {
    type: "object",
    properties: { kind: { type: "string", enum: ["hash", "team_id"] }, value: { type: "string" } },
    required: ["kind", "value"],
  },
};

// ClientEntry.added_unix: u64 + #[serde(default)] on the Rust side (absent
// reads as 0, writers always emit it); the Zod side accepts absence and
// hardens the integer to the JS-safe non-negative range, like the id field.
const ADDED_UNIX_FIELD: Reconciliation = {
  rust: { type: "integer", format: "uint64", minimum: 0, default: 0 },
  zod: { type: "integer", minimum: 0, maximum: JS_SAFE },
  canonical: { type: "integer", minimum: 0 },
};

const RECONCILED_FIELDS: Record<EnvelopeKind, Readonly<Record<string, Reconciliation>>> = {
  request: {
    "$.properties.id": ID_FIELD,
    // serde's Option<i64> also accepts an explicit null where Zod's
    // .optional() only accepts absence (our writers never emit null:
    // skip_serializing_if); the Zod side adds the JS-safe integer bounds.
    "$.properties.tabId": {
      rust: { type: ["integer", "null"], format: "int64" },
      zod: { type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE },
      canonical: { type: "integer" },
    },
    // The Zod side rejects the empty op early; the Rust side leaves op
    // validation to the catalogue lookup.
    "$.properties.op": {
      rust: { type: "string" },
      zod: { type: "string", minLength: 1 },
      canonical: { type: "string" },
    },
    // Option null-arm on the Rust side; the Zod side enforces the browser
    // label grammar (see BROWSER_LABEL in envelope.ts).
    "$.properties.browser": {
      rust: { type: ["string", "null"] },
      zod: { type: "string", minLength: 1, maxLength: 32, pattern: "^[A-Za-z0-9._-]+$" },
      canonical: { type: "string" },
    },
  },
  response: {
    "$.properties.id": ID_FIELD,
    // Option null-arm on the Rust side only (writers omit absent errors).
    "$.properties.error": OPTIONAL_STRING,
  },
  enclave_proof: PROOF_FIELDS,
  presence_proof: PROOF_FIELDS,
  // reason is required on both sides (the host always names its denial) and
  // otherwise unconstrained: nothing to reconcile.
  enclave_error: {},
  presence_error: {},
  // A bare tag on both sides; gated so a field the Rust side grows fails
  // here until the extension gets a validator for it.
  enclave_revoked: {},
  client_list_result: {
    "$.properties.error": OPTIONAL_STRING,
    "$.properties.clients.items.properties.name": NONEMPTY_STRING,
    "$.properties.clients.items.properties.anchor": ANCHOR_FIELD,
    "$.properties.clients.items.properties.added_unix": ADDED_UNIX_FIELD,
  },
  client_revoke_result: {
    "$.properties.error": OPTIONAL_STRING,
  },
  kill_status_result: {
    "$.properties.error": OPTIONAL_STRING,
    "$.properties.killed": OPTIONAL_BOOL,
  },
  // Extension->host frames: normalized rust-side only (for the R5
  // strictness walk); there is no Zod derivation to reconcile against.
  enclave_challenge: {},
  enclave_revoke: {},
  presence_challenge: {},
  client_list: {},
  client_revoke: {},
  kill_status: {},
  kill_engage: {},
  kill_release: {},
  audit_event: {},
};

const ARGS_PATH = "$.properties.args";

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function deepEquals(a: unknown, b: unknown): boolean {
  return diffSchemas(a, b).length === 0;
}

// Inline every internal $ref against the root's $defs, so one side using
// indirection and the other not compare equal.
function deref(node: unknown, defs: JsonObject): unknown {
  if (Array.isArray(node)) return node.map((item) => deref(item, defs));
  if (!isObject(node)) return node;
  const ref = node.$ref;
  if (typeof ref === "string") {
    const name = ref.match(/^#\/\$defs\/(.+)$/)?.[1];
    if (name === undefined || !(name in defs)) {
      throw new Error(`normalize: unresolvable $ref ${ref}`);
    }
    // A $ref node's constraint siblings would be lost by a plain inline of
    // the target; neither derivation emits that form, so refuse it rather
    // than silently merging. Pure-annotation siblings constrain nothing
    // (schemars puts a field's doc comment next to the $ref) and are
    // dropped like R1 drops them everywhere else - but NOT $id or $schema,
    // which change how a conforming validator would resolve the $ref itself
    // (base URI / dialect), so beside a $ref they are refused too.
    for (const key of Object.keys(node)) {
      if (key !== "$ref" && !REF_SIBLING_ANNOTATION_KEYS.has(key)) {
        throw new Error(`normalize: $ref with constraint siblings is not supported: ${ref}`);
      }
    }
    return deref(defs[name], defs);
  }
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(node)) {
    out[key] = deref(value, defs);
  }
  return out;
}

function normalizeNode(
  node: unknown,
  path: string,
  kind: EnvelopeKind,
  origin: SchemaOrigin,
): unknown {
  // R2: `true` means "anything".
  const bare = node === true ? {} : node;
  if (Array.isArray(bare)) {
    return bare.map((item, i) => normalizeNode(item, `${path}[${i}]`, kind, origin));
  }
  if (!isObject(bare)) return bare;

  const out: JsonObject = {};
  for (const [key, value] of Object.entries(bare)) {
    if (ANNOTATION_KEYS.has(key)) continue;
    out[key] = normalizeNode(value, `${path}.${key}`, kind, origin);
  }

  // R3: the request's args bag, per origin (see the module doc).
  if (kind === "request" && path === ARGS_PATH) {
    if (origin === "zod") {
      if (out.type === "object") return {};
      throw new Error(`normalize: the Zod args narrowing is gone (got ${show(out)})`);
    }
    if (Object.keys(out).length === 0) return {};
    throw new Error(`normalize: the Rust args field is no longer free-form (got ${show(out)})`);
  }

  // R5: control frames are strict on the Rust side, loose on the Zod side,
  // at every object node; each origin's exact form is required, then erased
  // (see the module doc).
  if (isControlFrameKind(kind) && out.type === "object") {
    const ap = out.additionalProperties;
    if (origin === "rust") {
      if (ap !== false) {
        throw new Error(
          `normalize: ${path} lost deny_unknown_fields on the rust side (got ${show(ap)})`,
        );
      }
    } else if (!(isObject(ap) && Object.keys(ap).length === 0)) {
      throw new Error(
        `normalize: ${path} is no longer the approved looseObject form on the zod side ` +
          `(got ${show(ap)})`,
      );
    }
    delete out.additionalProperties;
  }

  // R4: a reconciled field must match its origin's approved form exactly;
  // it is then replaced by the canonical form.
  const reconciliation = RECONCILED_FIELDS[kind][path];
  if (reconciliation !== undefined) {
    if (deepEquals(out, reconciliation[origin])) return structuredClone(reconciliation.canonical);
    throw new Error(
      `normalize: ${path} no longer matches the approved ${origin} form ` +
        `(expected ${show(reconciliation[origin])}, got ${show(out)}) - ` +
        "real drift, or a contract change that must update RECONCILED_FIELDS",
    );
  }

  if (Array.isArray(out.required)) {
    out.required = [...(out.required as string[])].sort();
  }
  return out;
}

/** Reduce a derived envelope JSON Schema to its canonical structural form
 * (see the module doc for the rule list). */
export function normalizeEnvelopeSchema(
  schema: unknown,
  kind: EnvelopeKind,
  origin: SchemaOrigin,
): unknown {
  if (!isObject(schema)) throw new Error("normalize: expected a schema object");
  const defs = isObject(schema.$defs) ? schema.$defs : {};
  const inlined = deref({ ...schema, $defs: undefined }, defs) as JsonObject;
  delete inlined.$defs;
  return normalizeNode(inlined, "$", kind, origin);
}

/** Split an internally-tagged (serde `tag = "type"`) enum schema into one
 * subschema per tag, with $defs indirection inlined first. Refuses anything
 * that is not exactly the shape schemars emits for such an enum: a top-level
 * oneOf whose every branch is an object schema carrying a unique string
 * `type` const. */
export function splitTaggedUnionSchema(schema: unknown): Map<string, unknown> {
  if (!isObject(schema)) throw new Error("split: expected a schema object");
  const defs = isObject(schema.$defs) ? schema.$defs : {};
  const inlined = deref({ ...schema, $defs: undefined }, defs) as JsonObject;
  const variants = inlined.oneOf;
  if (!Array.isArray(variants)) throw new Error("split: expected a top-level oneOf");
  const out = new Map<string, unknown>();
  for (const variant of variants) {
    if (!isObject(variant) || !isObject(variant.properties)) {
      throw new Error(`split: variant is not an object schema: ${show(variant)}`);
    }
    const tagNode = variant.properties.type;
    const tag = isObject(tagNode) ? tagNode.const : undefined;
    if (typeof tag !== "string") {
      throw new Error(`split: variant without a string \`type\` const: ${show(variant)}`);
    }
    if (out.has(tag)) throw new Error(`split: duplicate tag ${tag}`);
    out.set(tag, variant);
  }
  return out;
}

/** Deep-compare two normalized schemas, returning the differing paths (empty
 * means equivalent). */
export function diffSchemas(a: unknown, b: unknown, path = "$"): string[] {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return [`${path}: ${show(a)} != ${show(b)}`];
    if (a.length !== b.length) return [`${path}.length: ${a.length} != ${b.length}`];
    return a.flatMap((item, i) => diffSchemas(item, b[i], `${path}[${i}]`));
  }
  if (isObject(a) && isObject(b)) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    return [...keys].flatMap((key) => {
      if (!(key in a)) return [`${path}.${key}: missing on left`];
      if (!(key in b)) return [`${path}.${key}: missing on right`];
      return diffSchemas(a[key], b[key], `${path}.${key}`);
    });
  }
  return Object.is(a, b) ? [] : [`${path}: ${show(a)} != ${show(b)}`];
}

function show(v: unknown): string {
  return JSON.stringify(v) ?? String(v);
}
