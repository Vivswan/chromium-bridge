// Reduces the Rust (schemars; the Rust wire types are the contract) and Zod (z.toJSONSchema) envelope schemas to one
// canonical form for the asymmetry gate (scripts/check-envelope-parity.ts), so any diff left is the hand-written layer
// (envelope.ts, enclave.ts) drifting from its generated base; a mismatch is fixed in one of the two parsers, never here.
// Every deliberate asymmetry is PINNED per origin in RECONCILED_FIELDS, refused loudly when a node does not deep-equal
// its approved form or a pin goes unvisited (assertPinsConsumed), so drift cannot be compared away.
//
//   R1 annotations, everywhere       -> $schema/$id/$comment/title/description/examples stripped; `format` is NOT one
//                                       (it carries schemars' integer-width claim) and is erased only via an exact R4 form
//   R2 any-schema, everywhere        -> `true` and `{}` both canonicalize to `{}`
//   R3 args narrowing, request only  -> rust must be exactly the any-schema (validated per-op downstream); zod an
//                                       object schema (the OpArgs union, enforced by ops.gen.test.ts); anything else refused
//   R4 reconciled fields             -> an entry in RECONCILED_FIELDS: exact rust form, exact zod form, canonical
//                                       replacement, and the direction the extension moves in (see Reconciliation)
//   R5 control frames only           -> every rust object node must carry additionalProperties: false (serde's
//                                       deny_unknown_fields; the host refuses unknown fields on security frames) and every
//                                       zod node the documented looseObject (FRAME_LOOSENESS says why that widening is
//                                       safe), except STRICT_ZOD_NODES, which stay strict on both sides (an unknown
//                                       overlay field is a policy claim nobody owns); each origin's exact form is
//                                       required, then erased
//
// Not exported from the package index: contract-check infrastructure, not API.

/** Keys that annotate a schema without constraining instances (R1). The one
 * inventory: the envelope generator and the parity gate strip the same set. */
export const ANNOTATION_KEYS: ReadonlySet<string> = new Set([
  "$schema",
  "$id",
  "$comment",
  "title",
  "description",
  "examples",
]);

// The subset of those that are also harmless BESIDE a $ref: $id and $schema
// are excluded because they alter $ref resolution (base URI / dialect).
const REF_SIBLING_ANNOTATION_KEYS = new Set(["$comment", "title", "description", "examples"]);

/** Which envelope a schema describes; selects the path-scoped rules. */
export type EnvelopeKind = "request" | "response" | ControlFrameKind;

/** The control frames under the gate: one kind per `type` tag, extracted
 * from the internally-tagged EnclaveControl / AdminControl / PolicyControl
 * enum schemas by splitTaggedUnionSchema.
 * Host->extension frames are diffed against their Zod mirrors;
 * extension->host frames are normalized rust-side only, so the R5
 * strictness walk still refuses a variant that loses deny_unknown_fields
 * anywhere. */
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
  "policy_get",
  "policy_current",
  "lang_get",
  "lang_set",
  "lang_current",
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

/** Which way an asymmetry moves the extension's acceptance relative to the Rust parser. The parsers decide, not
 * their schemas: the Rust side is serde's Deserialize (a `schemars(with = "String")` newtype still refuses there),
 * the Zod side the extension's parse at the boundary (the wrapped validator, and for the request the per-op step of
 * parseBridgeReq, whose op set R6 holds equal to the Rust command enum).
 *
 *   narrow -> every value the Zod side accepts, the Rust parser accepts too (the extension only refuses earlier)
 *   widen  -> the Zod side accepts at least one value the Rust parser refuses; the reason says why that is safe */
export type AsymmetryDirection = "widen" | "narrow";

/** One deliberate parser asymmetry (R4): the node at this path must deep-equal its origin's approved form (post-R1/R2,
 * children normalized) and is then replaced by `canonical`; anything else is refused loudly. The reason is the one
 * sentence a reviewer reads in the gate's asymmetry table: for a widen, why accepting more than the host is safe; for
 * a narrow, what the extension refuses early. */
export type Reconciliation = {
  direction: AsymmetryDirection;
  reason: string;
  rust: JsonObject;
  zod: JsonObject;
  canonical: JsonObject;
};

type ReconciliationTable = Readonly<Record<string, Readonly<Record<string, Reconciliation>>>>;
type ReconciledFields = Record<EnvelopeKind, Readonly<Record<string, Reconciliation>>>;

/** Declare the reconciliation table, refusing a blank reason at module load (the gate's start): a direction alone
 * tells a reviewer nothing about why a widening is safe. A missing reason is already a type error. */
export function declareReconciledFields<T extends ReconciliationTable>(table: T): T {
  for (const [kind, fields] of Object.entries(table)) {
    for (const [path, { direction, reason }] of Object.entries(fields)) {
      if (reason.trim() === "") {
        throw new Error(
          `normalize: ${kind} ${path} is a ${direction} with no reason; every reconciliation says why in one sentence`,
        );
      }
    }
  }
  return table;
}

const JS_SAFE = Number.MAX_SAFE_INTEGER;

// The correlation id: BridgeReq::id / BridgeResp::id (protocol.rs) against BridgeIdSchema (envelope.ts).
const ID_FIELD: Reconciliation = {
  direction: "widen",
  reason:
    "Two widenings the host closes itself: a string arm kept for forward compatibility, and a signed " +
    "JS-safe integer where the host's u64 refuses a negative; the host is the only assigner of ids and " +
    "refuses both in its own parse.",
  rust: { type: "integer", format: "uint64", minimum: 0 },
  zod: {
    anyOf: [{ type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE }, { type: "string" }],
  },
  canonical: { type: "integer" },
};

const NULL_ARM_DROPPED =
  "serde's Option null arm is dropped: every writer omits an absent field (skip_serializing_if), " +
  "so only absence is accepted.";

const OPTIONAL_STRING: Reconciliation = {
  direction: "narrow",
  reason: NULL_ARM_DROPPED,
  rust: { type: ["string", "null"] },
  zod: { type: "string" },
  canonical: { type: "string" },
};

const OPTIONAL_BOOL: Reconciliation = {
  direction: "narrow",
  reason: NULL_ARM_DROPPED,
  rust: { type: ["boolean", "null"] },
  zod: { type: "boolean" },
  canonical: { type: "boolean" },
};

const EMPTY_REFUSED_EARLY =
  "The empty string is refused early on key material the host produces itself (signature, key id, " +
  "public key); the host leaves that to signature verification.";

const NONEMPTY_STRING: Reconciliation = {
  direction: "narrow",
  reason: EMPTY_REFUSED_EARLY,
  rust: { type: "string" },
  zod: { type: "string", minLength: 1 },
  canonical: { type: "string" },
};

const CLIENT_LABEL: Reconciliation = {
  ...NONEMPTY_STRING,
  reason:
    "A blank client label fails the frame early; the host validates labels when it pairs a client, not when " +
    "it loads the allowlist it forwards, so this line is the extension's own.",
};

// The signed-statement frames enclave_proof and presence_proof share one
// field set (sig, key_id, pubkey; see protocol/control.rs for the encoding).
const PROOF_FIELDS: Readonly<Record<string, Reconciliation>> = {
  "$.properties.sig": NONEMPTY_STRING,
  "$.properties.key_id": NONEMPTY_STRING,
  "$.properties.pubkey": NONEMPTY_STRING,
};

// allowlist::Anchor is serde adjacently-tagged, so schemars emits one object variant per kind with a pinned `const`
// over the newtype values (HashDigest / TeamId, `schemars(with = "String")`, validated in Deserialize); the Zod mirror
// spells the instance set as a single object with a two-value kind enum.
const ANCHOR_FIELD: Reconciliation = {
  direction: "widen",
  reason:
    "The extension only displays the anchor, so this single object with a kind enum skips the HashDigest " +
    "grammar (lowercase hex, 20 or 32 bytes) the host's parse enforces (TeamId is non-empty on both sides); " +
    "admission is decided by the host, whose own parse refuses a malformed value when it loads the allowlist.",
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

// A required u64 (lang_current.seq, client added_unix).
const JS_SAFE_U64_FIELD: Reconciliation = {
  direction: "narrow",
  reason:
    "A u64 held to the JS-safe non-negative range: above 2^53 - 1 a JS number cannot represent every " +
    "integer, so two consecutive host values could read equal here.",
  rust: { type: "integer", format: "uint64", minimum: 0 },
  zod: { type: "integer", minimum: 0, maximum: JS_SAFE },
  canonical: { type: "integer", minimum: 0 },
};

// Option<String> signed-artifact material (policy_current.baseline / sig).
const OPTIONAL_NONEMPTY_STRING: Reconciliation = {
  direction: "narrow",
  reason:
    "The Option null arm is dropped (writers omit absent fields) and the empty string is refused early on a " +
    "signed artifact the host only ever sends whole.",
  rust: { type: ["string", "null"] },
  zod: { type: "string", minLength: 1 },
  canonical: { type: "string" },
};

// policy_current.overlay: Option<PolicyOverlay> on the Rust side (a null arm around the strict all-optional object);
// the Zod side is the GENERATED PolicyOverlaySchema (policy.gen.ts). The overlay is also the one STRICT_ZOD_NODES
// exception to R5: strict on both sides.
//
//   ms fields                    -> both sides JS-safe: Zod by bound, the host through its Ms parser
//   disabledTools caps           -> pinned here as literals (DISABLED_TOOL_NAME_MAX_BYTES 128, DISABLED_TOOLS_MAX_ENTRIES
//                                   256); Rust enforces them in PolicyDoc::validate and at the restrict seam, not Deserialize
//   Zod maxLength 128 vs bytes   -> Zod counts UTF-16 code units, Rust bytes, so Zod is LOOSER than PolicyDoc::validate on
//                                   non-ASCII names (128 U+00E9 pass Zod, 256 bytes fail Rust); the host validates every
//                                   doc it stores or loads
const OVERLAY_BOOL_FIELDS = [
  "cdpMode",
  "fileUploadEnabled",
  "handleDialogEnabled",
  "pageEvalEnabled",
  "confirmHighRiskClick",
  "confirmPageEval",
  "touchIdConfirm",
  "confirmTabClose",
  "warnPreciseSnapshot",
  "evalMask",
] as const;

const OVERLAY_MS_FIELDS = [
  "hostReverifyMs",
  "confirmGraceMs",
  "clickToastTimeoutMs",
  "evalToastTimeoutMs",
] as const;

function overlayProperties(origin: SchemaOrigin | "canonical"): JsonObject {
  const forms = {
    rust: {
      bool: { type: ["boolean", "null"] },
      ms: { type: ["integer", "null"], format: "uint64", minimum: 0 },
      tools: { type: ["array", "null"], items: { type: "string" } },
    },
    zod: {
      bool: { type: "boolean" },
      ms: { type: "integer", minimum: 0, maximum: JS_SAFE },
      tools: {
        type: "array",
        items: { type: "string", minLength: 1, maxLength: 128 },
        maxItems: 256,
      },
    },
    canonical: {
      bool: { type: "boolean" },
      ms: { type: "integer", minimum: 0 },
      tools: { type: "array", items: { type: "string" } },
    },
  }[origin];
  const props: JsonObject = {};
  for (const field of OVERLAY_BOOL_FIELDS) props[field] = structuredClone(forms.bool);
  for (const field of OVERLAY_MS_FIELDS) props[field] = structuredClone(forms.ms);
  props.disabledTools = structuredClone(forms.tools);
  return props;
}

const OVERLAY_FIELD: Reconciliation = {
  direction: "narrow",
  reason:
    "No null arm around the overlay or any of its fields (writers omit absent fields), ms bounds matching the " +
    "host's JS-safe Ms parser, and the disabledTools caps applied at parse time where the host applies them in " +
    "PolicyDoc::validate.",
  rust: {
    anyOf: [{ type: "object", properties: overlayProperties("rust") }, { type: "null" }],
  },
  zod: { type: "object", properties: overlayProperties("zod") },
  canonical: { type: "object", properties: overlayProperties("canonical") },
};

const RECONCILED_FIELDS: ReconciledFields = declareReconciledFields({
  request: {
    "$.properties.id": ID_FIELD,
    "$.properties.op": {
      direction: "narrow",
      reason:
        "The empty op is refused early; an unknown op is refused on both sides (the Rust command enum, the " +
        "catalogue lookup in parseBridgeReq, held to one op set by R6), so this row covers the empty string only.",
      rust: { type: "string" },
      zod: { type: "string", minLength: 1 },
      canonical: { type: "string" },
    },
    "$.properties.browser": {
      direction: "narrow",
      reason:
        "The Option null arm is dropped and the browser-label grammar is enforced early; the host only " +
        "ever stamps a validated label.",
      rust: { type: ["string", "null"] },
      zod: { type: "string", minLength: 1, maxLength: 32, pattern: "^[A-Za-z0-9._-]+$" },
      canonical: { type: "string" },
    },
  },
  response: {
    "$.properties.id": ID_FIELD,
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
    "$.properties.clients.items.properties.name": CLIENT_LABEL,
    "$.properties.clients.items.properties.anchor": ANCHOR_FIELD,
    "$.properties.clients.items.properties.added_unix": JS_SAFE_U64_FIELD,
  },
  client_revoke_result: {
    "$.properties.error": OPTIONAL_STRING,
  },
  kill_status_result: {
    "$.properties.error": OPTIONAL_STRING,
    "$.properties.killed": OPTIONAL_BOOL,
  },
  policy_current: {
    "$.properties.baseline": OPTIONAL_NONEMPTY_STRING,
    "$.properties.sig": OPTIONAL_NONEMPTY_STRING,
    "$.properties.overlay": OVERLAY_FIELD,
    "$.properties.error": OPTIONAL_STRING,
  },
  lang_current: {
    "$.properties.seq": JS_SAFE_U64_FIELD,
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
  policy_get: {},
  lang_get: {},
  lang_set: {},
} satisfies ReconciledFields);

// The R5 strict-nested exception (see the module doc): at these zod-side
// paths the wrapped validator must keep additionalProperties: false - the
// nested document payloads the extension consumes field-by-field, where an
// unknown field is a policy claim the catalogue does not own and must fail
// the frame. Pinned per kind and path so looseness can neither creep in
// here nor strictness anywhere else.
const STRICT_ZOD_NODES: Readonly<Partial<Record<ControlFrameKind, ReadonlySet<string>>>> = {
  policy_current: new Set(["$.properties.overlay"]),
};

/** One row of the gate's asymmetry table. */
export type AsymmetryRow = { scope: string; direction: AsymmetryDirection; reason: string };

/** The R5 widening itself, so the gate's asymmetry table shows it beside the per-field entries: the extension reads
 * every control frame loose (enclave.ts) where the host refuses unknown fields. */
export const FRAME_LOOSENESS: AsymmetryRow = {
  scope: "control frames, every zod object node except STRICT_ZOD_NODES",
  direction: "widen",
  reason:
    "The host may add fields; the extension acts only on the fields it validated (and, for signed statements, " +
    "verifies in enclave-verify.ts), never on a frame merely having the right shape, so an unknown field is " +
    "ignored rather than fatal.",
};

/** Every pinned asymmetry as one row (scope, direction, reason), in table order, for the gate's output. */
export function listAsymmetries(): readonly AsymmetryRow[] {
  const rows: AsymmetryRow[] = Object.entries(RECONCILED_FIELDS).flatMap(([kind, fields]) =>
    Object.entries(fields).map(([path, { direction, reason }]) => ({
      scope: `${kind} ${path}`,
      direction,
      reason,
    })),
  );
  return [...rows, FRAME_LOOSENESS];
}

const ARGS_PATH = "$.properties.args";

// Every pin above is consulted only when the walk visits a node at its path,
// so a stale or typo'd pin would otherwise sit inert - erasing nothing,
// refusing nothing. The walk therefore records the pins it consumed, and
// normalizeEnvelopeSchema refuses leftovers by default (the gate normalizes
// the full schemas, so every pin must be hit; unit tests normalizing
// deliberately partial fixtures opt out).
type ConsumedPins = { reconciled: Set<string>; strictZod: Set<string> };

function assertPinsConsumed(
  kind: EnvelopeKind,
  origin: SchemaOrigin,
  consumed: ConsumedPins,
): void {
  const leftovers: string[] = [];
  // STRICT_ZOD_NODES pins are zod-side exceptions: only a zod walk can
  // consume one, so only a zod walk can prove it live.
  if (origin === "zod" && isControlFrameKind(kind)) {
    for (const path of STRICT_ZOD_NODES[kind] ?? []) {
      if (!consumed.strictZod.has(path)) leftovers.push(`STRICT_ZOD_NODES ${path}`);
    }
  }
  for (const path of Object.keys(RECONCILED_FIELDS[kind])) {
    if (!consumed.reconciled.has(path)) leftovers.push(`RECONCILED_FIELDS ${path}`);
  }
  if (leftovers.length > 0) {
    throw new Error(
      `normalize: pinned ${kind} paths the ${origin} walk never visited ` +
        `(stale or typo'd pins, or the schema lost the field): ${leftovers.join(", ")}`,
    );
  }
}

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
  consumed: ConsumedPins,
): unknown {
  // R2: `true` means "anything".
  const bare = node === true ? {} : node;
  if (Array.isArray(bare)) {
    return bare.map((item, i) => normalizeNode(item, `${path}[${i}]`, kind, origin, consumed));
  }
  if (!isObject(bare)) return bare;

  const out: JsonObject = {};
  for (const [key, value] of Object.entries(bare)) {
    if (ANNOTATION_KEYS.has(key)) continue;
    out[key] = normalizeNode(value, `${path}.${key}`, kind, origin, consumed);
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
  // at every object node - except the pinned STRICT_ZOD_NODES, which stay
  // strict on both; each origin's exact form is required, then erased
  // (see the module doc).
  if (isControlFrameKind(kind) && out.type === "object") {
    const ap = out.additionalProperties;
    if (origin === "rust") {
      if (ap !== false) {
        throw new Error(
          `normalize: ${path} lost deny_unknown_fields on the rust side (got ${show(ap)})`,
        );
      }
    } else if (STRICT_ZOD_NODES[kind]?.has(path)) {
      consumed.strictZod.add(path);
      if (ap !== false) {
        throw new Error(
          `normalize: ${path} is no longer the strict nested document the R5 exception ` +
            `pins on the zod side (got ${show(ap)})`,
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
    consumed.reconciled.add(path);
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
 * (see the module doc for the rule list). By default every RECONCILED_FIELDS
 * / STRICT_ZOD_NODES pin for this kind must be consumed by the walk (no
 * inert pins); tests normalizing partial fixtures pass
 * `{ requireConsumedPins: false }`. */
export function normalizeEnvelopeSchema(
  schema: unknown,
  kind: EnvelopeKind,
  origin: SchemaOrigin,
  opts: { requireConsumedPins?: boolean } = {},
): unknown {
  if (!isObject(schema)) throw new Error("normalize: expected a schema object");
  const defs = isObject(schema.$defs) ? schema.$defs : {};
  const inlined = deref({ ...schema, $defs: undefined }, defs) as JsonObject;
  delete inlined.$defs;
  const consumed: ConsumedPins = { reconciled: new Set(), strictZod: new Set() };
  const out = normalizeNode(inlined, "$", kind, origin, consumed);
  if (opts.requireConsumedPins ?? true) assertPinsConsumed(kind, origin, consumed);
  return out;
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
