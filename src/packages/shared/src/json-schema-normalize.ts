// Structural JSON Schema comparison for the envelope double-derivation gate
// (scripts/check-envelope-parity.ts).
//
// The canonical envelope contract is the Rust wire types (BridgeReq /
// BridgeResp in src/packages/core/src/protocol.rs, ADR-0028); the extension
// enforces hand-written Zod validators (envelope.ts). Both sides derive a
// JSON Schema (schemars on the Rust side, z.toJSONSchema on the Zod side),
// and this module reduces the two to one canonical structural form so the
// diff that remains is a real contract difference: property sets, base
// types, required-ness, additionalProperties, bounds, patterns, and formats
// are compared verbatim, and resolving a mismatch means changing one of the
// two parsers, not this module.
//
// The two parsers DELIBERATELY differ in a few places (each decision is
// documented on the field in protocol.rs / envelope.ts). Every such
// asymmetry is PINNED, per origin: at each reconciled path the node must
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
//
// Deliberately NOT exported from the package index: this is contract-check
// infrastructure, not API.

// Keys that annotate a schema without constraining instances (R1).
const ANNOTATION_KEYS = new Set(["$schema", "$id", "$comment", "title", "description", "examples"]);

/** Which envelope a schema describes; selects the path-scoped rules. */
export type EnvelopeKind = "request" | "response";

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
    "$.properties.error": {
      rust: { type: ["string", "null"] },
      zod: { type: "string" },
      canonical: { type: "string" },
    },
  },
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
    // A $ref node's siblings would be constraints too; neither derivation
    // emits that form, so refuse it rather than silently merging.
    if (Object.keys(node).length !== 1) {
      throw new Error(`normalize: $ref with siblings is not supported: ${ref}`);
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
