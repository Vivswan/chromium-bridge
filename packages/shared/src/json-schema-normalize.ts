// Structural JSON Schema comparison for the contract-equivalence tests.
//
// `z.toJSONSchema()` output and the hand-authored contracts/*.schema.json
// differ in representation without differing in meaning: annotations
// ($comment, description, ...), $defs/$ref indirection, `required` order.
// normalize() reduces both sides to one canonical structural form so the
// diff that remains is a real contract difference. Anything else - types,
// bounds, patterns, property sets, union shapes - is compared verbatim, and
// resolving a mismatch means changing one of the two sides, not this module.
// Deliberately NOT exported from the package index: this is test
// infrastructure, not API.

// Keys that annotate a schema without constraining instances.
const ANNOTATION_KEYS = new Set(["$schema", "$id", "$comment", "title", "description", "examples"]);

type JsonObject = { [key: string]: unknown };

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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
    // A $ref node's siblings would be constraints too; the contracts never
    // use that form, so refuse it rather than silently merging.
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

function normalizeNode(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(normalizeNode);
  if (!isObject(node)) return node;
  const out: JsonObject = {};
  for (const [key, value] of Object.entries(node)) {
    if (ANNOTATION_KEYS.has(key)) continue;
    out[key] = normalizeNode(value);
  }
  if (Array.isArray(out.required)) {
    out.required = [...(out.required as string[])].sort();
    if ((out.required as string[]).length === 0) delete out.required;
  }
  return out;
}

/** Reduce a JSON Schema to its canonical structural form (see module doc). */
export function normalizeJsonSchema(schema: unknown): unknown {
  if (!isObject(schema)) throw new Error("normalize: expected a schema object");
  const defs = isObject(schema.$defs) ? schema.$defs : {};
  const inlined = deref({ ...schema, $defs: undefined }, defs) as JsonObject;
  delete inlined.$defs;
  return normalizeNode(inlined);
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
