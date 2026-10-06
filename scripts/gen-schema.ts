// One JSON-Schema-to-Zod emission for both generators (scripts/gen-ops.ts and scripts/gen-envelope.ts): the
// validator is the library's reading of a prepared JSON Schema (z.fromJSONSchema), the exported type is
// json-schema-to-typescript's reading of the same schema, and the rules the repository holds its validators
// to are checks over the library's reading, run before anything is written:
//
//   R1  every object node is closed: additionalProperties false, or the loose form only on a reader under the
//       loose-frames rule (src/packages/shared/src/envelope-asymmetries.ts) - a Rust type losing
//       deny_unknown_fields, or a schema that forgot to say so, would read as a passthrough object
//   R2  no default: serde fills defaults on the Rust READ side, so a .default() here would hand consumers values
//       the frame never carried
//   R3  every integer is a JS-safe integer (the safe-integers rule of the asymmetry table): above 2^53 - 1 two
//       consecutive host u64 values could read equal here
//   R4  the object branches of a union (nested unions flattened, oneOf included) are discriminated: one key
//       required in every branch, a distinct const each, whatever non-object arms ride beside them. A plain
//       union of overlapping objects would admit a frame no branch's producer emits
//
// Which keywords the library reads at all is pinned once, in scripts/tests/gen-schema.test.ts, against the
// keyword lists the generators admit (prepare's allowlist and the asymmetry table's changes).

import { compile, type JSONSchema as TypeSchema } from "json-schema-to-typescript";
import { z } from "zod";

export type JsonObject = Record<string, unknown>;

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function show(v: unknown): string {
  return JSON.stringify(v) ?? String(v);
}

/** The library's reading of a JSON Schema, serialized as the INPUT side of a JSON Schema again (the output
 * side of a stripping object also says additionalProperties: false, so only the input side tells strict from
 * strip). */
export function libraryReading(schema: unknown): JsonObject {
  const reading = z.toJSONSchema(
    z.fromJSONSchema(schema as Parameters<typeof z.fromJSONSchema>[0]),
    {
      io: "input",
    },
  ) as JsonObject;
  delete reading.$schema;
  return reading;
}

/** Every schema node of a tree (the root, property values, items, union branches), depth first. */
export function* schemaNodes(node: unknown, path = "$"): Generator<[string, JsonObject]> {
  if (!isObject(node)) return;
  yield [path, node];
  if (isObject(node.properties)) {
    for (const [name, sub] of Object.entries(node.properties)) {
      yield* schemaNodes(sub, `${path}.properties.${name}`);
    }
  }
  if (node.items !== undefined) yield* schemaNodes(node.items, `${path}.items`);
  for (const combinator of ["anyOf", "oneOf"] as const) {
    const branches = node[combinator];
    if (!Array.isArray(branches)) continue;
    for (const [i, branch] of branches.entries()) {
      yield* schemaNodes(branch, `${path}.${combinator}[${i}]`);
    }
  }
}

const SAFE = Number.MAX_SAFE_INTEGER;

/** R1-R4 over a reading. `loose` says whether the loose object form may appear anywhere in it. */
export function assertReadingRules(name: string, reading: JsonObject, loose: boolean): void {
  const fail = (path: string, why: string, rule: string): never => {
    throw new Error(`gen-schema: ${name}: ${path} ${why} (${rule})`);
  };
  for (const [path, node] of schemaNodes(reading)) {
    if ("default" in node) fail(path, "carries a default", "R2");
    if (node.type === "object" || isObject(node.properties)) {
      const closing = node.additionalProperties;
      const isLoose = isObject(closing) && Object.keys(closing).length === 0;
      if (closing !== false && !(loose && isLoose)) {
        fail(path, `is an object read as ${show(closing ?? "open")}, not strict`, "R1");
      }
    }
    if (node.type === "integer") {
      const { minimum, maximum } = node;
      if (
        typeof minimum !== "number" ||
        typeof maximum !== "number" ||
        minimum < -SAFE ||
        maximum > SAFE
      ) {
        fail(
          path,
          `is an integer without JS-safe bounds (${show(minimum)}..${show(maximum)})`,
          "R3",
        );
      }
    }
    const objectBranches = unionBranches(node).filter((b) => b.type === "object");
    if (objectBranches.length > 1) {
      assertDiscriminated(objectBranches, (why) => fail(path, why, "R4"));
    }
  }
}

/** The leaf branches of a union node, nested unions flattened and oneOf read like anyOf (zod reads oneOf as an
 * exclusive union, which equals the plain union exactly when the object branches are discriminated, so R4 is
 * what makes the two readings agree). A non-union node has no branches. */
function unionBranches(node: JsonObject): JsonObject[] {
  const out: JsonObject[] = [];
  for (const combinator of ["anyOf", "oneOf"] as const) {
    const branches = node[combinator];
    if (!Array.isArray(branches)) continue;
    for (const branch of branches) {
      if (!isObject(branch)) continue;
      const nested = unionBranches(branch);
      out.push(...(nested.length > 0 ? nested : [branch]));
    }
  }
  return out;
}

/** The branches share one required key whose const differs in every branch; returns that key. */
export function assertDiscriminated(branches: JsonObject[], fail: (why: string) => never): string {
  const first = branches[0];
  if (first === undefined || !isObject(first.properties)) {
    return fail("is a union with no object branches");
  }
  outer: for (const candidate of Object.keys(first.properties)) {
    const seen = new Set<string>();
    for (const branch of branches) {
      const props = isObject(branch.properties) ? branch.properties : {};
      const tagNode = props[candidate];
      const tag = isObject(tagNode) ? tagNode.const : undefined;
      const required = Array.isArray(branch.required) ? branch.required : [];
      if (tag === undefined || seen.has(show(tag)) || !required.includes(candidate)) continue outer;
      seen.add(show(tag));
    }
    return candidate;
  }
  return fail("is a union of objects with no discriminating required const");
}

/** The gate for one emitted validator: the rules over the library's reading of its schema. */
export function assertSchemaRules(name: string, schema: unknown, loose: boolean): void {
  assertReadingRules(name, libraryReading(schema), loose);
}

/** Whether two schemas read the same to the library: the cross-module equality that replaces identity (a
 * node inlined into one generated module against the schema another generated module exports). */
export function readsEqual(schema: unknown, exported: z.ZodType): boolean {
  const theirs = z.toJSONSchema(exported, { io: "input" }) as JsonObject;
  delete theirs.$schema;
  return Bun.deepEquals(libraryReading(schema), theirs, true);
}

// ---- the schemas both generators build -----------------------------------------------

/** Every tool's args props, all optional, in one strict object (the request envelope's `args` bag before the
 * per-op validator runs). A prop two tools declare must agree on its schema, or the bag is ill-formed. */
export function opArgsSchema(argsByOp: ReadonlyMap<string, JsonObject>): JsonObject {
  const props = new Map<string, unknown>();
  for (const [op, args] of argsByOp) {
    if (!isObject(args.properties)) {
      throw new Error(`gen-schema: ${op} args schema is not an object schema`);
    }
    for (const [key, prop] of Object.entries(args.properties)) {
      const prior = props.get(key);
      if (prior !== undefined && show(prior) !== show(prop)) {
        throw new Error(
          `gen-schema: conflicting schemas for arg ${show(key)}: ${show(prior)} vs ${show(prop)}`,
        );
      }
      props.set(key, prop);
    }
  }
  return {
    type: "object",
    additionalProperties: false,
    properties: Object.fromEntries(props),
    required: [],
  };
}

/** The policy contract's value kinds (Rust FieldKind) and the bounds its document carries. */
export interface PolicyShape {
  fields: readonly { name: string; kind: "bool" | "ms" | "toolSet" }[];
  docVersion: number;
  revisionMax: number;
  disabledToolsMaxEntries: number;
  disabledToolNameMaxBytes: number;
}

function policyFieldSchema(
  kind: PolicyShape["fields"][number]["kind"],
  policy: PolicyShape,
): JsonObject {
  switch (kind) {
    case "bool":
      return { type: "boolean" };
    case "ms":
      return { type: "integer", minimum: 0 };
    case "toolSet":
      return {
        type: "array",
        items: { type: "string", minLength: 1, maxLength: policy.disabledToolNameMaxBytes },
        maxItems: policy.disabledToolsMaxEntries,
      };
  }
}

function policyFields(policy: PolicyShape): JsonObject {
  return Object.fromEntries(policy.fields.map((f) => [f.name, policyFieldSchema(f.kind, policy)]));
}

/** The field values without the document's scoping fields (Rust PolicyValues). */
export function policyValuesSchema(policy: PolicyShape): JsonObject {
  return {
    type: "object",
    additionalProperties: false,
    properties: policyFields(policy),
    required: policy.fields.map((f) => f.name),
  };
}

/** The signed policy document (Rust PolicyDoc): the version literal, the bounded revision, the touched set over
 * the field names, then every value. */
export function policyDocSchema(policy: PolicyShape): JsonObject {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      v: { type: "integer", const: policy.docVersion },
      revision: { type: "integer", minimum: 0, maximum: policy.revisionMax },
      touched: { type: "array", items: { type: "string", enum: policy.fields.map((f) => f.name) } },
      ...policyFields(policy),
    },
    required: ["v", "revision", "touched", ...policy.fields.map((f) => f.name)],
  };
}

/** The unsigned restriction overlay (Rust PolicyOverlay): every value optional under the document's bounds. */
export function policyOverlaySchema(policy: PolicyShape): JsonObject {
  return {
    type: "object",
    additionalProperties: false,
    properties: policyFields(policy),
    required: [],
  };
}

// ---- emission -------------------------------------------------------------------------

/** The expression of one validator: the library's reading of `schema`, typed as the exported `type`. */
export function schemaExpression(type: string, schema: unknown): string {
  return `z.fromJSONSchema(${show(schema)}) as z.ZodType<${type}>`;
}

/** The source of one exported validator. */
export function schemaSource(name: string, type: string, schema: unknown): string {
  return `export const ${name} = ${schemaExpression(type, schema)};`;
}

/** The source of one exported type: json-schema-to-typescript's reading of `schema`. An empty strict object
 * is typed Record<string, never>, never `{}` (which TypeScript reads as any non-null value); annotations were
 * stripped upstream, so no nested node is hoisted into a type of its own. */
export async function typeSource(type: string, schema: unknown): Promise<string> {
  const typed = structuredClone(schema) as unknown;
  for (const [, node] of schemaNodes(typed)) {
    if (
      node.type === "object" &&
      node.additionalProperties === false &&
      isObject(node.properties) &&
      Object.keys(node.properties).length === 0
    ) {
      node.tsType = "Record<string, never>";
    }
  }
  const source = await compile(typed as TypeSchema, type, {
    bannerComment: "",
    format: false,
    ignoreMinAndMaxItems: true,
    additionalProperties: false,
  });
  return source.trim();
}

/** `snake_case` to `PascalCase`, for a type named after an op or a tag. */
export function pascal(name: string): string {
  return name
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}
