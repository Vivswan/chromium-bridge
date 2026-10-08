// One JSON-Schema-to-Zod emission for both generators (scripts/gen-ops.ts and scripts/gen-envelope.ts): the
// validator is the Zod source json-schema-to-zod writes from a prepared JSON Schema, the exported type is
// json-schema-to-typescript's reading of the same schema, and the rules the repository holds its validators
// to are checks over the emitted validator's own reading, run before anything is written:
//
//   R1  every object node is closed: additionalProperties false, or the loose form only on a reader under the
//       loose-frames rule (src/packages/shared/src/envelope-asymmetries.ts) - a Rust type losing
//       deny_unknown_fields, or a schema that forgot to say so, would read as a passthrough object
//   R2  no default: serde fills defaults on the Rust READ side, so a .default() here would hand consumers values
//       the frame never carried
//   R3  every integer is a JS-safe integer (the safe-integers rule of the asymmetry table): above 2^53 - 1 two
//       consecutive host u64 values could read equal here
//   R4  the object branches of a union (nested unions flattened) are discriminated: one key required in every
//       branch, a distinct const each, whatever non-object arms ride beside them. A plain union of overlapping
//       objects would admit a frame no branch's producer emits
//
// A oneOf never reaches the emitter: prepare has rewritten every discriminated oneOf to anyOf (G3), and the
// emitter's exclusive form is a refinement the reading cannot see, so one that slipped through fails here.
//
// Which keywords the emitter reads at all is pinned once, in scripts/tests/gen-schema.test.ts, against the
// keyword lists the generators admit (prepare's allowlist and the asymmetry table's changes).

import { compile, type JSONSchema as TypeSchema } from "json-schema-to-typescript";
import { jsonSchemaToZod, type JsonSchema as ZodInput } from "json-schema-to-zod";
import traverse from "json-schema-traverse";
import { z } from "zod";

export type JsonObject = Record<string, unknown>;

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function show(v: unknown): string {
  return JSON.stringify(v) ?? String(v);
}

/** A schema another generated module exports, standing in for a node: the validator is the `symbol` imported
 * from `from`, the type its exported `type`. */
export interface ImportedSchema {
  from: string;
  symbol: string;
  type: string;
}

/** The node that stands for an imported schema; `tsType` is json-schema-to-typescript's keyword for a type it
 * emits by name. */
export function importedNode(imported: ImportedSchema): JsonObject {
  return { imported, tsType: imported.type };
}

export function importedOf(node: JsonObject): ImportedSchema | undefined {
  return isObject(node.imported) ? (node.imported as unknown as ImportedSchema) : undefined;
}

/** Every imported schema a tree refers to, each once. */
export function importsOf(schema: unknown): ImportedSchema[] {
  const seen = new Map<string, ImportedSchema>();
  for (const [, node] of schemaNodes(schema)) {
    const imported = importedOf(node);
    if (imported !== undefined) seen.set(`${imported.from}#${imported.symbol}`, imported);
  }
  return [...seen.values()];
}

/** The Zod source json-schema-to-zod writes for a schema: the validator the generated module ships, an
 * imported node spelled as its symbol. */
export function zodSource(schema: unknown): string {
  for (const [path, node] of schemaNodes(schema)) {
    if ("oneOf" in node) {
      throw new Error(
        `gen-schema: ${path} carries a oneOf the emitter would turn into an opaque refinement; prepare rewrites it to anyOf (G3)`,
      );
    }
  }
  return jsonSchemaToZod(schema as ZodInput, {
    module: "none",
    zodVersion: 4,
    parserOverride: (node) => importedOf(node as JsonObject)?.symbol,
  });
}

/** The shipped validator, built from that same source, so the rules judge what the module will run and not
 * the schema it was written from. `imports` supplies the validators the imported nodes name, by symbol. */
export function emittedValidator(
  schema: unknown,
  imports: Readonly<Record<string, z.ZodType>> = {},
): z.ZodType {
  const symbols = importsOf(schema).map((imported) => imported.symbol);
  for (const symbol of symbols) {
    if (!(symbol in imports)) {
      throw new Error(`gen-schema: no validator supplied for the imported ${symbol}`);
    }
  }
  const build = new Function("z", ...symbols, `return ${zodSource(schema)};`);
  return build(z, ...symbols.map((symbol) => imports[symbol])) as z.ZodType;
}

/** A validator's reading, serialized as the INPUT side of a JSON Schema (the output side of a stripping
 * object also says additionalProperties: false, so only the input side tells strict from strip). */
function inputReading(validator: z.ZodType): JsonObject {
  const reading = z.toJSONSchema(validator, { io: "input" }) as JsonObject;
  delete reading.$schema;
  return reading;
}

export function emittedReading(
  schema: unknown,
  imports: Readonly<Record<string, z.ZodType>> = {},
): JsonObject {
  return inputReading(emittedValidator(schema, imports));
}

/** Every object schema node of a tree, depth first, each under its JSON pointer from the root (`#`,
 * `#/properties/x`, `#/anyOf/0`), which is how a diagnostic names it. */
export function schemaNodes(root: unknown): [string, JsonObject][] {
  const out: [string, JsonObject][] = [];
  if (!isObject(root)) return out;
  traverse(root, { cb: (node, pointer) => out.push([`#${pointer}`, node]) });
  return out;
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

/** The leaf branches of a union node, nested unions flattened; a union inside a branch's property belongs
 * to that property, not to this union. */
function unionBranches(node: JsonObject): JsonObject[] {
  const leaves: JsonObject[] = [];
  traverse(node, {
    cb: (sub, pointer) => {
      if (/^(\/anyOf\/\d+)+$/.test(pointer) && !Array.isArray(sub.anyOf)) leaves.push(sub);
    },
  });
  return leaves;
}

/** The branches are object schemas sharing one required key whose const differs in every branch; returns that
 * key, or `fail`s with why. `tags` is the const's admitted type: serde's tag is a string (G3), an ok-split arm's
 * is a boolean, so R4 admits any. */
export function assertDiscriminated(
  branches: unknown[],
  fail: (why: string) => never,
  tags: "string" | "any" = "any",
): string {
  const first = branches[0];
  if (first === undefined || !isObject(first) || !isObject(first.properties)) {
    return fail("has no object branches");
  }
  const objects: JsonObject[] = [];
  for (const branch of branches) {
    if (!isObject(branch) || branch.type !== "object" || !isObject(branch.properties)) {
      return fail("has a non-object branch");
    }
    objects.push(branch);
  }
  outer: for (const candidate of Object.keys(first.properties)) {
    const seen = new Set<string>();
    for (const branch of objects) {
      const tagNode = (branch.properties as JsonObject)[candidate];
      const tag = isObject(tagNode) ? tagNode.const : undefined;
      const usable = tags === "string" ? typeof tag === "string" : tag !== undefined;
      const required = Array.isArray(branch.required) ? branch.required : [];
      if (!usable || seen.has(show(tag)) || !required.includes(candidate)) continue outer;
      seen.add(show(tag));
    }
    return candidate;
  }
  return fail("is a union of objects with no discriminating required const");
}

export function assertSchemaRules(
  name: string,
  schema: unknown,
  loose: boolean,
  imports: Readonly<Record<string, z.ZodType>> = {},
): void {
  assertReadingRules(name, emittedReading(schema, imports), loose);
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

export function schemaExpression(type: string, schema: unknown): string {
  return `${zodSource(schema)} satisfies z.ZodType<${type}>`;
}

/** The source of one exported validator; without a `type` it is exported as zod types it (a faithful base,
 * which only the gate reads). */
export function schemaSource(name: string, type: string | undefined, schema: unknown): string {
  const expression = type === undefined ? zodSource(schema) : schemaExpression(type, schema);
  return `export const ${name} = ${expression};`;
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

/** Run one of the core's gen-only emitter examples and parse what it prints. `-q` keeps cargo's own output
 * off the pipe; a compile error still lands on stderr and fails loudly here. */
export function emitFromRust(root: string, example: string, features?: string): unknown {
  const emitted = Bun.spawnSync(
    [
      "cargo",
      "run",
      "--frozen",
      "-q",
      "-p",
      "genkan-core",
      ...(features === undefined ? [] : ["--features", features]),
      "--example",
      example,
    ],
    { cwd: root, stderr: "inherit" },
  );
  if (!emitted.success) {
    throw new Error(`gen-schema: cargo ${example} failed with status ${emitted.exitCode}`);
  }
  return JSON.parse(emitted.stdout.toString());
}
