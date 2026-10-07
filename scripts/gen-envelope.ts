#!/usr/bin/env bun

// Generate the extension's wire validators (src/packages/shared/src/envelope.gen.ts) from the Rust core's
// schemars-derived JSON Schemas: the FAITHFUL base per envelope and control frame (strict objects, required
// fields required, no defaults), and beside each reader base the ENFORCED validator, which is that base plus
// exactly the asymmetries declared in src/packages/shared/src/envelope-asymmetries.ts. The extension runs the
// enforced validators; the bases exist so the asymmetry gate (scripts/check-envelope.ts) can prove each entry.
// Every validator is the Zod source json-schema-to-zod writes from its JSON Schema and every exported type is
// json-schema-to-typescript's reading of the same schema; scripts/gen-schema.ts holds the emitted validator to
// the schema rules R1-R4 before the file is written.
//
//   `moon run gen`   -> cargo example emit_envelope_schema (gen-only `envelope-schema` feature) -> dereference
//                       -> prepare -> applyAsymmetries (readers only) -> gen-schema (rules, type, Zod source)
//                       -> write
//   check-gen in CI  -> regenerates and fails on a stale diff
//
// Fail-closed rules over the Rust input; a violation aborts, because shipping a weaker parser than the Rust
// contract is never an option. The error messages cite them by number.
//   G1  every object declares type: "object" + additionalProperties: false: an object claim is stated, never
//       inferred, and a Rust type losing deny_unknown_fields fails here (the library's reading is then held
//       closed by R1)
//   G2  `default` is stripped: serde fills defaults on the Rust READ side; a .default() would hand consumers
//       values the frame never carried (required-ness is unchanged: schemars already leaves defaulted fields optional)
//   G3  oneOf only as a discriminated union (the same required const tag in every branch, values distinct), then
//       rewritten to anyOf: the mutual exclusivity needs no exclusive-union check at runtime
//   G4  every internal $ref dereferenced (json-schema-ref-parser) before emission, an external one left in
//       place for prepare to refuse; nothing downstream resolves one
//   G5  every keyword and type on the supported list below, in a position the library enforces (the keyword
//       census in scripts/tests/gen-schema.test.ts says which it reads); an unlisted keyword aborts until
//       support lands in that census AND in the adversarial tests. The empty schema {} is the contract's own
//       free-form claim (BridgeResp.data, and the request envelope's args once G6 has split the command off),
//       read as unknown so consumers must narrow
//   G6  the request's command (serde `#[serde(flatten)]` of the adjacently tagged BridgeCommand) arrives as the
//       envelope's own properties beside a `oneOf` of {op, args} branches under `unevaluatedProperties: false`.
//       splitFlattenedCommand hands it back as the envelope (op: string, args: any) plus one args schema per op:
//       the envelope base stays a strict object, and the per-op schemas are scripts/gen-ops.ts's
//   G7  every variant of every Rust control-frame enum is planned exactly once below (a reader, a writer, or a
//       bare classification tag), so an added or renamed variant fails generation until the plan says how the
//       extension covers it
//   A1  an asymmetry entry names a path the prepared Rust schema has, and its node is in the shape the change
//       expects (a `string` change on a plain string, a `string-arm` on a number, ...); a stale or misplaced
//       entry aborts instead of sitting inert
//   A2  a `generated-schema` entry puts the schema another generated module exports in place of a node, imported
//       by name; the imported schema is cross-checked against the Rust node it stands in for (same field
//       inventory, same base type per field, strict where the Rust node refuses unknown fields), two Rust
//       emitters held to each other
//   A3  an `ok-split` entry (at `$`) names a required boolean discriminant and one arm per value; each arm's
//       required and forbidden fields exist on the frame, and the reader is a union whose arms require and
//       refuse exactly those fields, so a frame the typed producer cannot emit (ok with an error, a refusal
//       without its reason) fails the reader rather than a consumer's re-check

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import $RefParser from "@apidevtools/json-schema-ref-parser";
import { walk } from "neotraverse";
import { z } from "zod";
import {
  ASYMMETRIES,
  type Asymmetry,
  type Change,
} from "../src/packages/shared/src/envelope-asymmetries";
import {
  assertDiscriminated,
  assertSchemaRules,
  emitFromRust,
  type ImportedSchema,
  importedNode,
  importedOf,
  importsOf,
  isObject,
  type JsonObject,
  schemaSource,
  show,
  typeSource,
} from "./gen-schema";

// Keys that annotate a schema without constraining instances; stripped before emission (schemars puts a field's
// doc comment here).
export const ANNOTATION_KEYS = new Set([
  "$schema",
  "$id",
  "$comment",
  "title",
  "description",
  "examples",
]);

const REF_SIBLING_KEYS = new Set(["description"]);

/** G4: the dereference merges a $ref's siblings over the target, the sibling winning (description is the one
 * key schemars puts beside a $ref). The library resolves a $ref in any object of the document, keyword or
 * not, so the walk is over every object, not over the schema keywords. */
export function assertRefSiblings(schema: JsonObject): void {
  walk(schema, (context, node: unknown) => {
    if (!isObject(node) || typeof node.$ref !== "string") return;
    const extra = Object.keys(node).filter((key) => key !== "$ref" && !REF_SIBLING_KEYS.has(key));
    if (extra.length > 0) {
      throw new Error(
        `gen-envelope: $ref ${node.$ref} at #/${context.path.join("/")} carries ${extra.join(", ")}; ` +
          `the dereference would merge them over the target, so only ${[...REF_SIBLING_KEYS].join(", ")} ` +
          "may sit beside a $ref (G4)",
      );
    }
  });
}

/** Split an internally-tagged (serde `tag = "type"`) enum schema into one subschema per tag, every internal
 * $ref dereferenced first (G4). Refuses anything that is not exactly the shape schemars emits for such an
 * enum: a top-level oneOf whose every branch is an object schema carrying a unique string `type` const. */
export async function splitTaggedUnionSchema(schema: unknown): Promise<Map<string, unknown>> {
  if (!isObject(schema)) throw new Error("gen-envelope: split expected a schema object");
  assertRefSiblings(schema);
  // dereference rewrites its argument in place; the Rust output is read once per group, so a copy keeps the
  // caller's object as it was.
  const inlined = (await $RefParser.dereference(structuredClone(schema) as never, {
    resolve: { external: false },
  })) as JsonObject;
  delete inlined.$defs;
  const variants = inlined.oneOf;
  if (!Array.isArray(variants)) throw new Error("gen-envelope: split expected a top-level oneOf");
  const out = new Map<string, unknown>();
  for (const variant of variants) {
    if (!isObject(variant) || !isObject(variant.properties)) {
      throw new Error(`gen-envelope: split: variant is not an object schema: ${show(variant)}`);
    }
    const tagNode = variant.properties.type;
    const tag = isObject(tagNode) ? tagNode.const : undefined;
    if (typeof tag !== "string") {
      throw new Error(
        `gen-envelope: split: variant without a string \`type\` const: ${show(variant)}`,
      );
    }
    if (out.has(tag)) throw new Error(`gen-envelope: split: duplicate tag ${tag}`);
    out.set(tag, variant);
  }
  return out;
}

// G3: accept the branch list only if some property is a required string const in every branch with all values
// distinct; the union is then discriminated and oneOf/anyOf coincide. Returns the discriminating property.
export function assertDiscriminatedUnion(branches: unknown[], path: string): string {
  return assertDiscriminated(
    branches,
    (why) => {
      throw new Error(`gen-envelope: oneOf at ${path} ${why} (G3)`);
    },
    "string",
  );
}

/** The request's flattened command, split back into the two things the rest of the pipeline models (G6). */
export interface FlattenedCommand {
  /** The envelope with the command's two fields restored as plain members: `op` any string, `args` any object.
   * The same shape the request had before the command was typed. */
  envelope: JsonObject;
  /** Each op's args schema (the Rust args struct, as schemars emitted it), keyed by the op const. */
  commands: Map<string, unknown>;
}

// The branch shape is serde's adjacently tagged variant under the flatten: exactly the two members, both
// required, the tag a string const. Anything else is a different serde shape and must not be read as a command.
const COMMAND_MEMBERS = ["args", "op"] as const;

export function splitFlattenedCommand(schema: unknown, path: string): FlattenedCommand {
  if (
    !isObject(schema) ||
    schema.type !== "object" ||
    !isObject(schema.properties) ||
    !Array.isArray(schema.oneOf) ||
    schema.oneOf.length === 0 ||
    schema.unevaluatedProperties !== false ||
    "additionalProperties" in schema ||
    "anyOf" in schema
  ) {
    throw new Error(`gen-envelope: ${path} is not a flattened tagged union (G6)`);
  }
  for (const member of COMMAND_MEMBERS) {
    if (member in schema.properties) {
      throw new Error(`gen-envelope: ${path} declares ${member} beside the flattened command (G6)`);
    }
  }
  const commands = new Map<string, unknown>();
  schema.oneOf.forEach((branch, i) => {
    const at = `${path}.oneOf[${i}]`;
    if (!isObject(branch) || branch.type !== "object" || !isObject(branch.properties)) {
      throw new Error(`gen-envelope: ${at} is not an object branch (G6)`);
    }
    for (const key of Object.keys(branch)) {
      if (!["type", "properties", "required"].includes(key) && !ANNOTATION_KEYS.has(key)) {
        throw new Error(`gen-envelope: ${at} carries ${key} beside the command members (G6)`);
      }
    }
    const members = Object.keys(branch.properties).sort().join();
    const required = Array.isArray(branch.required) ? [...branch.required].sort().join() : "";
    if (members !== COMMAND_MEMBERS.join() || required !== COMMAND_MEMBERS.join()) {
      throw new Error(`gen-envelope: ${at} is not exactly {op, args}, both required (G6)`);
    }
    const tag = branch.properties.op;
    const op = isObject(tag) && tag.type === "string" ? tag.const : undefined;
    if (typeof op !== "string") {
      throw new Error(`gen-envelope: ${at} has no string op const (G6)`);
    }
    if (commands.has(op)) throw new Error(`gen-envelope: ${path} repeats op ${op} (G6)`);
    commands.set(op, branch.properties.args);
  });
  const envelope: JsonObject = { ...schema };
  delete envelope.oneOf;
  delete envelope.unevaluatedProperties;
  // Sorted like schemars sorts its own properties, so the emitted base stays format-stable.
  envelope.properties = Object.fromEntries(
    Object.entries({ ...schema.properties, op: { type: "string" }, args: {} }).sort(([a], [b]) =>
      a.localeCompare(b),
    ),
  );
  const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
  envelope.required = [...required, ...COMMAND_MEMBERS];
  envelope.additionalProperties = false;
  return { envelope, commands };
}

// prepare (below) recurses only through positions that hold subschemas (property values, items, union
// branches), so a FIELD merely named like an annotation ("description", "default") is never stripped.
const SUPPORTED_KEYWORDS = new Set([
  "type",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "oneOf",
  "anyOf",
  "const",
  "enum",
  "format",
  "minimum",
  "maximum",
  "minItems",
]);

const SUPPORTED_TYPES = new Set([
  "object",
  "array",
  "string",
  "integer",
  "number",
  "boolean",
  "null",
]);

export function prepare(node: unknown, path: string): unknown {
  // The boolean schema `true` and the empty schema {} both mean "accept anything"; canonicalize to {} (read as
  // unknown). `false` (accept nothing) and any other non-object form are outside the Rust input this admits.
  if (node === true) return {};
  if (!isObject(node)) {
    throw new Error(`gen-envelope: unsupported schema form at ${path}: ${show(node)}`);
  }
  if ("$ref" in node) throw new Error(`gen-envelope: unresolved $ref at ${path} (G4)`);

  const out: JsonObject = {};
  for (const [key, value] of Object.entries(node)) {
    if (ANNOTATION_KEYS.has(key)) continue;
    if (key === "default") continue; // G2
    if (!SUPPORTED_KEYWORDS.has(key)) {
      throw new Error(`gen-envelope: unsupported schema keyword "${key}" at ${path} (G5)`);
    }
    out[key] = value;
  }

  const types = out.type === undefined ? [] : Array.isArray(out.type) ? out.type : [out.type];
  if (Array.isArray(out.type) && out.type.length === 0) {
    throw new Error(`gen-envelope: empty type list at ${path} (G5)`);
  }
  for (const t of types) {
    if (typeof t !== "string" || !SUPPORTED_TYPES.has(t)) {
      throw new Error(`gen-envelope: unsupported type ${show(t)} at ${path} (G5)`);
    }
  }

  // G5 placement: `format` is schemars' integer-width annotation (uint64, int32, ...), inert beside the
  // safe-integers rule and unread by zod, so it is stripped from an integer node and refused anywhere else (on a
  // string it would name a string format - uuid, email - and on a plain number an integer claim, neither of
  // which the reader would enforce). The numeric bounds may sit only on a numeric node (JSON Schema scopes
  // them per instance type: the Option null-arm beside a numeric type is inert and stays allowed).
  if ("format" in out) {
    if (!types.includes("integer") || !types.every((t) => t === "integer" || t === "null")) {
      throw new Error(`gen-envelope: "format" at ${path} sits on a non-integer node (G5)`);
    }
    delete out.format;
  }
  const numeric = types.includes("integer") || types.includes("number");
  const numericOrNull = numeric && types.every((t) => t !== "string" && t !== "boolean");
  for (const key of ["minimum", "maximum"] as const) {
    if (key in out && !numericOrNull) {
      throw new Error(`gen-envelope: "${key}" at ${path} sits on a non-numeric node (G5)`);
    }
  }
  for (const key of ["minimum", "maximum"] as const) {
    if (key in out && typeof out[key] !== "number") {
      throw new Error(`gen-envelope: non-numeric ${key} at ${path} (G5)`);
    }
  }
  // minItems is modeled only as a z.array() length floor, so it may sit only on an array node (the Option
  // null-arm beside it is inert, as above) and must be a non-negative integer.
  if ("minItems" in out) {
    if (!types.includes("array")) {
      throw new Error(`gen-envelope: "minItems" at ${path} sits on a non-array node (G5)`);
    }
    if (typeof out.minItems !== "number" || !Number.isInteger(out.minItems) || out.minItems < 0) {
      throw new Error(`gen-envelope: minItems at ${path} is not a non-negative integer (G5)`);
    }
  }

  // G1: object-shaped keywords demand the explicit, sole object type and deny_unknown_fields; an object claim
  // is stated, never inferred.
  const objectish = ["properties", "required", "additionalProperties"].filter((k) => k in out);
  if (objectish.length > 0 || types.includes("object")) {
    if (types.length !== 1 || types[0] !== "object") {
      throw new Error(
        `gen-envelope: ${path} carries ${objectish.join("/")} but type is ` +
          `${show(out.type)}, not "object" (G1)`,
      );
    }
    if (out.additionalProperties !== false) {
      throw new Error(
        `gen-envelope: object at ${path} does not carry additionalProperties:false (G1)`,
      );
    }
    const props = out.properties ?? {};
    if (!isObject(props)) throw new Error(`gen-envelope: malformed properties at ${path}`);
    const prepared: JsonObject = {};
    for (const [name, sub] of Object.entries(props)) {
      prepared[name] = prepare(sub, `${path}.properties.${name}`);
    }
    out.properties = prepared;
    const required = out.required ?? [];
    if (
      !Array.isArray(required) ||
      required.some((name) => typeof name !== "string" || !(name in props))
    ) {
      throw new Error(`gen-envelope: required names a non-property at ${path}`);
    }
  }

  if ("items" in out || types.includes("array")) {
    // The sole non-null type must be "array"; serde's Option<Vec<_>> null-arm beside it is inert (an array
    // keyword never constrains null) and stays allowed, like the numeric Option arms above.
    if (types.filter((t) => t !== "null").join() !== "array") {
      throw new Error(`gen-envelope: ${path} carries items but type is not "array" (G5)`);
    }
    if (!isObject(out.items)) {
      // Refuse missing/boolean/tuple items: z.array(z.any()) would accept elements the Rust parser refuses.
      throw new Error(`gen-envelope: array at ${path} lacks a single object items schema (G5)`);
    }
    out.items = prepare(out.items, `${path}.items`);
  }

  // Unions: a combinator node must be EXACTLY one non-empty combinator - sibling constraints beside a
  // combinator have no single faithful Zod form, and an empty union claims nothing, both weaker than the
  // contract.
  const [combinator, ...extraCombinators] = (["oneOf", "anyOf"] as const).filter(
    (key) => key in out,
  );
  if (combinator !== undefined) {
    const others = Object.keys(out).filter((key) => key !== combinator);
    if (extraCombinators.length > 0 || others.length > 0) {
      throw new Error(
        `gen-envelope: ${path} mixes ${combinator} with ` +
          `${[...extraCombinators, ...others].join("/")} - constraints would be dropped (G5)`,
      );
    }
    const branches = out[combinator];
    if (!Array.isArray(branches) || branches.length === 0) {
      throw new Error(`gen-envelope: empty or malformed ${combinator} at ${path} (G5)`);
    }
    out[combinator] = branches.map((branch, i) => prepare(branch, `${path}.${combinator}[${i}]`));
  }
  if (Array.isArray(out.oneOf)) {
    assertDiscriminatedUnion(out.oneOf, path);
    out.anyOf = out.oneOf;
    delete out.oneOf; // G3
  }

  // G5 placement: const and enum are modeled only as string literals, alone or on a plain string node (the
  // enum tags schemars emits); on any other type they would be ignored rather than enforced.
  for (const key of ["const", "enum"] as const) {
    if (!(key in out)) continue;
    const values = key === "enum" ? out.enum : [out.const];
    if (
      !Array.isArray(values) ||
      values.length === 0 ||
      values.some((v) => typeof v !== "string") ||
      new Set(values).size !== values.length
    ) {
      throw new Error(`gen-envelope: unsupported non-string or degenerate ${key} at ${path} (G5)`);
    }
    if (types.length > 0 && (types.length !== 1 || types[0] !== "string")) {
      throw new Error(`gen-envelope: ${key} on a non-string node at ${path} (G5)`);
    }
  }
  if ("const" in out && "enum" in out) {
    throw new Error(`gen-envelope: const beside enum at ${path} (G5)`);
  }

  return out;
}

// ---- the asymmetry pass (readers only) -----------------------------------------
//
// The pass writes plain JSON Schema, so its output is the library's input as it stands. Forms only it
// introduces (never read from the Rust schema; prepare refuses them there):
//   minLength / maxLength / pattern on a string node   -> the `string` change
//   additionalProperties: true on an object node       -> the loose-frames rule
//   another module's exported schema, imported, in place of a node -> the `generated-schema` change
//   a `false` property schema                          -> a field an ok-split arm forbids: a present value (null
//                                                         included) fails the arm, absence passes

/** A `generated-schema` replacement the pass performed, kept for the A2 cross-check in main. */
export interface GeneratedReplacement {
  path: string;
  imported: ImportedSchema;
  /** The prepared Rust node the imported schema stands in for: its own null arm dropped when it was an
   * optional property, its children as prepared. */
  rust: unknown;
}

export interface AsymmetryPass {
  /** The transformed schema. */
  schema: unknown;
  replacements: GeneratedReplacement[];
}

// optional-only: serde's Option null arm on an OPTIONAL property (a null member of its type list or a null
// branch of its union). Only there: a required nullable value or a nullable array item (Vec<Option<_>>) has no
// omission to fall back on, so its null stays.
function dropNullArm(node: JsonObject): JsonObject {
  if (Array.isArray(node.type) && node.type.includes("null")) {
    const rest = node.type.filter((t) => t !== "null");
    return { ...node, type: rest.length === 1 ? rest[0] : rest };
  }
  if (Array.isArray(node.anyOf)) {
    const rest = node.anyOf.filter((b) => !(isObject(b) && b.type === "null"));
    if (rest.length !== node.anyOf.length) {
      return rest.length === 1 && isObject(rest[0]) ? rest[0] : { ...node, anyOf: rest };
    }
  }
  return node;
}

/** The exported type of a generated validator: its export name minus `Schema`. */
const typeOf = (schemaName: string) => schemaName.replace(/Schema$/, "");

function applyChange(node: JsonObject, change: Change, path: string): JsonObject {
  const refuse = (expected: string): never => {
    throw new Error(
      `gen-envelope: ${path} is not ${expected} (got ${show(node)}), so the ${change.change} ` +
        "asymmetry cannot apply (A1)",
    );
  };
  if (importedOf(node) !== undefined) {
    throw new Error(`gen-envelope: ${path} already stands for an imported schema (A1)`);
  }
  switch (change.change) {
    case "string": {
      if (node.type !== "string" || Object.keys(node).length !== 1) refuse("a plain string node");
      const out: JsonObject = { type: "string" };
      if (change.minLength !== undefined) out.minLength = change.minLength;
      if (change.maxLength !== undefined) out.maxLength = change.maxLength;
      if (change.pattern !== undefined) out.pattern = change.pattern;
      return out;
    }
    case "string-arm": {
      if (node.type !== "integer" && node.type !== "number") refuse("a numeric node");
      return { anyOf: [node, { type: "string" }] };
    }
    case "tag-union-as-enum-object": {
      const branches = node.anyOf;
      if (!Array.isArray(branches) || branches.length < 2 || Object.keys(node).length !== 1) {
        refuse("a union of at least two object variants");
      }
      const tag = assertDiscriminatedUnion(branches as unknown[], path);
      const values = new Set<string>();
      let content: [string, unknown] | undefined;
      for (const branch of branches as JsonObject[]) {
        const props = branch.properties as JsonObject;
        const others = Object.keys(props).filter((k) => k !== tag);
        const required = Array.isArray(branch.required) ? [...branch.required].sort() : [];
        if (others.length !== 1 || required.join() !== [tag, others[0]].sort().join()) {
          refuse(`a union of {${tag}, <one content field>} variants, both required`);
        }
        const [key] = others as [string];
        const tagNode = props[tag] as JsonObject;
        values.add(tagNode.const as string);
        if (content === undefined) content = [key, props[key]];
        else if (content[0] !== key || show(content[1]) !== show(props[key])) {
          refuse("a union whose variants share one content field with one schema");
        }
      }
      const [contentKey, contentSchema] = content as [string, unknown];
      return {
        type: "object",
        properties: {
          [tag]: { type: "string", enum: [...values] },
          [contentKey]: contentSchema,
        },
        required: [tag, contentKey],
        additionalProperties: false,
      };
    }
    case "generated-schema":
      return importedNode({
        from: change.from,
        symbol: change.symbol,
        type: typeOf(change.symbol),
      });
    case "ok-split":
      // Exhaustiveness only: the pass applies an ok-split after the field changes (applyOkSplit), never here.
      throw new Error(`gen-envelope: ${path}: an ok-split is applied after the field changes (A3)`);
  }
}

function applyOkSplit(
  node: JsonObject,
  change: Extract<Change, { change: "ok-split" }>,
  path: string,
): JsonObject {
  const refuse = (why: string): never => {
    throw new Error(`gen-envelope: ${path}: ${why}, so the ok-split cannot apply (A3)`);
  };
  if (path !== "$") refuse("an ok-split names a whole frame, not a field");
  const properties = node.properties;
  if (node.type !== "object" || !isObject(properties)) refuse("the frame is not an object node");
  const props = properties as JsonObject;
  const required = new Set(Array.isArray(node.required) ? (node.required as string[]) : []);
  const discriminant = props[change.discriminant];
  if (
    !isObject(discriminant) ||
    discriminant.type !== "boolean" ||
    !required.has(change.discriminant)
  ) {
    refuse(`${change.discriminant} is not a required boolean field`);
  }
  const values = change.arms.map((arm) => arm.when).sort();
  if (values.join() !== "false,true") refuse("the arms do not cover true and false exactly once");
  const arms = change.arms.map((arm) => {
    const armProps: JsonObject = {
      ...props,
      [change.discriminant]: { type: "boolean", const: arm.when },
    };
    const armRequired = new Set(required);
    for (const field of arm.required) {
      if (!Object.hasOwn(props, field)) refuse(`required field ${field} is not on the frame`);
      armRequired.add(field);
    }
    for (const field of arm.forbidden) {
      if (!Object.hasOwn(props, field)) refuse(`forbidden field ${field} is not on the frame`);
      if (armRequired.has(field))
        refuse(`${field} is both required and forbidden on the ok: ${arm.when} arm`);
      armProps[field] = false;
    }
    return { ...node, properties: armProps, required: [...armRequired] };
  });
  return { anyOf: arms };
}

/** Apply the reader rules and this kind's asymmetry entries to a prepared schema (A1). `loose` is the
 * loose-frames rule: true for control frames, false for the envelopes. Every entry must be consumed. */
export function applyAsymmetries(
  prepared: unknown,
  kind: string,
  entries: Readonly<Record<string, Asymmetry>>,
  loose: boolean,
): AsymmetryPass {
  const consumed = new Set<string>();
  const replacements: GeneratedReplacement[] = [];
  const visit = (node: unknown, path: string): unknown => {
    if (!isObject(node)) return node;
    let out: JsonObject = node;
    const entry = entries[path];
    if (entry !== undefined) {
      consumed.add(path);
      const kinds = new Set(entry.changes.map((change) => change.change));
      if (kinds.has("ok-split") && kinds.has("generated-schema")) {
        throw new Error(
          `gen-envelope: ${path}: a generated-schema replacement has no arms to split, so it cannot pair ` +
            "with an ok-split (A3)",
        );
      }
      for (const change of entry.changes) {
        if (change.change === "ok-split") continue;
        const rust = out;
        out = applyChange(out, change, path);
        const imported = importedOf(out);
        if (imported !== undefined) replacements.push({ path, imported, rust });
      }
    }
    // An imported schema is its module's to walk: strict and complete as that module wrote it.
    if (importedOf(out) !== undefined) return out;
    if (isObject(out.properties)) {
      const required = new Set(Array.isArray(out.required) ? out.required : []);
      const props: JsonObject = {};
      for (const [name, sub] of Object.entries(out.properties)) {
        const field = !required.has(name) && isObject(sub) ? dropNullArm(sub) : sub;
        props[name] = visit(field, `${path}.properties.${name}`);
      }
      out = { ...out, properties: props };
      if (loose) out = { ...out, additionalProperties: true };
    }
    if (isObject(out.items)) out = { ...out, items: visit(out.items, `${path}.items`) };
    if (Array.isArray(out.anyOf)) {
      out = { ...out, anyOf: out.anyOf.map((b, i) => visit(b, `${path}.anyOf[${i}]`)) };
    }
    for (const change of entry?.changes ?? []) {
      if (change.change === "ok-split") out = applyOkSplit(out, change, path);
    }
    return out;
  };
  const schema = visit(prepared, "$");
  const stale = Object.keys(entries).filter((path) => !consumed.has(path));
  if (stale.length > 0) {
    throw new Error(
      `gen-envelope: ${kind} asymmetry entries name paths the Rust schema does not have: ` +
        `${stale.join(", ")} (A1)`,
    );
  }
  return { schema, replacements };
}

// ---- the frame plan (G7) ---------------------------------------------------------

// The control-frame groups, keyed by the emit_envelope_schema output field that carries each Rust enum
// (EnclaveControl / AdminControl / PolicyControl / WebAuthnControl).
export const GROUPS = ["enclave", "admin", "policy", "webauthn"] as const;
export type Group = (typeof GROUPS)[number];

/** The host->extension frames the extension validates: the export names of the faithful base and of the
 * enforced validator (the base plus the asymmetry table). The enforced validator's type is exported under the
 * enforced name minus `Schema`. */
export const READER_FRAMES: Record<
  Group,
  Readonly<Record<string, { wire: string; enforced: string }>>
> = {
  enclave: {
    enclave_proof: { wire: "EnclaveProofWireSchema", enforced: "EnclaveProofFrameSchema" },
    enclave_error: { wire: "EnclaveErrorWireSchema", enforced: "EnclaveErrorFrameSchema" },
  },
  admin: {
    client_list_result: { wire: "ClientListResultWireSchema", enforced: "ClientListResultSchema" },
    client_revoke_result: {
      wire: "ClientRevokeResultWireSchema",
      enforced: "ClientRevokeResultSchema",
    },
    kill_status_result: { wire: "KillStatusResultWireSchema", enforced: "KillStatusResultSchema" },
    registration_status_result: {
      wire: "RegistrationStatusResultWireSchema",
      enforced: "RegistrationStatusResultSchema",
    },
    audit_read_result: { wire: "AuditReadResultWireSchema", enforced: "AuditReadResultSchema" },
    doctor_report_result: {
      wire: "DoctorReportResultWireSchema",
      enforced: "DoctorReportResultSchema",
    },
  },
  policy: {
    policy_current: { wire: "PolicyCurrentWireSchema", enforced: "PolicyCurrentFrameSchema" },
    policy_restrict_result: {
      wire: "PolicyRestrictResultWireSchema",
      enforced: "PolicyRestrictResultSchema",
    },
    lang_current: { wire: "LangCurrentWireSchema", enforced: "LangCurrentFrameSchema" },
  },
  webauthn: {
    enroll_options: { wire: "EnrollOptionsWireSchema", enforced: "EnrollOptionsFrameSchema" },
    enroll_result: { wire: "EnrollResultWireSchema", enforced: "EnrollResultFrameSchema" },
    presence_request: { wire: "PresenceRequestWireSchema", enforced: "PresenceRequestFrameSchema" },
    presence_result: { wire: "PresenceResultWireSchema", enforced: "PresenceResultFrameSchema" },
    browser_revoke_result: {
      wire: "BrowserRevokeResultWireSchema",
      enforced: "BrowserRevokeResultFrameSchema",
    },
  },
};

/** Host->extension frames with no fields beyond the tag: classified by tag alone, no validator; generation
 * refuses one that grows a field until a reader is planned for it. */
export const BARE_TAG_FRAMES: Record<Group, readonly string[]> = {
  enclave: ["enclave_revoked"],
  admin: [],
  policy: [],
  webauthn: [],
};

/** The extension->host frames the extension CONSTRUCTS; the Rust serde parser is the enforcing reader, so these
 * exist only for their inferred types, and every constructor site claims conformance with `satisfies` (a drifted
 * field or typo'd tag fails to compile instead of being refused by the host at runtime). */
export const WRITER_FRAMES: Record<Group, Readonly<Record<string, string>>> = {
  enclave: {
    enclave_challenge: "EnclaveChallengeWireSchema",
    enclave_revoke: "EnclaveRevokeWireSchema",
  },
  admin: {
    client_list: "ClientListWireSchema",
    client_revoke: "ClientRevokeWireSchema",
    kill_status: "KillStatusWireSchema",
    kill_engage: "KillEngageWireSchema",
    kill_release: "KillReleaseWireSchema",
    audit_event: "AuditEventWireSchema",
    audit_read: "AuditReadWireSchema",
    doctor_report: "DoctorReportWireSchema",
    registration_status: "RegistrationStatusWireSchema",
    registration_repair: "RegistrationRepairWireSchema",
  },
  policy: {
    policy_get: "PolicyGetWireSchema",
    policy_restrict: "PolicyRestrictWireSchema",
    lang_set: "LangSetWireSchema",
    lang_get: "LangGetWireSchema",
  },
  webauthn: {
    enroll_begin: "EnrollBeginWireSchema",
    enroll_finish: "EnrollFinishWireSchema",
    presence_begin: "PresenceBeginWireSchema",
    presence_assert: "PresenceAssertWireSchema",
    presence_confirm: "PresenceConfirmWireSchema",
    browser_revoke: "BrowserRevokeWireSchema",
  },
};

/** The server->extension frames beside the request (the Rust `BridgeSignal` enum), each read STRICT like the
 * envelopes: the writer is the MCP server, and an envelope field it adds is a protocol change an older
 * extension refuses rather than misreads. One reader per variant, planned here like the control frames (G7). */
export const SIGNAL_FRAMES: Readonly<Record<string, { wire: string; enforced: string }>> = {
  cancel: { wire: "BridgeCancelWireSchema", enforced: "BridgeCancelSchema" },
};

/** G7 for the signal enum: every variant planned, every planned tag a variant. */
export function assertSignalPlan(variants: Map<string, unknown>): void {
  for (const tag of variants.keys()) {
    if (!Object.hasOwn(SIGNAL_FRAMES, tag)) {
      throw new Error(`gen-envelope: the Rust signal enum has an unplanned frame ${tag} (G7)`);
    }
  }
  for (const tag of Object.keys(SIGNAL_FRAMES)) {
    if (!variants.has(tag)) {
      throw new Error(
        `gen-envelope: ${tag} is planned as a signal reader but the Rust signal enum has no such frame (G7)`,
      );
    }
  }
}

/** G7: every Rust variant planned exactly once, every planned tag a Rust variant, every bare tag fieldless. */
export function assertFramePlan(group: Group, variants: Map<string, unknown>): void {
  const planned = new Map<string, string>();
  const plan = (tag: string, how: string) => {
    const prior = planned.get(tag);
    if (prior !== undefined) {
      throw new Error(
        `gen-envelope: ${group} frame ${tag} is planned as both ${prior} and ${how} (G7)`,
      );
    }
    planned.set(tag, how);
  };
  for (const tag of Object.keys(READER_FRAMES[group])) plan(tag, "a reader");
  for (const tag of BARE_TAG_FRAMES[group]) plan(tag, "a bare tag");
  for (const tag of Object.keys(WRITER_FRAMES[group])) plan(tag, "a writer");
  for (const tag of variants.keys()) {
    if (!planned.has(tag)) {
      throw new Error(`gen-envelope: the Rust ${group} enum has an unplanned frame ${tag} (G7)`);
    }
  }
  for (const [tag, how] of planned) {
    const variant = variants.get(tag);
    if (variant === undefined) {
      throw new Error(
        `gen-envelope: ${tag} is planned as ${how} but the Rust ${group} enum has no such frame (G7)`,
      );
    }
    if (how === "a bare tag") {
      const keys =
        isObject(variant) && isObject(variant.properties) ? Object.keys(variant.properties) : [];
      const fields = keys.filter((key) => key !== "type");
      if (fields.length > 0 || !keys.includes("type")) {
        throw new Error(`gen-envelope: bare tag ${tag} carries fields ${fields.join(", ")} (G7)`);
      }
    }
  }
}

// ---- A2: the imported schema against the Rust node it stands in for ----------------------

const nonNullType = (node: unknown): string | undefined => {
  if (!isObject(node)) return undefined;
  const types = Array.isArray(node.type) ? node.type : [node.type];
  return types.filter((t) => t !== "null" && t !== undefined).join("|") || undefined;
};

/** Hold an imported schema to the Rust object node it stands in for: same field names, same base type per
 * field (the null arm aside; the asymmetry table owns that), and strict where the Rust node refuses unknown
 * fields (the loose-frames rule never reaches a replaced node, so a loose import would be a silent widening).
 * Skipped for the any-schema (nothing to hold). */
export function assertGeneratedMatches(
  replacement: GeneratedReplacement,
  generated: z.ZodType,
): void {
  const { rust, path, imported } = replacement;
  if (!isObject(rust) || !isObject(rust.properties)) return;
  const derived = z.toJSONSchema(generated) as JsonObject;
  const derivedProps = isObject(derived.properties) ? derived.properties : {};
  if (rust.additionalProperties === false && derived.additionalProperties !== false) {
    throw new Error(
      `gen-envelope: ${path}: ${imported.symbol} admits unknown fields where the Rust node refuses them (A2)`,
    );
  }
  const rustKeys = Object.keys(rust.properties).sort();
  const derivedKeys = Object.keys(derivedProps).sort();
  if (rustKeys.join() !== derivedKeys.join()) {
    throw new Error(
      `gen-envelope: ${path}: ${imported.symbol} has fields [${derivedKeys.join(", ")}] ` +
        `but the Rust node has [${rustKeys.join(", ")}] (A2)`,
    );
  }
  for (const key of rustKeys) {
    const want = nonNullType(rust.properties[key]);
    const got = nonNullType(derivedProps[key]);
    if (want !== got) {
      throw new Error(
        `gen-envelope: ${path}.${key}: ${imported.symbol} says ${got} but the Rust node says ${want} (A2)`,
      );
    }
  }
}

// ---- main ----------------------------------------------------------------------------

async function main(): Promise<void> {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");

  // The Rust core is the source: run its envelope-schema emitter.
  const fromRust = emitFromRust(root, "emit_envelope_schema", "envelope-schema") as {
    request: unknown;
    response: unknown;
    signal: unknown;
    enclave: unknown;
    admin: unknown;
    policy: unknown;
    webauthn: unknown;
  };

  const variants = {
    enclave: await splitTaggedUnionSchema(fromRust.enclave),
    admin: await splitTaggedUnionSchema(fromRust.admin),
    policy: await splitTaggedUnionSchema(fromRust.policy),
    webauthn: await splitTaggedUnionSchema(fromRust.webauthn),
  };
  for (const group of GROUPS) assertFramePlan(group, variants[group]);
  const signals = await splitTaggedUnionSchema(fromRust.signal);
  assertSignalPlan(signals);

  function preparedFrame(group: Group, tag: string): unknown {
    return prepare(variants[group].get(tag), `$.${group}.${tag}`);
  }

  // G6: the typed command is split off; its per-op args schemas are scripts/gen-ops.ts's, and the request's
  // args node is OpArgsSchema imported from there (the asymmetry table's generated-schema entry).
  const { envelope: requestEnvelope } = splitFlattenedCommand(fromRust.request, "$.request");

  const replacements: GeneratedReplacement[] = [];
  function enforced(kind: string, prepared: unknown, loose: boolean): unknown {
    const pass = applyAsymmetries(prepared, kind, ASYMMETRIES[kind] ?? {}, loose);
    replacements.push(...pass.replacements);
    return pass.schema;
  }
  const kindsWithEntries = new Set(Object.keys(ASYMMETRIES));

  // The validators the generated-schema entries import, read from the generated tree gen-ops.ts wrote just
  // before this script runs: the emitted source is evaluated against them for the rules, and A2 holds each to
  // the Rust node it stands in for.
  const owners = new Map<string, z.ZodType>();
  async function owner(imported: ImportedSchema): Promise<z.ZodType> {
    const key = `${imported.from}#${imported.symbol}`;
    const known = owners.get(key);
    if (known !== undefined) return known;
    const module = (await import(join(root, "src/packages/shared/src", imported.from))) as Record<
      string,
      unknown
    >;
    const schema = module[imported.symbol];
    if (!(schema instanceof z.ZodType)) {
      throw new Error(
        `gen-envelope: ${imported.from} exports no Zod schema named ${imported.symbol} (A2)`,
      );
    }
    owners.set(key, schema);
    return schema;
  }

  const pieces: string[] = [];
  /** One exported validator: the schema rules over the emitted validator first, then the exported type (the
   * enforced readers and the writers have one; the faithful bases are the gate's and have none), then the
   * schema itself. `loose` is the loose-frames rule, true only for an enforced control-frame reader. */
  async function exportSchema(name: string, node: unknown, loose: boolean, type?: string) {
    const imports: Record<string, z.ZodType> = {};
    for (const imported of importsOf(node)) imports[imported.symbol] = await owner(imported);
    assertSchemaRules(name, node, loose, imports);
    if (type !== undefined) pieces.push(await typeSource(type, node), "");
    pieces.push(schemaSource(name, type, node), "");
  }

  const request = prepare(requestEnvelope, "$.request");
  const response = prepare(fromRust.response, "$.response");
  kindsWithEntries.delete("request");
  kindsWithEntries.delete("response");

  pieces.push(
    "// The request envelope (BridgeReq) and the response envelope (BridgeResp): the faithful bases, then the",
    "// enforced validators the extension runs (the base plus the asymmetry table; strict like the host).",
  );
  await exportSchema("BridgeReqWireSchema", request, false);
  await exportSchema("BridgeRespWireSchema", response, false);
  await exportSchema(
    "BridgeReqSchema",
    enforced("request", request, false),
    false,
    "BridgeReqEnvelope",
  );
  await exportSchema(
    "BridgeRespSchema",
    enforced("response", response, false),
    false,
    "BridgeResp",
  );

  pieces.push(
    "// The server->extension signal frames (BridgeSignal), one strict reader per variant: the faithful base,",
    "// then the enforced validator the extension runs.",
  );
  for (const [tag, names] of Object.entries(SIGNAL_FRAMES)) {
    kindsWithEntries.delete(tag);
    const base = prepare(signals.get(tag), `$.signal.${tag}`);
    await exportSchema(names.wire, base, false);
    await exportSchema(names.enforced, enforced(tag, base, false), false, typeOf(names.enforced));
  }

  // Types embedded in a reader's field (an array's items, or an object field itself), emitted as their own
  // exports (base and enforced) so a consumer can name the type; the embedding readers carry the same node
  // inline. An ok-split reader carries the field on one arm only, so the search walks the arms; on the base
  // an Option field is a union with null, so the object arm is picked out of it.
  const EMBEDDED_TYPES = [
    {
      group: "admin",
      tag: "client_list_result",
      field: "clients",
      wire: "ClientEntryWireSchema",
      enforced: "TrustedClientSchema",
      doc: "One trusted-client entry (allowlist::ClientEntry), embedded in client_list_result's `clients` array.",
    },
    {
      group: "admin",
      tag: "registration_status_result",
      field: "browsers",
      wire: "RegistrationRowWireSchema",
      enforced: "RegistrationRowSchema",
      doc: "One browser's registration row (protocol::control::RegistrationRow), embedded in registration_status_result's `browsers` array.",
    },
    {
      group: "admin",
      tag: "audit_read_result",
      field: "entries",
      wire: "AuditTrailEntryWireSchema",
      enforced: "AuditTrailEntrySchema",
      doc: "One line of the host's audit trail (protocol::control::AuditTrailEntry), embedded in audit_read_result's `entries` array.",
    },
    {
      group: "admin",
      tag: "doctor_report_result",
      field: "report",
      wire: "HealthReportWireSchema",
      enforced: "HealthReportSchema",
      doc: "The health report (protocol::control::HealthReport), embedded as doctor_report_result's `report`.",
    },
  ] as const satisfies readonly {
    group: Group;
    tag: string;
    field: string;
    wire: string;
    enforced: string;
    doc: string;
  }[];
  const isObjectSchema = (node: unknown): boolean => isObject(node) && node.type === "object";
  const embeddedNode = (schema: unknown, field: string, tag: string): unknown => {
    const nodes = isObject(schema) && Array.isArray(schema.anyOf) ? schema.anyOf : [schema];
    for (const node of nodes) {
      if (!isObject(node) || !isObject(node.properties)) continue;
      const prop = node.properties[field];
      if (!isObject(prop)) continue;
      if (prop.items !== undefined) return prop.items;
      if (isObjectSchema(prop)) return prop;
      const arm = Array.isArray(prop.anyOf) ? prop.anyOf.find(isObjectSchema) : undefined;
      if (arm !== undefined) return arm;
    }
    throw new Error(`gen-envelope: ${tag} no longer embeds a ${field} items or object schema`);
  };
  const preparedBases = new Map<string, unknown>();
  const enforcedReaders = new Map<string, unknown>();
  for (const item of EMBEDDED_TYPES) {
    const base = preparedFrame(item.group, item.tag);
    const reader = enforced(item.tag, base, true);
    preparedBases.set(item.tag, base);
    enforcedReaders.set(item.tag, reader);
    pieces.push(`// ${item.doc}`);
    await exportSchema(item.wire, embeddedNode(base, item.field, item.tag), false);
    await exportSchema(
      item.enforced,
      embeddedNode(reader, item.field, item.tag),
      true,
      typeOf(item.enforced),
    );
  }

  pieces.push(
    "// The host->extension control frames: the faithful base, then the enforced reader (the base plus the",
    "// asymmetry table, read loose under its loose-frames rule).",
  );
  for (const group of GROUPS) {
    for (const [tag, names] of Object.entries(READER_FRAMES[group])) {
      kindsWithEntries.delete(tag);
      const base = preparedBases.get(tag) ?? preparedFrame(group, tag);
      const reader = enforcedReaders.get(tag) ?? enforced(tag, base, true);
      await exportSchema(names.wire, base, false);
      await exportSchema(names.enforced, reader, true, typeOf(names.enforced));
    }
  }
  if (kindsWithEntries.size > 0) {
    throw new Error(
      `gen-envelope: the asymmetry table names frames with no generated reader: ` +
        `${[...kindsWithEntries].join(", ")} (A1)`,
    );
  }

  // A2: every imported schema against the Rust node it stands in for.
  for (const replacement of replacements) {
    assertGeneratedMatches(replacement, await owner(replacement.imported));
  }

  // The import lines: one per owner module, the validator and its type. A symbol two modules export under one
  // name cannot share the module scope.
  const bySymbol = new Map<string, ImportedSchema>();
  for (const { imported } of replacements) {
    const prior = bySymbol.get(imported.symbol);
    if (prior !== undefined && prior.from !== imported.from) {
      throw new Error(
        `gen-envelope: ${imported.symbol} is imported from both ${prior.from} and ${imported.from} (A2)`,
      );
    }
    bySymbol.set(imported.symbol, imported);
  }
  const byModule = new Map<string, ImportedSchema[]>();
  for (const imported of bySymbol.values()) {
    byModule.set(imported.from, [...(byModule.get(imported.from) ?? []), imported]);
  }
  const importLines = [...byModule.keys()].sort().map((from) => {
    const names = (byModule.get(from) ?? [])
      .flatMap((imported) => [imported.symbol, `type ${imported.type}`])
      .sort();
    return `import { ${names.join(", ")} } from ${JSON.stringify(from)};`;
  });

  const manifest = (table: Record<Group, Readonly<Record<string, unknown>> | readonly string[]>) =>
    GROUPS.map((group) => {
      const tags = Array.isArray(table[group]) ? table[group] : Object.keys(table[group]);
      return `  ${group}: [${(tags as string[]).map((tag) => JSON.stringify(tag)).join(", ")}],`;
    });

  pieces.push(
    "// Which control-frame tags have a generated reader above, and which are bare classification tags.",
    "// scripts/check-envelope.ts holds the extension's inbound classifiers to these.",
    "export const GENERATED_WIRE_FRAMES = {",
    ...manifest(READER_FRAMES),
    "} as const;",
    "",
    "export const BARE_TAG_FRAMES = {",
    ...manifest(BARE_TAG_FRAMES),
    "} as const;",
    "",
  );

  pieces.push(
    "// The extension->host writer frames (the extension constructs these; the enforcing reader is the Rust",
    "// serde parser). Emitted for their types: constructor sites claim conformance with `satisfies`, so a",
    "// drifted field or tag is a compile error. Never used as runtime parsers.",
  );
  for (const group of GROUPS) {
    for (const [tag, name] of Object.entries(WRITER_FRAMES[group])) {
      await exportSchema(name, preparedFrame(group, tag), false, typeOf(name));
    }
  }

  pieces.push(
    "// Which extension->host frames have a generated writer schema above.",
    "export const GENERATED_WRITER_FRAMES = {",
    ...manifest(WRITER_FRAMES),
    "} as const;",
  );

  const out = `// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs and
// protocol/control.rs; AdminControl embeds allowlist::ClientEntry, PolicyControl embeds
// policy::PolicyOverlay, WebAuthnControl carries the WebAuthn ceremonies) by scripts/gen-envelope.ts -
// DO NOT EDIT. Edit the Rust types or
// src/packages/shared/src/envelope-asymmetries.ts, then run \`moon run gen\`.
//
// Per envelope, per server->extension signal frame, and per host->extension control frame: the FAITHFUL base
// (*WireSchema: strict objects, required fields required, no defaults; rules G1-G7 in scripts/gen-envelope.ts)
// and the ENFORCED validator the extension runs, which is the base plus exactly the asymmetry table
// (direction and reason per entry in envelope-asymmetries.ts; proved per entry by scripts/check-envelope.ts,
// \`moon run check-envelope\`). Each validator is the Zod source json-schema-to-zod wrote from the Rust JSON
// Schema and each type is json-schema-to-typescript's reading of the same schema. The request's \`args\` and
// policy_current's \`overlay\` are the schemas ops.gen.ts and policy.gen.ts export, imported. The
// extension->host writer schemas exist for their types only (constructor-site \`satisfies\`); the enforcing
// reader for those frames is the Rust serde parser.

import { z } from "zod";
${importLines.join("\n")}

${pieces.join("\n")}
`;

  writeFileSync(join(root, "src/packages/shared/src/envelope.gen.ts"), out);
  console.log("generated src/packages/shared/src/envelope.gen.ts from the Rust wire types");
}

if (import.meta.main) await main();
