#!/usr/bin/env bun

// Generate the extension's wire validators (src/packages/shared/src/envelope.gen.ts) from the Rust core's
// schemars-derived JSON Schemas: the FAITHFUL base per envelope and control frame (strict objects, required
// fields required, no defaults), and beside each reader base the ENFORCED validator, which is that base plus
// exactly the asymmetries declared in src/packages/shared/src/envelope-asymmetries.ts. The extension runs the
// enforced validators; the bases exist so the asymmetry gate (scripts/check-envelope.ts) can prove each entry.
//
//   `moon run gen`   -> cargo example emit_envelope_schema (gen-only `envelope-schema` feature) -> prepare ->
//                       applyAsymmetries (readers only) -> emitZod -> write
//   check-gen in CI  -> regenerates and fails on a stale diff
//
// Fail-closed generation rules; a violation aborts, because shipping a weaker parser than the Rust contract is
// never an option. The error messages cite them by number.
//   G1  every object declares type: "object" + additionalProperties: false, and the emitted source closes every
//       z.object( with .strict() (or, on a reader under the loose-frames rule, .catchall(z.unknown())) - neither
//       a Rust type losing deny_unknown_fields nor an emitter bug slips through
//   G2  `default` is stripped: serde fills defaults on the Rust READ side; a .default() would hand consumers
//       values the frame never carried (required-ness is unchanged: schemars already leaves defaulted fields optional)
//   G3  oneOf only as a discriminated union (the same required const tag in every branch, values distinct), then
//       emitted as a plain z.union: the mutual exclusivity needs no extra runtime check
//   G4  every $ref inlined before emission; the emitter does not resolve them
//   G5  every keyword and type on the supported list below, in a position the emitter models; an unmodeled
//       keyword would have to be silently dropped, so it aborts until support lands here AND in the adversarial
//       tests. The empty schema {} is the contract's own free-form claim (BridgeResp.data, and the request
//       envelope's args once G6 has split the command off), emitted as z.unknown() so consumers must narrow
//   G6  the request's command (serde `#[serde(flatten)]` of the adjacently tagged BridgeCommand) arrives as the
//       envelope's own properties beside a `oneOf` of {op, args} branches under `unevaluatedProperties: false`.
//       splitFlattenedCommand hands it back as the envelope (op: string, args: any) plus one args schema per op:
//       the envelope base stays a strict object, and the per-op schemas go to scripts/gen-ops.ts
//   G7  every variant of every Rust control-frame enum is planned exactly once below (a reader, a writer, or a
//       bare classification tag), so an added or renamed variant fails generation until the plan says how the
//       extension covers it
//   A1  an asymmetry entry names a path the prepared Rust schema has, and its node is in the shape the change
//       expects (a `string` change on a plain string, a `string-arm` on a number, ...); a stale or misplaced
//       entry aborts instead of sitting inert
//   A2  a `generated-schema` entry replacing an object node is cross-checked against the schema it names: same
//       field inventory, same base type per field, and strict where the Rust node refuses unknown fields (two
//       Rust emitters, held equal here)
//   A3  an `ok-split` entry (at `$`) names a required boolean discriminant and one arm per value; each arm's
//       required and forbidden fields exist on the frame, and the reader is emitted as a z.discriminatedUnion
//       whose arms require and refuse exactly those fields, so a frame the typed producer cannot emit (ok with
//       an error, a refusal without its reason) fails the reader rather than a consumer's re-check
//   A4  every faithful base and writer schema the file exports is held to Zod's own reading of the prepared
//       node it came from (z.fromJSONSchema): both serialize to the same JSON Schema, so a keyword this
//       emitter stops modeling, or a claim it adds that the node does not carry, is a diff against the library

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  ASYMMETRIES,
  type Asymmetry,
  type Change,
} from "../src/packages/shared/src/envelope-asymmetries";

type JsonObject = Record<string, unknown>;

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function show(v: unknown): string {
  return JSON.stringify(v) ?? String(v);
}

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

// The subset of those that are also harmless BESIDE a $ref: $id and $schema are excluded because they alter
// $ref resolution (base URI / dialect).
const REF_SIBLING_ANNOTATION_KEYS = new Set(["$comment", "title", "description", "examples"]);

// Inline every internal $ref against the root's $defs (G4).
function deref(node: unknown, defs: JsonObject): unknown {
  if (Array.isArray(node)) return node.map((item) => deref(item, defs));
  if (!isObject(node)) return node;
  const ref = node.$ref;
  if (typeof ref === "string") {
    const name = ref.match(/^#\/\$defs\/(.+)$/)?.[1];
    if (name === undefined || !(name in defs)) {
      throw new Error(`gen-envelope: unresolvable $ref ${ref} (G4)`);
    }
    // A $ref node's constraint siblings would be lost by a plain inline of the target; neither derivation
    // emits that form, so refuse it rather than silently merging. Pure-annotation siblings constrain nothing.
    for (const key of Object.keys(node)) {
      if (key !== "$ref" && !REF_SIBLING_ANNOTATION_KEYS.has(key)) {
        throw new Error(
          `gen-envelope: $ref with constraint siblings is not supported: ${ref} (G4)`,
        );
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

/** Split an internally-tagged (serde `tag = "type"`) enum schema into one subschema per tag, with $defs
 * indirection inlined first. Refuses anything that is not exactly the shape schemars emits for such an enum: a
 * top-level oneOf whose every branch is an object schema carrying a unique string `type` const. */
export function splitTaggedUnionSchema(schema: unknown): Map<string, unknown> {
  if (!isObject(schema)) throw new Error("gen-envelope: split expected a schema object");
  const defs = isObject(schema.$defs) ? schema.$defs : {};
  const inlined = deref({ ...schema, $defs: undefined }, defs) as JsonObject;
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
  const first = branches[0];
  if (branches.length === 0 || !isObject(first) || !isObject(first.properties)) {
    throw new Error(`gen-envelope: oneOf at ${path} has no object branches (G3)`);
  }
  outer: for (const candidate of Object.keys(first.properties)) {
    const seen = new Set<string>();
    for (const branch of branches) {
      if (!isObject(branch) || branch.type !== "object" || !isObject(branch.properties)) {
        throw new Error(`gen-envelope: oneOf at ${path} has a non-object branch (G3)`);
      }
      const tagNode = branch.properties[candidate];
      const tag = isObject(tagNode) ? tagNode.const : undefined;
      const required = Array.isArray(branch.required) ? branch.required : [];
      if (typeof tag !== "string" || seen.has(tag) || !required.includes(candidate)) {
        continue outer;
      }
      seen.add(tag);
    }
    return candidate; // discriminates every branch
  }
  throw new Error(`gen-envelope: oneOf at ${path} is not a discriminated union (G3)`);
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
  // The boolean schema `true` and the empty schema {} both mean "accept anything"; canonicalize to {} (emitted
  // as z.unknown()). `false` (accept nothing) and any other non-object form have no faithful emission.
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

  // G5 placement: format is modeled only as schemars' integer-width claim and the numeric bounds only as
  // z.number() bounds, so both may sit only on a numeric node (JSON Schema scopes them per instance type: the
  // Option null-arm beside a numeric type is inert and stays allowed, but a string arm would give `format` a
  // string-format meaning - uuid, email, ... - that this emitter does not model).
  const numeric = types.includes("integer") || types.includes("number");
  const numericOrNull = numeric && types.every((t) => t !== "string" && t !== "boolean");
  for (const key of ["format", "minimum", "maximum"] as const) {
    if (key in out && !numericOrNull) {
      throw new Error(`gen-envelope: "${key}" at ${path} sits on a non-numeric node (G5)`);
    }
  }
  for (const key of ["minimum", "maximum"] as const) {
    if (key in out && typeof out[key] !== "number") {
      throw new Error(`gen-envelope: non-numeric ${key} at ${path} (G5)`);
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
// Node forms only this pass introduces (never read from the Rust schema; prepare refuses them there):
//   minLength / maxLength / pattern on a string node   -> the `string` change
//   $loose: true on an object node                     -> the loose-frames rule, emitted as .catchall(z.unknown())
//   { $generated: symbol, $from: module }              -> the `generated-schema` change, emitted as the symbol

const LOOSE = "$loose";
const GENERATED = "$generated";
const GENERATED_FROM = "$from";
/** An ok-split's union node: the discriminant key; emitted as z.discriminatedUnion over `anyOf`. */
const DISCRIMINANT = "$discriminant";
/** A field an ok-split arm forbids: emitted as z.undefined(), so a present value (null included) fails the arm. */
const FORBIDDEN = "$forbidden";

/** A `generated-schema` replacement the pass performed, kept for the A2 cross-check in main. */
export interface GeneratedReplacement {
  path: string;
  symbol: string;
  from: string;
  /** The prepared Rust node the symbol stands in for: its own null arm dropped when it was an optional
   * property, its children as prepared. */
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

function applyChange(node: JsonObject, change: Change, path: string): JsonObject {
  const refuse = (expected: string): never => {
    throw new Error(
      `gen-envelope: ${path} is not ${expected} (got ${show(node)}), so the ${change.change} ` +
        "asymmetry cannot apply (A1)",
    );
  };
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
      return { [GENERATED]: change.symbol, [GENERATED_FROM]: change.from };
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
      armProps[field] = { [FORBIDDEN]: true };
    }
    return { ...node, properties: armProps, required: [...armRequired] };
  });
  return { [DISCRIMINANT]: change.discriminant, anyOf: arms };
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
        if (GENERATED in out) {
          throw new Error(`gen-envelope: ${path} is already a generated-schema replacement (A1)`);
        }
        const rust = out;
        out = applyChange(out, change, path);
        if (change.change === "generated-schema") {
          replacements.push({ path, symbol: change.symbol, from: change.from, rust });
        }
      }
    }
    if (GENERATED in out) return out;
    if (isObject(out.properties)) {
      const required = new Set(Array.isArray(out.required) ? out.required : []);
      const props: JsonObject = {};
      for (const [name, sub] of Object.entries(out.properties)) {
        const field = !required.has(name) && isObject(sub) ? dropNullArm(sub) : sub;
        props[name] = visit(field, `${path}.properties.${name}`);
      }
      out = { ...out, properties: props };
      if (loose) out = { ...out, [LOOSE]: true };
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

// ---- the emitter -----------------------------------------------------------------

// Emit Zod source for one prepared (and possibly asymmetry-transformed) node. Total over the subset prepare and
// applyAsymmetries produce: anything else is a bug upstream, so it throws rather than guesses. `override` lets
// a caller substitute a named schema for a specific node (matched by identity) instead of inlining it.
function emitZod(node: unknown, override?: (node: unknown) => string | undefined): string {
  const custom = override?.(node);
  if (custom !== undefined) return custom;
  if (!isObject(node)) {
    throw new Error(`gen-envelope: emitter reached an unprepared node: ${show(node)}`);
  }
  if (typeof node[GENERATED] === "string") return node[GENERATED];
  if (node[FORBIDDEN] === true) return "z.undefined()";
  if (typeof node[DISCRIMINANT] === "string" && Array.isArray(node.anyOf)) {
    const arms = node.anyOf.map((arm) => emitZod(arm, override));
    return `z.discriminatedUnion(${JSON.stringify(node[DISCRIMINANT])}, [${arms.join(", ")}])`;
  }
  if (Array.isArray(node.anyOf)) {
    // A non-empty, pure combinator; a one-branch union is the branch itself.
    if (node.anyOf.length === 1) return emitZod(node.anyOf[0], override);
    const branches = node.anyOf.map((branch) => emitZod(branch, override));
    return `z.union([${branches.join(", ")}])`;
  }
  if ("const" in node) return `z.literal(${JSON.stringify(node.const)})`;
  if (Array.isArray(node.enum)) {
    return `z.enum([${node.enum.map((v) => JSON.stringify(v)).join(", ")}])`;
  }
  if (Array.isArray(node.type)) {
    // serde's Option null-arm and friends: one branch per type, each keeping the node's other keywords
    // (numeric ones and items, per G5 placement; the null branch ignores them - none constrains null).
    const branches = node.type.map((type) => emitZod({ ...node, type }, override));
    return `z.union([${branches.join(", ")}])`;
  }
  switch (node.type) {
    case "object": {
      // additionalProperties: false is guaranteed by G1: .strict() is its faithful spelling, and a reader under
      // the loose-frames rule carries $loose instead. prepare always materializes `properties`.
      const required = new Set(Array.isArray(node.required) ? node.required : []);
      const fields = Object.entries(node.properties as JsonObject).map(([key, sub]) => {
        const value = emitZod(sub, override);
        return `${JSON.stringify(key)}: ${required.has(key) ? value : `${value}.optional()`}`;
      });
      const object = fields.length === 0 ? "z.object({})" : `z.object({ ${fields.join(", ")} })`;
      return node[LOOSE] === true ? `${object}.catchall(z.unknown())` : `${object}.strict()`;
    }
    case "array":
      return `z.array(${emitZod(node.items, override)})`;
    case "integer":
    case "number": {
      // schemars' integer-width formats: `integer` is already .int(); the int64 format on a plain number carries
      // the same integer claim. Other formats (uint64, double, ...) add nothing beyond the type and the explicit
      // bounds. z.number().int() is a JS-safe integer, the safe-integers rule of the asymmetry table.
      let out =
        node.type === "integer" || node.format === "int64" ? "z.number().int()" : "z.number()";
      if (typeof node.minimum === "number") out += `.gte(${JSON.stringify(node.minimum)})`;
      if (typeof node.maximum === "number") out += `.lte(${JSON.stringify(node.maximum)})`;
      return out;
    }
    case "string": {
      let out = "z.string()";
      if (typeof node.minLength === "number") out += `.min(${node.minLength})`;
      if (typeof node.maxLength === "number") out += `.max(${node.maxLength})`;
      if (typeof node.pattern === "string")
        out += `.regex(/${node.pattern.replaceAll("/", "\\/")}/)`;
      return out;
    }
    case "boolean":
      return "z.boolean()";
    case "null":
      return "z.null()";
    case undefined: {
      // The only typeless survivor of prepare is the empty any-schema: unknown, not any, so a consumer must
      // narrow the payload before using it (same instance set).
      if (Object.keys(node).length > 0) {
        throw new Error(`gen-envelope: emitter reached an unprepared node: ${show(node)}`);
      }
      return "z.unknown()";
    }
    default:
      throw new Error(`gen-envelope: emitter has no form for type ${show(node.type)}`);
  }
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// Emit one prepared schema as Zod source, then re-assert G1 on the OUTPUT: every emitted z.object( must be
// closed by a .strict() or, under the loose-frames rule, by .catchall(z.unknown()).
export function convert(
  schema: unknown,
  name: string,
  parserOverride?: (node: unknown) => string | undefined,
): string {
  const code = emitZod(schema, parserOverride);
  const objects = count(code, "z.object(");
  const closed = count(code, ".strict()") + count(code, ".catchall(z.unknown())");
  if (objects !== closed) {
    throw new Error(
      `gen-envelope: ${name}: emitted ${objects} z.object( but ${closed} strict/loose closings (G1)`,
    );
  }
  return code;
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
    presence_assert: "PresenceAssertWireSchema",
    presence_confirm: "PresenceConfirmWireSchema",
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

// ---- A2: the generated-schema cross-check -------------------------------------------

const nonNullType = (node: unknown): string | undefined => {
  if (!isObject(node)) return undefined;
  const types = Array.isArray(node.type) ? node.type : [node.type];
  return types.filter((t) => t !== "null" && t !== undefined).join("|") || undefined;
};

/** Hold a generated schema to the Rust object node it replaces: same field names, same base type per field
 * (the null arm aside; the asymmetry table owns that), and strict where the Rust node refuses unknown fields
 * (the loose-frames rule never reaches a replaced node, so a loose replacement would be a silent widening).
 * Skipped for the any-schema (nothing to hold). */
export function assertGeneratedMatches(
  replacement: GeneratedReplacement,
  generated: z.ZodType,
): void {
  const rust = replacement.rust;
  if (!isObject(rust) || !isObject(rust.properties)) return;
  const derived = z.toJSONSchema(generated) as JsonObject;
  const derivedProps = isObject(derived.properties) ? derived.properties : {};
  if (rust.additionalProperties === false && derived.additionalProperties !== false) {
    throw new Error(
      `gen-envelope: ${replacement.path}: ${replacement.symbol} admits unknown fields where the Rust node ` +
        "refuses them (A2)",
    );
  }
  const rustKeys = Object.keys(rust.properties).sort();
  const derivedKeys = Object.keys(derivedProps).sort();
  if (rustKeys.join() !== derivedKeys.join()) {
    throw new Error(
      `gen-envelope: ${replacement.path}: ${replacement.symbol} has fields [${derivedKeys.join(", ")}] ` +
        `but the Rust node has [${rustKeys.join(", ")}] (A2)`,
    );
  }
  for (const key of rustKeys) {
    const want = nonNullType(rust.properties[key]);
    const got = nonNullType(derivedProps[key]);
    if (want !== got) {
      throw new Error(
        `gen-envelope: ${replacement.path}.${key}: ${replacement.symbol} says ${got} but the Rust node ` +
          `says ${want} (A2)`,
      );
    }
  }
}

// ---- A4: the library's reading of each faithful schema ---------------------------------

/** Hold an exported schema to Zod's own reading of the prepared node it was emitted from: the two readings
 * must serialize to the same JSON Schema of their INPUT (the output schema of a stripping object also says
 * additionalProperties: false, so only the input side tells strict from strip). The enforced readers carry
 * this pass's own node forms ($loose, $generated, $discriminant, $forbidden), which the library does not
 * read, so the oracle covers the faithful bases and the writer schemas. */
export function assertLibraryReadingMatches(
  name: string,
  prepared: unknown,
  emitted: z.ZodType,
): void {
  const library = z.toJSONSchema(
    z.fromJSONSchema(prepared as Parameters<typeof z.fromJSONSchema>[0]),
    { io: "input" },
  );
  const ours = z.toJSONSchema(emitted, { io: "input" });
  if (!Bun.deepEquals(library, ours, true)) {
    throw new Error(
      `gen-envelope: ${name}: the emitted schema reads as ${show(ours)} but zod reads the Rust node as ` +
        `${show(library)} (A4)`,
    );
  }
}

// ---- main ----------------------------------------------------------------------------

async function main(): Promise<void> {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");

  // The Rust core is the source: run its envelope-schema emitter.
  const emitted = Bun.spawnSync(
    [
      "cargo",
      "run",
      "--frozen",
      "-q",
      "-p",
      "chromium-bridge-core",
      "--features",
      "envelope-schema",
      "--example",
      "emit_envelope_schema",
    ],
    { cwd: root, stderr: "inherit" },
  );
  if (!emitted.success) {
    throw new Error(`gen-envelope: cargo emit failed with status ${emitted.exitCode}`);
  }
  const fromRust = JSON.parse(emitted.stdout.toString()) as {
    request: unknown;
    response: unknown;
    signal: unknown;
    enclave: unknown;
    admin: unknown;
    policy: unknown;
    webauthn: unknown;
  };

  const variants = {
    enclave: splitTaggedUnionSchema(fromRust.enclave),
    admin: splitTaggedUnionSchema(fromRust.admin),
    policy: splitTaggedUnionSchema(fromRust.policy),
    webauthn: splitTaggedUnionSchema(fromRust.webauthn),
  };
  for (const group of GROUPS) assertFramePlan(group, variants[group]);
  const signals = splitTaggedUnionSchema(fromRust.signal);
  assertSignalPlan(signals);

  function preparedFrame(group: Group, tag: string): unknown {
    return prepare(variants[group].get(tag), `$.${group}.${tag}`);
  }

  const imports = new Map<string, Set<string>>();
  const replacements: GeneratedReplacement[] = [];
  function enforced(kind: string, prepared: unknown, loose: boolean): unknown {
    const pass = applyAsymmetries(prepared, kind, ASYMMETRIES[kind] ?? {}, loose);
    for (const r of pass.replacements) {
      replacements.push(r);
      const symbols = imports.get(r.from) ?? new Set<string>();
      symbols.add(r.symbol);
      imports.set(r.from, symbols);
    }
    return pass.schema;
  }
  const kindsWithEntries = new Set(Object.keys(ASYMMETRIES));

  const pieces: string[] = [];
  const typeOf = (schemaName: string) => schemaName.replace(/Schema$/, "");
  /** Every faithful base and writer schema with the prepared node it was emitted from, for A4; the export
   * line and the registration are one operation so no emission site can skip the oracle. */
  const faithful = new Map<string, unknown>();
  const exportFaithful = (
    name: string,
    node: unknown,
    override?: (node: unknown) => string | undefined,
  ): string => {
    faithful.set(name, node);
    return `export const ${name} = ${convert(node, name, override)};`;
  };

  // G6: the typed command is split off; its per-op args schemas reach the extension through scripts/gen-ops.ts.
  const request = prepare(
    splitFlattenedCommand(fromRust.request, "$.request").envelope,
    "$.request",
  );
  const response = prepare(fromRust.response, "$.response");
  kindsWithEntries.delete("request");
  kindsWithEntries.delete("response");

  pieces.push(
    "// The request envelope (BridgeReq) and the response envelope (BridgeResp): the faithful bases, then the",
    "// enforced validators the extension runs (the base plus the asymmetry table; strict like the host).",
    exportFaithful("BridgeReqWireSchema", request),
    "",
    exportFaithful("BridgeRespWireSchema", response),
    "",
    `export const BridgeReqSchema = ${convert(enforced("request", request, false), "BridgeReqSchema")};`,
    "",
    "export type BridgeReqEnvelope = z.infer<typeof BridgeReqSchema>;",
    "",
    `export const BridgeRespSchema = ${convert(enforced("response", response, false), "BridgeRespSchema")};`,
    "",
    "export type BridgeResp = z.infer<typeof BridgeRespSchema>;",
    "",
  );

  pieces.push(
    "// The server->extension signal frames (BridgeSignal), one strict reader per variant: the faithful base,",
    "// then the enforced validator the extension runs.",
  );
  for (const [tag, names] of Object.entries(SIGNAL_FRAMES)) {
    kindsWithEntries.delete(tag);
    const base = prepare(signals.get(tag), `$.signal.${tag}`);
    pieces.push(
      exportFaithful(names.wire, base),
      "",
      `export const ${names.enforced} = ${convert(enforced(tag, base, false), names.enforced)};`,
      "",
      `export type ${typeOf(names.enforced)} = z.infer<typeof ${names.enforced}>;`,
      "",
    );
  }

  // Item types embedded in a reader's array field, emitted as their own exports (base and enforced) so a
  // consumer can name the element type; the embedding readers reference them by name (the override
  // substitutes the identical node). An ok-split reader carries the field on one arm only, so the search
  // walks the arms.
  const EMBEDDED_ITEMS = [
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
  ] as const satisfies readonly {
    group: Group;
    tag: string;
    field: string;
    wire: string;
    enforced: string;
    doc: string;
  }[];
  const itemsOf = (schema: unknown, field: string, tag: string): unknown => {
    const nodes = isObject(schema) && Array.isArray(schema.anyOf) ? schema.anyOf : [schema];
    for (const node of nodes) {
      if (!isObject(node) || !isObject(node.properties)) continue;
      const prop = node.properties[field];
      if (isObject(prop) && prop.items !== undefined) return prop.items;
    }
    throw new Error(`gen-envelope: ${tag} no longer embeds a ${field} items schema`);
  };
  const preparedBases = new Map<string, unknown>();
  const enforcedReaders = new Map<string, unknown>();
  const namedNodes = new Map<unknown, string>();
  for (const item of EMBEDDED_ITEMS) {
    const base = preparedFrame(item.group, item.tag);
    const reader = enforced(item.tag, base, true);
    preparedBases.set(item.tag, base);
    enforcedReaders.set(item.tag, reader);
    const wireNode = itemsOf(base, item.field, item.tag);
    const enforcedNode = itemsOf(reader, item.field, item.tag);
    namedNodes.set(wireNode, item.wire);
    namedNodes.set(enforcedNode, item.enforced);
    pieces.push(
      `// ${item.doc}`,
      exportFaithful(item.wire, wireNode),
      "",
      `export const ${item.enforced} = ${convert(enforcedNode, item.enforced)};`,
      "",
      `export type ${typeOf(item.enforced)} = z.infer<typeof ${item.enforced}>;`,
      "",
    );
  }
  const byName = (node: unknown): string | undefined => namedNodes.get(node);

  pieces.push(
    "// The host->extension control frames: the faithful base, then the enforced reader (the base plus the",
    "// asymmetry table, read loose under its loose-frames rule).",
  );
  for (const group of GROUPS) {
    for (const [tag, names] of Object.entries(READER_FRAMES[group])) {
      kindsWithEntries.delete(tag);
      const base = preparedBases.get(tag) ?? preparedFrame(group, tag);
      const reader = enforcedReaders.get(tag) ?? enforced(tag, base, true);
      pieces.push(
        exportFaithful(names.wire, base, byName),
        "",
        `export const ${names.enforced} = ${convert(reader, names.enforced, byName)};`,
        "",
        `export type ${typeOf(names.enforced)} = z.infer<typeof ${names.enforced}>;`,
        "",
      );
    }
  }
  if (kindsWithEntries.size > 0) {
    throw new Error(
      `gen-envelope: the asymmetry table names frames with no generated reader: ` +
        `${[...kindsWithEntries].join(", ")} (A1)`,
    );
  }

  // A2: every generated-schema replacement against the module it names (imported from the generated tree
  // gen-ops.ts wrote just before this script runs).
  for (const replacement of replacements) {
    const module = (await import(
      join(root, "src/packages/shared/src", replacement.from)
    )) as Record<string, unknown>;
    const generated = module[replacement.symbol];
    if (!(generated instanceof z.ZodType)) {
      throw new Error(
        `gen-envelope: ${replacement.from} exports no Zod schema named ${replacement.symbol} (A2)`,
      );
    }
    assertGeneratedMatches(replacement, generated);
  }

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
    "// serde parser). Emitted for their inferred types: constructor sites claim conformance with `satisfies`,",
    "// so a drifted field or tag is a compile error. Never used as runtime parsers.",
  );
  for (const group of GROUPS) {
    for (const [tag, name] of Object.entries(WRITER_FRAMES[group])) {
      pieces.push(
        exportFaithful(name, preparedFrame(group, tag)),
        "",
        `export type ${typeOf(name)} = z.infer<typeof ${name}>;`,
        "",
      );
    }
  }

  pieces.push(
    "// Which extension->host frames have a generated writer schema above.",
    "export const GENERATED_WRITER_FRAMES = {",
    ...manifest(WRITER_FRAMES),
    "} as const;",
  );

  const importLines = [...imports.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([from, symbols]) => `import { ${[...symbols].sort().join(", ")} } from "${from}";`);

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
// \`moon run check-envelope\`). The extension->host writer schemas exist for their inferred types only
// (constructor-site \`satisfies\`); the enforcing reader for those frames is the Rust serde parser.

import { z } from "zod";
${importLines.join("\n")}

${pieces.join("\n")}
`;

  const outPath = join(root, "src/packages/shared/src/envelope.gen.ts");
  writeFileSync(outPath, out);

  // A4 reads the schemas back from the written module, so it judges the file as the extension will import it.
  const generated = (await import(outPath)) as Record<string, unknown>;
  for (const [name, node] of faithful) {
    const emitted = generated[name];
    if (!(emitted instanceof z.ZodType)) {
      throw new Error(`gen-envelope: the written module exports no Zod schema named ${name} (A4)`);
    }
    assertLibraryReadingMatches(name, node, emitted);
  }
  console.log("generated src/packages/shared/src/envelope.gen.ts from the Rust wire types");
}

if (import.meta.main) await main();
