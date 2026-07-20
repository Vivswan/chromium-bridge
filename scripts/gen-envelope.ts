#!/usr/bin/env bun

// Generate the extension's base wire validators from the Rust core's
// schemars-derived JSON Schemas (ADR-0028): the BridgeReq/BridgeResp envelope
// pair and every host->extension control frame the extension validates.
// Runs the core's `emit_envelope_schema` example (schemars behind the
// gen-only `envelope-schema` cargo feature, absent from every binary),
// reduces each schema to the supported subset below (prepare), emits Zod
// source for it with the in-repo emitter (emitZod - the schema subset the
// G-rules admit is small enough that every form maps to exactly one Zod
// expression, in the style of gen-ops.ts; it replaced the archived
// json-schema-to-zod dependency), and writes
// src/packages/shared/src/envelope-wire.gen.ts.
// Run via `moon run gen`; CI regenerates and fails on a stale diff (check-gen).
//
// The emitted schemas are the FAITHFUL Rust contract: strict objects
// (serde's deny_unknown_fields -> Zod's .strict()), required fields
// required, no defaults. The deliberate parser asymmetries the extension
// layers on top stay hand-written in envelope.ts / enclave.ts, each pinned
// by scripts/check-envelope-parity.ts (`moon run check-envelope`) and exercised
// in tests/envelope-wire.gen.test.ts.
//
// Fail-closed generation rules (a violation aborts generation; shipping a
// weaker parser than the Rust contract is never an option). These assert the
// CONTRACT the emitted validators must uphold, independent of how the
// emission is implemented:
//   G1 every object schema must declare type: "object" and carry
//      additionalProperties: false, and the emitted source must call
//      .strict() once per z.object( - so neither a Rust type losing
//      deny_unknown_fields nor an emitter bug dropping strictness can slip
//      through. Object-shaped keywords (properties/required/
//      additionalProperties) on a node without the explicit object type
//      abort: the object claim must be stated, never inferred.
//   G2 `default` keywords are stripped before emission: serde fills
//      defaults on the Rust READ side; a Zod validator that invented fields
//      (.default(...)) would silently hand consumers values the frame never
//      carried. Stripping never changes required-ness - schemars already
//      leaves defaulted fields out of `required`.
//   G3 a oneOf is emitted only when it is a discriminated union (every
//      branch an object schema with the same required const-tag property,
//      all tag values distinct - so the branches are mutually exclusive and
//      oneOf equals anyOf over the same instance set). It is rewritten to
//      anyOf and emitted as a plain z.union; the mutual exclusivity that
//      distinguishes oneOf needs no extra runtime check. Anything else
//      aborts.
//   G4 $refs must all be inlined before emission (the emitter does not
//      resolve them); a surviving $ref aborts.
//   G5 every keyword and type must be on the explicit supported list below,
//      in a position the emitter models. A keyword it does not model
//      (minProperties, contains, patternProperties, a format or bound on a
//      non-numeric node, ...) would have to be silently dropped - weaker
//      validation than the contract claims - so its appearance aborts until
//      support is added here AND in the adversarial tests. Same philosophy
//      as gen-ops.ts's assertSupportedProp. The empty schema {} (accept
//      anything) is allowed: it is the contract's own free-form claim
//      (BridgeReq.args, BridgeResp.data), faithfully emitted as z.any() and
//      still held to the R3 rule by the parity gate.

import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { splitTaggedUnionSchema } from "../src/packages/shared/src/json-schema-normalize";

type JsonObject = Record<string, unknown>;

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Annotation keys that constrain nothing (same list as the R1 rule in
// src/packages/shared/src/json-schema-normalize.ts); stripped so the
// generated source stays readable and free of Rust doc comments.
const ANNOTATION_KEYS = new Set(["$schema", "$id", "$comment", "title", "description", "examples"]);

// G3: accept the branch list only if some property is a required string
// const in every branch with all values distinct; the union is then
// discriminated and oneOf/anyOf coincide.
export function assertDiscriminatedUnion(branches: unknown[], path: string): void {
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
    return; // `candidate` discriminates every branch
  }
  throw new Error(`gen-envelope: oneOf at ${path} is not a discriminated union (G3)`);
}

// Reduce one schema to the form the emitter consumes: annotations and
// `default` stripped, every keyword and type checked against the supported
// list (G5), object strictness asserted (G1), discriminated oneOf -> anyOf
// (G3), no $refs (G4). Structure is otherwise preserved verbatim. This is a
// schema-aware walker: it recurses only through positions that hold
// subschemas (properties values, items, union branches), so a FIELD merely
// named like an annotation ("description", "default") is never stripped.
const SUPPORTED_KEYWORDS = new Set([
  "type",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "oneOf",
  "anyOf",
  "const",
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
  // The boolean schema `true` and the empty schema {} both mean "accept
  // anything"; canonicalize to {} (emitted as z.any()). `false` (accept
  // nothing) and any other non-object form have no faithful emission.
  if (node === true) return {};
  if (!isObject(node)) {
    throw new Error(`gen-envelope: unsupported schema form at ${path}: ${JSON.stringify(node)}`);
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
      throw new Error(`gen-envelope: unsupported type ${JSON.stringify(t)} at ${path} (G5)`);
    }
  }

  // G5 placement: format is modeled only as schemars' integer-width claim
  // and the numeric bounds only as z.number() bounds, so both may sit only
  // on a numeric node (JSON Schema scopes them per instance type: the
  // Option null-arm beside a numeric type is inert and stays allowed, but a
  // string arm would give `format` a string-format meaning - uuid, email,
  // ... - that this emitter does not model).
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

  // G1: object-shaped keywords demand the explicit, sole object type and
  // deny_unknown_fields; an object claim is stated, never inferred.
  const objectish = ["properties", "required", "additionalProperties"].filter((k) => k in out);
  if (objectish.length > 0 || types.includes("object")) {
    if (types.length !== 1 || types[0] !== "object") {
      throw new Error(
        `gen-envelope: ${path} carries ${objectish.join("/")} but type is ` +
          `${JSON.stringify(out.type)}, not "object" (G1)`,
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
    if (types.length !== 1 || types[0] !== "array") {
      throw new Error(`gen-envelope: ${path} carries items but type is not "array" (G5)`);
    }
    if (!isObject(out.items)) {
      // Refuse missing/boolean/tuple items: z.array(z.any()) would accept
      // elements the Rust parser refuses.
      throw new Error(`gen-envelope: array at ${path} lacks a single object items schema (G5)`);
    }
    out.items = prepare(out.items, `${path}.items`);
  }

  // Unions: a combinator node must be EXACTLY one non-empty combinator -
  // sibling constraints beside a combinator have no single faithful Zod
  // form, and an empty union claims nothing, both weaker than the contract.
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

  // G5 placement: const is modeled only as a string literal, alone or on a
  // plain string node (the enum tags schemars emits); on any other type it
  // would be ignored rather than enforced.
  if ("const" in out) {
    if (typeof out.const !== "string") {
      throw new Error(`gen-envelope: unsupported non-string const at ${path} (G5)`);
    }
    if (types.length > 0 && (types.length !== 1 || types[0] !== "string")) {
      throw new Error(`gen-envelope: const on a non-string node at ${path} (G5)`);
    }
  }

  return out;
}

// Emit Zod source for one prepared node. Total over the subset prepare
// admits: every branch below is a shape prepare guarantees, and anything
// else is a bug in prepare, so it throws rather than guesses. `override`
// lets a caller substitute a named schema for a specific node (matched by
// identity) instead of inlining it.
function emitZod(node: unknown, override?: (node: unknown) => string | undefined): string {
  const custom = override?.(node);
  if (custom !== undefined) return custom;
  if (!isObject(node)) {
    throw new Error(`gen-envelope: emitter reached an unprepared node: ${JSON.stringify(node)}`);
  }
  if (Array.isArray(node.anyOf)) {
    // prepare guarantees a non-empty, pure combinator; a one-branch union
    // is the branch itself.
    if (node.anyOf.length === 1) return emitZod(node.anyOf[0], override);
    const branches = node.anyOf.map((branch) => emitZod(branch, override));
    return `z.union([${branches.join(", ")}])`;
  }
  if ("const" in node) return `z.literal(${JSON.stringify(node.const)})`;
  if (Array.isArray(node.type)) {
    // serde's Option null-arm and friends: one branch per type, each keeping
    // the node's other keywords (only numeric ones exist, per G5 placement).
    const branches = node.type.map((type) => emitZod({ ...node, type }, override));
    return `z.union([${branches.join(", ")}])`;
  }
  switch (node.type) {
    case "object": {
      // additionalProperties: false is guaranteed by G1; .strict() is its
      // one faithful spelling. prepare always materializes `properties`.
      const required = new Set(Array.isArray(node.required) ? node.required : []);
      const fields = Object.entries(node.properties as JsonObject).map(([key, sub]) => {
        const value = emitZod(sub, override);
        return `${JSON.stringify(key)}: ${required.has(key) ? value : `${value}.optional()`}`;
      });
      const object = fields.length === 0 ? "z.object({})" : `z.object({ ${fields.join(", ")} })`;
      return `${object}.strict()`;
    }
    case "array":
      return `z.array(${emitZod(node.items, override)})`;
    case "integer":
    case "number": {
      // schemars' integer-width formats: `integer` is already .int(); the
      // int64 format on a plain number carries the same integer claim.
      // Other formats (uint64, double, ...) add nothing beyond the type and
      // the explicit bounds.
      let out =
        node.type === "integer" || node.format === "int64" ? "z.number().int()" : "z.number()";
      if (typeof node.minimum === "number") out += `.gte(${JSON.stringify(node.minimum)})`;
      if (typeof node.maximum === "number") out += `.lte(${JSON.stringify(node.maximum)})`;
      return out;
    }
    case "string":
      return "z.string()";
    case "boolean":
      return "z.boolean()";
    case "null":
      return "z.null()";
    case undefined: {
      // The only typeless survivor of prepare is the empty any-schema.
      if (Object.keys(node).length > 0) {
        throw new Error(
          `gen-envelope: emitter reached an unprepared node: ${JSON.stringify(node)}`,
        );
      }
      return "z.any()";
    }
    default:
      throw new Error(`gen-envelope: emitter has no form for type ${JSON.stringify(node.type)}`);
  }
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// Emit one prepared schema as Zod source, then re-assert G1 on the OUTPUT:
// every emitted z.object( must be closed by a .strict().
export function convert(
  schema: unknown,
  name: string,
  parserOverride?: (node: unknown) => string | undefined,
): string {
  const code = emitZod(schema, parserOverride);
  const objects = count(code, "z.object(");
  const stricts = count(code, ".strict()");
  if (objects !== stricts) {
    throw new Error(
      `gen-envelope: ${name}: emitted ${objects} z.object( but ${stricts} .strict() (G1)`,
    );
  }
  return code;
}

// The host->extension frames the extension validates, and the export name of
// each generated base schema. Extension->host frames have no extension-side
// reader (the Rust serde parser is the enforcing reader), and
// enclave_revoked is a bare classification tag with no per-frame validator;
// both stay covered by scripts/check-envelope-parity.ts, which also
// cross-checks this map against its FRAME_PLANS via GENERATED_WIRE_FRAMES.
const GENERATED_FRAMES: Record<"enclave" | "admin", Readonly<Record<string, string>>> = {
  enclave: {
    enclave_proof: "EnclaveProofWireSchema",
    enclave_error: "EnclaveErrorWireSchema",
    presence_proof: "PresenceProofWireSchema",
    presence_error: "PresenceErrorWireSchema",
  },
  admin: {
    client_list_result: "ClientListResultWireSchema",
    client_revoke_result: "ClientRevokeResultWireSchema",
    kill_status_result: "KillStatusResultWireSchema",
  },
};

function main(): void {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");

  // The Rust core is the source: run its envelope-schema emitter (same
  // invocation as scripts/check-envelope-parity.ts).
  const emitted = Bun.spawnSync(
    [
      "cargo",
      "run",
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
    enclave: unknown;
    admin: unknown;
  };

  const variants = {
    enclave: splitTaggedUnionSchema(fromRust.enclave),
    admin: splitTaggedUnionSchema(fromRust.admin),
  };

  function preparedFrame(group: "enclave" | "admin", tag: string): unknown {
    const variant = variants[group].get(tag);
    if (variant === undefined) {
      throw new Error(`gen-envelope: the Rust ${group} enum has no ${tag} frame`);
    }
    return prepare(variant, `$.${group}.${tag}`);
  }

  const pieces: string[] = [];

  pieces.push(
    "// The request envelope (BridgeReq) and the response envelope (BridgeResp).",
    `export const BridgeReqWireSchema = ${convert(prepare(fromRust.request, "$.request"), "BridgeReqWireSchema")};`,
    "",
    `export const BridgeRespWireSchema = ${convert(prepare(fromRust.response, "$.response"), "BridgeRespWireSchema")};`,
    "",
  );

  // One trusted-client entry (allowlist::ClientEntry), extracted from
  // client_list_result's `clients` items and emitted as its own export so the
  // asymmetry layer can extend it; the embedding schema below references it by
  // name (the parserOverride substitutes the identical node).
  const clientListResult = preparedFrame("admin", "client_list_result");
  const clientEntry = (() => {
    if (isObject(clientListResult) && isObject(clientListResult.properties)) {
      const clients = clientListResult.properties.clients;
      if (isObject(clients) && clients.items !== undefined) return clients.items;
    }
    throw new Error("gen-envelope: client_list_result no longer embeds a clients items schema");
  })();

  pieces.push(
    "// One trusted-client entry (allowlist::ClientEntry), embedded in",
    "// client_list_result's `clients` array.",
    `export const ClientEntryWireSchema = ${convert(clientEntry, "ClientEntryWireSchema")};`,
    "",
  );

  pieces.push("// The host->extension control frames (ADR-0021/0025/0030/0031).");
  for (const group of ["enclave", "admin"] as const) {
    for (const [tag, name] of Object.entries(GENERATED_FRAMES[group])) {
      const schema = tag === "client_list_result" ? clientListResult : preparedFrame(group, tag);
      const code = convert(schema, name, (node) =>
        node === clientEntry ? "ClientEntryWireSchema" : undefined,
      );
      pieces.push(`export const ${name} = ${code};`, "");
    }
  }

  const manifest = (group: "enclave" | "admin") =>
    Object.keys(GENERATED_FRAMES[group])
      .map((tag) => JSON.stringify(tag))
      .join(", ");

  pieces.push(
    "// Which control-frame tags have a generated base schema above.",
    "// scripts/check-envelope-parity.ts cross-checks this against its per-frame",
    "// coverage plan, so a frame cannot silently drop out of generation.",
    "export const GENERATED_WIRE_FRAMES = {",
    `  enclave: [${manifest("enclave")}],`,
    `  admin: [${manifest("admin")}],`,
    "} as const;",
  );

  const out = `// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs;
// AdminControl embeds allowlist::ClientEntry) by scripts/gen-envelope.ts -
// DO NOT EDIT. Edit the Rust types, then run \`moon run gen\`.
//
// The FAITHFUL base wire schemas: strict objects (deny_unknown_fields ->
// .strict()), required fields required, no defaults (see the fail-closed
// generation rules G1-G5 in scripts/gen-envelope.ts). The extension never
// consumes these directly: envelope.ts and enclave.ts layer the deliberate
// parser asymmetries on top - each pinned by scripts/check-envelope-parity.ts
// (\`moon run check-envelope\`) and exercised in tests/envelope-wire.gen.test.ts.

import { z } from "zod";

${pieces.join("\n")}
`;

  writeFileSync(join(root, "src/packages/shared/src/envelope-wire.gen.ts"), out);
  console.log("generated src/packages/shared/src/envelope-wire.gen.ts from the Rust wire types");
}

if (import.meta.main) main();
