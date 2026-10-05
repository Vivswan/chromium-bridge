#!/usr/bin/env bun

// The envelope asymmetry gate. The extension's wire validators are GENERATED (envelope.gen.ts, kept fresh by
// `moon run check-gen`): a faithful base per envelope and control frame, and beside each reader base the
// enforced validator, which is that base plus the asymmetry table (src/packages/shared/src/envelope-asymmetries.ts).
// This gate holds what generation alone cannot:
//
//   every asymmetry entry's probes          -> the enforced validator and the base disagree exactly as the entry's
//                                              direction says (a narrow entry refuses what the base admits and
//                                              admits nothing the base refuses; a widen entry admits what the base
//                                              refuses, or says its evidence is parser-level)
//   both reader rules                        -> null at every Option field refused (optional-only); an added field
//                                              admitted on every control frame and refused on the envelopes
//                                              (loose-frames)
//   the inbound classifiers (enclave.ts,     -> equal to the generated reader plan plus the pinned outbound tags
//   webauthn.ts)
//   refinements, in no derived schema        -> pinned in FRAME_REFINEMENTS by count and by probe
//   the approved asymmetries                 -> printed as a table (scope, direction, reason, proof) for the reviewer
//
// The rules are exported and unit-tested in scripts/tests/check-envelope.test.ts; the gate itself runs under
// import.meta.main via `moon run check-envelope` (part of `moon run ci`).

import { z } from "zod";
import {
  ADMIN_RESULT_FRAME_TYPES,
  ENCLAVE_FRAME_TYPES,
  POLICY_FRAME_TYPES,
  PRESENCE_FRAME_TYPES,
} from "../src/packages/shared/src/enclave";
import * as generated from "../src/packages/shared/src/envelope.gen";
import {
  ASYMMETRIES,
  type Asymmetry,
  READER_RULES,
} from "../src/packages/shared/src/envelope-asymmetries";
import { WEBAUTHN_FRAME_TYPES } from "../src/packages/shared/src/webauthn";
import { BARE_TAG_FRAMES, GROUPS, type Group, READER_FRAMES, WRITER_FRAMES } from "./gen-envelope";

type Frame = Record<string, unknown>;

// ---- the reader pairs under the gate ---------------------------------------------

/** The valid frame arms of one reader: at least one, so a reader can never prove vacuously. */
export type FrameArms = readonly [Frame, ...Frame[]];

export interface ReaderPair {
  base: z.ZodType;
  enforced: z.ZodType;
  frames: FrameArms;
  loose: boolean;
}

function exported(name: string): z.ZodType {
  const schema = (generated as Record<string, unknown>)[name];
  if (!(schema instanceof z.ZodType)) {
    throw new Error(`check-envelope: envelope.gen.ts exports no Zod schema named ${name}`);
  }
  return schema;
}

// Hand-written minimal valid frames, one list per reader: the first is the primary arm the entry probes mutate;
// the rest are the other arms an ok-split divides the frame into (policy_current ok:false), so the Option
// inventory below reaches fields the primary arm can never carry.
const FRAMES: Readonly<Record<string, FrameArms>> = {
  request: [{ id: 1, op: "tab_list", browser: "brave", args: {} }],
  response: [{ id: 1, ok: true, data: { any: "thing" }, error: "reason" }],
  enclave_proof: [{ type: "enclave_proof", sig: "s", key_id: "k", pubkey: "p" }],
  enclave_error: [{ type: "enclave_error", reason: "denied" }],
  presence_proof: [{ type: "presence_proof", sig: "s", key_id: "k", pubkey: "p" }],
  presence_error: [{ type: "presence_error", reason: "busy" }],
  client_list_result: [
    {
      type: "client_list_result",
      ok: true,
      enrolled: true,
      clients: [
        { name: "example-client", anchor: { kind: "hash", value: "abc123" }, added_unix: 1 },
      ],
      error: "e",
    },
  ],
  client_revoke_result: [{ type: "client_revoke_result", ok: true, error: "e" }],
  kill_status_result: [{ type: "kill_status_result", ok: true, killed: false, error: "e" }],
  policy_current: [
    {
      type: "policy_current",
      ok: true,
      baseline: "YmFzZQ==",
      sig: "c2ln",
      // Every overlay field, so the Option inventory finds each one carried by this arm.
      overlay: {
        cdpMode: false,
        fileUploadEnabled: false,
        handleDialogEnabled: false,
        pageEvalEnabled: false,
        confirmHighRiskClick: true,
        confirmPageEval: true,
        touchIdConfirm: true,
        confirmTabClose: true,
        warnPreciseSnapshot: true,
        evalMask: true,
        hostReverifyMs: 1000,
        confirmGraceMs: 1000,
        clickToastTimeoutMs: 1000,
        evalToastTimeoutMs: 1000,
        disabledTools: ["page_eval"],
      },
    },
    { type: "policy_current", ok: false, error: "no policy baseline" },
  ],
  lang_current: [{ type: "lang_current", value: "en", seq: 3 }],
  enroll_options: [
    {
      type: "enroll_options",
      challenge: "Y2hhbGxlbmdl",
      nonce: "nonce-0001",
      user_id: "dXNlci1pZA",
      user_name: "brave",
      exclude_credential_ids: ["Y3JlZC1h"],
    },
  ],
  enroll_result: [
    { type: "enroll_result", ok: true, credential_id: "Y3JlZC1h" },
    { type: "enroll_result", ok: false, reason: "attestation_format" },
  ],
  presence_request: [
    {
      type: "presence_request",
      challenge: "cHJlc2VuY2U",
      nonce: "nonce-0002",
      action: "pair_client:codex",
      allowed_credential_ids: ["Y3JlZC1h"],
    },
  ],
  presence_result: [
    { type: "presence_result", ok: true },
    { type: "presence_result", ok: false, reason: "sign_count_not_increased" },
  ],
};

/** Every reader the gate proves, keyed like the asymmetry table. */
export function readerPairs(): Readonly<Record<string, ReaderPair>> {
  const pairs: Record<string, ReaderPair> = {
    request: {
      base: generated.BridgeReqWireSchema,
      enforced: generated.BridgeReqSchema,
      frames: FRAMES.request as FrameArms,
      loose: false,
    },
    response: {
      base: generated.BridgeRespWireSchema,
      enforced: generated.BridgeRespSchema,
      frames: FRAMES.response as FrameArms,
      loose: false,
    },
  };
  for (const group of GROUPS) {
    for (const [tag, names] of Object.entries(READER_FRAMES[group])) {
      const frames = FRAMES[tag];
      if (frames === undefined)
        throw new Error(`check-envelope: no representative frame for ${tag}`);
      pairs[tag] = {
        base: exported(names.wire),
        enforced: exported(names.enforced),
        frames,
        loose: true,
      };
    }
  }
  return pairs;
}

// ---- the asymmetry-table rule ------------------------------------------------------

// Place `value` at a table path ("$.properties.a.items.properties.b") inside a copy of `frame`: a property
// segment selects the key, an items segment the first element, and the bare `$` is the whole frame (an
// ok-split's probes are whole frames). Returns undefined when the path does not resolve in this frame (an arm
// that lacks the field, or a whole-frame value that is not an object).
export function placeAt(frame: Frame, path: string, value: unknown): Frame | undefined {
  if (path === "$") {
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Frame)
      : undefined;
  }
  const copy = structuredClone(frame);
  const segments = path.split(".").slice(1);
  let cursor: unknown = copy;
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    if (segment === "properties") {
      const key = segments[++i] as string;
      if (typeof cursor !== "object" || cursor === null || Array.isArray(cursor)) return undefined;
      if (i === segments.length - 1) {
        (cursor as Frame)[key] = value;
        return copy;
      }
      cursor = (cursor as Frame)[key];
    } else if (segment === "items") {
      if (!Array.isArray(cursor) || cursor.length === 0) return undefined;
      if (i === segments.length - 1) {
        cursor[0] = value;
        return copy;
      }
      cursor = cursor[0];
    } else {
      throw new Error(`check-envelope: unsupported path segment ${segment} in ${path}`);
    }
  }
  throw new Error(`check-envelope: ${path} names the whole frame`);
}

const admits = (schema: z.ZodType, frame: unknown) => schema.safeParse(frame).success;

// The value currently at a table path in a frame (the same walk as placeAt), for probes that extend it.
function valueAt(frame: Frame, path: string): unknown {
  let cursor: unknown = frame;
  const segments = path.split(".").slice(1);
  for (let i = 0; i < segments.length; i++) {
    if (segments[i] === "properties") {
      cursor =
        typeof cursor === "object" && cursor !== null
          ? (cursor as Frame)[segments[++i] as string]
          : undefined;
    } else if (segments[i] === "items") {
      cursor = Array.isArray(cursor) ? cursor[0] : undefined;
    }
  }
  return cursor;
}

/** The asymmetry-table rule for one entry (see the module doc), against the first arm where the path
 * resolves. Pure over its inputs so the test file can prove the refusals fire; returns the failures, empty
 * meaning the entry is proved. */
export function asymmetryProblems(
  scope: string,
  entry: Asymmetry,
  pair: ReaderPair,
  path: string,
): string[] {
  const problems: string[] = [];
  // The arm must CARRY the field, not merely admit its insertion: on an arm that cannot carry it, the ok-split
  // would refuse the inserted field and stand in for the constraint under proof.
  const frame = pair.frames.find((candidate) => valueAt(candidate, path) !== undefined);
  if (frame === undefined) return [`${scope}: no representative frame carries the path`];
  const at = (value: unknown) => placeAt(frame, path, value) as Frame;
  if (!admits(pair.base, frame) || !admits(pair.enforced, frame)) {
    return [`${scope}: the representative frame is not admitted by both validators`];
  }
  for (const value of entry.probes.refuses ?? []) {
    if (admits(pair.enforced, at(value))) {
      problems.push(
        `${scope}: the enforced validator admits ${JSON.stringify(value)}, declared refused`,
      );
    }
    if (entry.direction === "narrow" && !admits(pair.base, at(value))) {
      problems.push(
        `${scope}: the base refuses ${JSON.stringify(value)} too, so the probe proves nothing about this layer`,
      );
    }
  }
  let baseRefusesAnAccepted = false;
  for (const value of entry.probes.accepts ?? []) {
    if (!admits(pair.enforced, at(value))) {
      problems.push(
        `${scope}: the enforced validator refuses ${JSON.stringify(value)}, declared accepted`,
      );
    }
    if (!admits(pair.base, at(value))) {
      baseRefusesAnAccepted = true;
      if (entry.direction === "narrow") {
        problems.push(
          `${scope}: declared narrow, but the base refuses ${JSON.stringify(value)} and the enforced ` +
            "validator admits it: a widening",
        );
      }
    }
  }
  if (entry.direction === "widen") {
    if ((entry.probes.accepts ?? []).length === 0) {
      problems.push(`${scope}: declared widen with no accepts probe`);
    } else if (!baseRefusesAnAccepted && entry.evidence !== "parser") {
      problems.push(
        `${scope}: declared widen, but the base admits every accepts probe; name a value it refuses or ` +
          'declare evidence: "parser"',
      );
    }
  } else if ((entry.probes.refuses ?? []).length === 0) {
    problems.push(`${scope}: declared narrow with no refuses probe`);
  }
  // A generated-schema replacement sits outside the loose-frames rule: where the Rust node refuses an unknown
  // field (the base refuses it), the replacement must too, or an overlay claim nobody owns would ride the frame.
  if (entry.changes.some((change) => change.change === "generated-schema")) {
    const current = valueAt(frame, path);
    if (typeof current === "object" && current !== null && !Array.isArray(current)) {
      const grown = at({ ...(current as Frame), hostAdded: "field" });
      if (!admits(pair.base, grown) && admits(pair.enforced, grown)) {
        problems.push(
          `${scope}: the generated replacement admits an unknown field the base refuses`,
        );
      }
    }
  }
  return problems;
}

// Every Option path of a base validator, from its derived JSON Schema: a property whose type list or union
// carries null. Recurses through properties, array items, and union branches.
export function optionPaths(schema: unknown, path = "$"): string[] {
  if (typeof schema !== "object" || schema === null) return [];
  const node = schema as Record<string, unknown>;
  const found: string[] = [];
  const nullable = (sub: unknown): boolean => {
    if (typeof sub !== "object" || sub === null) return false;
    const n = sub as Record<string, unknown>;
    if (Array.isArray(n.type) && n.type.includes("null")) return true;
    return (
      Array.isArray(n.anyOf) &&
      n.anyOf.some(
        (b) =>
          typeof b === "object" && b !== null && (b as Record<string, unknown>).type === "null",
      )
    );
  };
  if (typeof node.properties === "object" && node.properties !== null) {
    // A required nullable property is a value, not an Option (the generator keeps its null arm too); its
    // children are still walked.
    const required = new Set(Array.isArray(node.required) ? node.required : []);
    for (const [key, sub] of Object.entries(node.properties as Record<string, unknown>)) {
      const subPath = `${path}.properties.${key}`;
      if (!required.has(key) && nullable(sub)) found.push(subPath);
      found.push(...optionPaths(sub, subPath));
    }
  }
  if (node.items !== undefined) found.push(...optionPaths(node.items, `${path}.items`));
  if (Array.isArray(node.anyOf))
    for (const branch of node.anyOf) found.push(...optionPaths(branch, path));
  return found;
}

/** The two reader rules the generator applies everywhere, proved per frame. */
export function readerRuleProblems(kind: string, pair: ReaderPair): string[] {
  const problems: string[] = [];
  // optional-only: at every Option path of the base (its derived schema is the inventory), in every arm that
  // carries the field and whose base admits null there, the enforced validator refuses null. An Option path no
  // arm carries is a gap in the frames, named rather than skipped.
  for (const path of new Set(optionPaths(z.toJSONSchema(pair.base)))) {
    let covered = false;
    for (const frame of pair.frames) {
      if (valueAt(frame, path) === undefined) continue; // this arm does not carry the field
      const withNull = placeAt(frame, path, null);
      if (withNull === undefined || !admits(pair.base, withNull)) continue;
      covered = true;
      if (admits(pair.enforced, withNull)) {
        problems.push(`${kind}: optional-only: the enforced validator admits null at ${path}`);
      }
    }
    if (!covered) problems.push(`${kind}: optional-only: no representative frame carries ${path}`);
  }
  // loose-frames: an added field is admitted on a control frame and refused on an envelope; the base always
  // refuses it (deny_unknown_fields), and loose never means lax (the validated fields still gate).
  for (const frame of pair.frames) {
    const grown = { ...frame, hostAdded: "field" };
    if (admits(pair.base, grown)) problems.push(`${kind}: the base admits an unknown field`);
    if (admits(pair.enforced, grown) !== pair.loose) {
      problems.push(
        `${kind}: loose-frames: the enforced validator ${pair.loose ? "refuses" : "admits"} an unknown field`,
      );
    }
    if (pair.loose && admits(pair.enforced, { ...grown, type: "evil" })) {
      problems.push(`${kind}: loose-frames: a retagged frame is admitted`);
    }
  }
  return problems;
}

// ---- the classifier-coverage rule -----------------------------------------------------

// The runtime classifiers the extension routes inbound frames on, held per group to the generated reader plan
// (readers plus bare tags) plus the pinned CLASSIFIED_OUTBOUND_TAGS below: a classified tag with no reader would
// route frames nothing checks, and a tag dropped from a classification array would silently stop routing.
// kill_status_result has no classification array: isKillStatusFrame (enclave.ts) classifies by full parse.
export const CLASSIFIED_TAGS: Record<Group, ReadonlySet<string>> = {
  enclave: new Set([...ENCLAVE_FRAME_TYPES, ...PRESENCE_FRAME_TYPES]),
  admin: new Set([...ADMIN_RESULT_FRAME_TYPES, "kill_status_result"]),
  policy: new Set(POLICY_FRAME_TYPES),
  webauthn: new Set(WEBAUTHN_FRAME_TYPES),
};

// Ceremony tags classified WITHOUT a reader, deliberately: these are extension->host (writer) frames, and
// classifying the inbound direction too makes the extension handle a copy arriving inbound as ceremony traffic
// - dropped/refused by the handler - instead of dispatching it (see ENCLAVE_FRAME_TYPES in enclave.ts). Not a
// missing validator, so do not "fix" the exception away; each entry is cross-checked below to stay classified
// and stay a writer.
const CLASSIFIED_OUTBOUND_TAGS: Record<Group, ReadonlySet<string>> = {
  enclave: new Set(["enclave_challenge", "enclave_revoke"]),
  admin: new Set(),
  policy: new Set(),
  webauthn: new Set(),
};

/** The classifier-coverage rule: pure over its inputs so the test file can prove the refusals fire; the running
 * gate passes the real classified sets. Returns the failures, empty meaning covered. */
export function classifierCoverageProblems(
  group: Group,
  classified: ReadonlySet<string>,
): string[] {
  const problems: string[] = [];
  const inbound = new Set([...Object.keys(READER_FRAMES[group]), ...BARE_TAG_FRAMES[group]]);
  const writers = new Set(Object.keys(WRITER_FRAMES[group]));
  for (const tag of classified) {
    if (!inbound.has(tag) && !writers.has(tag)) {
      problems.push(`classifier: ${tag} is not a planned frame of the Rust ${group} enum`);
    }
    if (!inbound.has(tag) && !CLASSIFIED_OUTBOUND_TAGS[group].has(tag)) {
      problems.push(
        `classifier: ${group} tag ${tag} is classified inbound but no reader or bare tag covers it - a ` +
          "frame wearing it would route unvalidated",
      );
    }
  }
  for (const tag of CLASSIFIED_OUTBOUND_TAGS[group]) {
    if (!classified.has(tag)) {
      problems.push(
        `classifier: pinned outbound tag ${tag} is no longer classified by the ${group} arrays`,
      );
    }
    if (!writers.has(tag)) {
      problems.push(
        `classifier: pinned outbound tag ${tag} is not a ${group} writer - an inbound frame needs a reader, ` +
          "not an exception pin",
      );
    }
  }
  for (const tag of inbound) {
    if (!classified.has(tag)) {
      problems.push(`${group}: inbound frame ${tag} is gated but no runtime classifier routes it`);
    }
  }
  return problems;
}

// ---- pinned refinements (in no derived schema) --------------------------------------------
//
// A refinement (.superRefine / .refine) never appears in a derived JSON Schema, so neither the generator nor
// the probes above can see one appear or vanish; every deliberate refinement on an enforced validator is pinned
// HERE instead: the custom-check count must equal the pin count, and each pin's probe frames must behave.

export type RefinementPin = {
  /** Which deliberate asymmetry this is, for the failure message; the full why lives on the schema. */
  name: string;
  /** Frames the generated shape accepts that the refinement must refuse. */
  refuses: readonly unknown[];
  /** Legitimate frames the refinement must keep accepting. */
  accepts: readonly unknown[];
};

export const FRAME_REFINEMENTS: Readonly<Partial<Record<string, readonly RefinementPin[]>>> = {
  // No enforced reader carries a hand-written refinement (the ok-splits are `ok-split` entries of the
  // asymmetry table, emitted by the generator); every reader is held to zero refinements until one is pinned
  // here.
};

/** Count the custom checks (refinements) in a Zod schema, recursively, so a .refine buried on a nested property
 * counts too. Built-in checks (min_length, bounds, formats) surface in a derived JSON Schema and are the
 * generator's business, so they are not counted.
 *
 * Zod has no public check-kind accessor: .refine() attaches a ZodCustom, .superRefine() a bare $ZodCheck, and only
 * `_zod.def.check === "custom"` (the route Zod documents for library authors) names both. refinementCounterProblems
 * owns what a dead read would cost and proves the counter live at module load. */
function countCustomChecks(schema: z.core.$ZodType): number {
  let count = 0;
  const seen = new Set<object>();
  const visit = (node: unknown): void => {
    if (typeof node !== "object" || node === null || seen.has(node)) return;
    seen.add(node);
    if (node instanceof z.core.$ZodType) {
      for (const check of node._zod.def.checks ?? []) {
        if (check._zod.def.check === "custom") count += 1;
      }
      visit(node._zod.def);
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    for (const value of Object.values(node)) visit(value);
  };
  visit(schema);
  return count;
}

/** Known schemas with a known refinement count, held against a counter: the failure a dead counter would otherwise
 * produce is an unpinned frame growing a refinement unnoticed, its count of 0 matching its empty pin list. Run at
 * module load against countCustomChecks; exported so scripts/tests/check-envelope.test.ts can prove the refusal on a dead
 * counter. */
export function refinementCounterProblems(count: (schema: z.ZodType) => number): string[] {
  const probes: readonly [string, z.ZodType, number][] = [
    ["one .superRefine on the frame", z.looseObject({ ok: z.boolean() }).superRefine(() => {}), 1],
    [
      "one .refine nested under an array item",
      z.looseObject({
        clients: z.array(z.looseObject({ name: z.string().refine((n) => n !== "x") })),
      }),
      1,
    ],
    ["built-in checks only", z.looseObject({ name: z.string().min(1).max(8) }), 0],
  ];
  return probes.flatMap(([name, schema, expected]) => {
    const got = count(schema);
    return got === expected
      ? []
      : [
          `refinement counter: ${name} counts ${got}, expected ${expected} - Zod's check internals moved; ` +
            "fix countCustomChecks before trusting any refinement pin",
        ];
  });
}

const counterProblems = refinementCounterProblems(countCustomChecks);
if (counterProblems.length > 0) throw new Error(counterProblems.join("\n"));

/** The refinement-pin rule (see FRAME_REFINEMENTS): pure over its inputs so scripts/tests/check-envelope.test.ts can prove
 * the refusals fire; the running gate passes each enforced reader with its pins (an unpinned reader gets the empty
 * list, holding it to zero refinements). Returns the failures, empty meaning the schema carries exactly the pinned
 * number of custom refinements and each probe behaves. */
export function refinementProblems(
  tag: string,
  schema: z.ZodType,
  pins: readonly RefinementPin[],
): string[] {
  const problems: string[] = [];
  const checks = countCustomChecks(schema);
  if (checks !== pins.length) {
    problems.push(
      `${tag}: the enforced validator carries ${checks} custom refinement(s) but FRAME_REFINEMENTS pins ` +
        `${pins.length} - refinements are invisible to the generator and the probes, so every one must be ` +
        "pinned there (and no pin may outlive its refinement)",
    );
  }
  for (const pin of pins) {
    for (const frame of pin.refuses) {
      if (schema.safeParse(frame).success) {
        problems.push(
          `${tag}: pinned refinement ${pin.name} no longer refuses ${JSON.stringify(frame)}`,
        );
      }
    }
    for (const frame of pin.accepts) {
      if (!schema.safeParse(frame).success) {
        problems.push(
          `${tag}: pinned refinement ${pin.name} refuses the legitimate ${JSON.stringify(frame)}`,
        );
      }
    }
  }
  return problems;
}

// ---- main ------------------------------------------------------------------------------------

function main(): void {
  let failed = false;
  function fail(message: string): void {
    console.error(message);
    failed = true;
  }

  const pairs = readerPairs();

  // The asymmetry table, entry by entry, then the two reader rules per frame.
  const rows: { scope: string; direction: string; reason: string; proof: string }[] = [];
  for (const rule of READER_RULES) {
    rows.push({
      scope: `every reader (${rule.rule})`,
      direction: rule.direction,
      reason: rule.reason,
      proof: "",
    });
  }
  for (const [kind, entries] of Object.entries(ASYMMETRIES)) {
    const pair = pairs[kind];
    if (pair === undefined) {
      fail(`${kind}: the asymmetry table names a frame with no generated reader`);
      continue;
    }
    for (const [path, entry] of Object.entries(entries)) {
      const scope = `${kind} ${path}`;
      const problems = asymmetryProblems(scope, entry, pair, path);
      for (const problem of problems) fail(problem);
      const proof =
        problems.length > 0
          ? "FAILED"
          : entry.evidence === "parser"
            ? "proved (parser-level)"
            : "proved";
      rows.push({ scope, direction: entry.direction, reason: entry.reason, proof });
    }
  }
  for (const [kind, pair] of Object.entries(pairs)) {
    for (const problem of readerRuleProblems(kind, pair)) fail(problem);
  }

  for (const group of GROUPS) {
    for (const problem of classifierCoverageProblems(group, CLASSIFIED_TAGS[group])) fail(problem);
  }

  // Pinned refinements: every enforced reader is held to its pinned refinement count and probe behavior - the
  // unpinned ones to zero.
  for (const [kind, pair] of Object.entries(pairs)) {
    const pins = FRAME_REFINEMENTS[kind] ?? [];
    const problems = refinementProblems(kind, pair.enforced, pins);
    for (const problem of problems) fail(problem);
    if (pins.length > 0 && problems.length === 0) {
      console.log(`${kind}: pinned refinement(s) present and behaving`);
    }
  }
  for (const tag of Object.keys(FRAME_REFINEMENTS)) {
    if (!(tag in pairs)) fail(`FRAME_REFINEMENTS pins ${tag} but no generated reader carries it`);
  }

  // The approved asymmetries, for the reviewer of a PR touching the table: every row is a place the extension's
  // parser deliberately differs from the host's, and a widen is where it accepts a frame the host refuses.
  const scopeWidth = Math.max(...rows.map((row) => row.scope.length));
  console.log(
    "\nPinned parser asymmetries (narrow: the extension refuses earlier; widen: it accepts more than the host)",
  );
  for (const row of rows) {
    const proof = row.proof === "" ? "" : `  [${row.proof}]`;
    console.log(
      `  ${row.scope.padEnd(scopeWidth)}  ${row.direction.padEnd(6)}  ${row.reason}${proof}`,
    );
  }

  if (failed) process.exit(1);
}

if (import.meta.main) main();
