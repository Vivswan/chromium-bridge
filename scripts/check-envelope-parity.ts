#!/usr/bin/env bun

// The envelope asymmetry gate (ADR-0028). The Rust wire types in
// src/packages/core/src/protocol.rs are the canonical contract: the
// BridgeReq/BridgeResp envelope pair, and the host-handled control frames
// (EnclaveControl, AdminControl, and PolicyControl - AdminControl embedding
// allowlist::ClientEntry, PolicyControl embedding policy::PolicyOverlay).
// The validators the extension enforces are built
// in two layers: a GENERATED base (scripts/gen-envelope.ts ->
// src/packages/shared/src/envelope-wire.gen.ts, faithful to the Rust
// schemas; freshness is `moon run check-gen`'s job) wrapped by a hand-written
// asymmetry layer (envelope.ts / enclave.ts) that deliberately diverges from
// the contract in a short, documented list of places.
//
// This gate pins that hand-written layer. It derives one schema from each
// side - schemars on the Rust side (behind the gen-only `envelope-schema`
// cargo feature, absent from every binary), z.toJSONSchema on the WRAPPED
// exported validators - normalizes both through the documented rules in
// src/packages/shared/src/json-schema-normalize.ts (each asymmetry is erased
// only when it exactly matches its approved form there), and fails on any
// remaining difference. With the base generated, a surviving diff means the
// wrapper drifted outside the approved asymmetry list; the diff is NOT
// tautological because the wrapper is hand-written. Refinements
// (.superRefine) never appear in either derivation, so those asymmetries are
// pinned separately in FRAME_REFINEMENTS below and checked behaviorally. The
// same asymmetries are exercised behaviorally in
// src/packages/shared/tests/envelope-wire.gen.test.ts.
//
// The gate also checks coverage: every control frame must have a plan
// (FRAME_PLANS below), the plans with a Zod reader must exactly match the
// set of generated base schemas (GENERATED_WIRE_FRAMES), and the classified
// inbound tag sets must EQUAL the gated inbound plans (modulo the pinned
// CLASSIFIED_OUTBOUND_TAGS exceptions). That last rule is pure table logic,
// so it is exported (classifierCoverageProblems) and unit-tested in
// scripts/check-envelope-parity.test.ts; the gate itself only runs under
// import.meta.main. Run via `moon run check-envelope` (part of
// `moon run ci`).

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  ADMIN_RESULT_FRAME_TYPES,
  ClientListResultSchema,
  ClientRevokeResultSchema,
  ENCLAVE_FRAME_TYPES,
  EnclaveErrorFrameSchema,
  EnclaveProofFrameSchema,
  KillStatusResultSchema,
  LangCurrentFrameSchema,
  POLICY_FRAME_TYPES,
  PolicyCurrentFrameSchema,
  PRESENCE_FRAME_TYPES,
  PresenceErrorFrameSchema,
  PresenceProofFrameSchema,
} from "../src/packages/shared/src/enclave";
import { BridgeReqSchema, BridgeRespSchema } from "../src/packages/shared/src/envelope";
import {
  GENERATED_WIRE_FRAMES,
  GENERATED_WRITER_FRAMES,
} from "../src/packages/shared/src/envelope-wire.gen";
import {
  type ControlFrameKind,
  diffSchemas,
  normalizeEnvelopeSchema,
  splitTaggedUnionSchema,
} from "../src/packages/shared/src/json-schema-normalize";

// How each control-frame tag is covered, one entry per Rust enum variant:
//
//   { zod }       a host->extension frame the extension validates: a
//                 generated base schema (envelope-wire.gen.ts) wrapped by
//                 the asymmetry layer in shared/enclave.ts (the extension's
//                 contract surface for it); its two derivations are diffed
//                 exactly like the envelopes.
//   "bare-tag"    a host->extension frame that must stay fieldless: the
//                 `type` classification IS its whole shape, so there is no
//                 per-frame Zod validator. Pinned to the bare tag - a field
//                 grown on the Rust side fails the gate until the extension
//                 gets a validator for it.
//   "rust-parsed" an extension->host frame: the enforcing reader is the
//                 Rust serde parser itself, and there is no Zod reader to
//                 diff. Still normalized rust-side, so the R5 strictness
//                 walk fails the gate if the variant ever stops refusing
//                 unknown fields (deny_unknown_fields lost anywhere). The
//                 WRITER side is generated (GENERATED_WRITER_FRAMES): the
//                 extension's constructor sites `satisfies` the inferred
//                 wire types, and the cross-check below holds the generated
//                 set to exactly these plans.
//
// Both directions are checked against the emitted enum, so adding, renaming,
// or removing a variant fails here until this plan says how it is covered;
// the { zod } set is additionally cross-checked against the generated frame
// list below, so a frame cannot silently drop out of generation either.
type FramePlan = { zod: z.ZodType } | "bare-tag" | "rust-parsed";

export const GROUPS = ["enclave", "admin", "policy"] as const;
export type Group = (typeof GROUPS)[number];

export const FRAME_PLANS: Record<Group, Readonly<Record<string, FramePlan>>> = {
  enclave: {
    enclave_challenge: "rust-parsed",
    enclave_proof: { zod: EnclaveProofFrameSchema },
    enclave_error: { zod: EnclaveErrorFrameSchema },
    enclave_revoke: "rust-parsed",
    enclave_revoked: "bare-tag",
    presence_challenge: "rust-parsed",
    presence_proof: { zod: PresenceProofFrameSchema },
    presence_error: { zod: PresenceErrorFrameSchema },
  },
  admin: {
    client_list: "rust-parsed",
    client_list_result: { zod: ClientListResultSchema },
    client_revoke: "rust-parsed",
    client_revoke_result: { zod: ClientRevokeResultSchema },
    kill_status: "rust-parsed",
    kill_engage: "rust-parsed",
    kill_release: "rust-parsed",
    kill_status_result: { zod: KillStatusResultSchema },
    audit_event: "rust-parsed",
  },
  policy: {
    policy_get: "rust-parsed",
    policy_current: { zod: PolicyCurrentFrameSchema },
    legacy_settings: "rust-parsed",
    lang_get: "rust-parsed",
    lang_set: "rust-parsed",
    lang_current: { zod: LangCurrentFrameSchema },
  },
};

function bareTag(tag: string): unknown {
  return {
    type: "object",
    properties: { type: { type: "string", const: tag } },
    required: ["type"],
  };
}

// The runtime classifiers the extension routes inbound frames on. Held to
// EQUALITY with the plans, per group: every classified tag must be a real
// frame of the matching Rust enum AND have an inbound validator plan behind
// it ({ zod } / "bare-tag") - a writer-only tag added to a classification
// array would otherwise route frames nothing validates - and every gated
// inbound frame must still be reachable through a classifier - a tag dropped
// from its classification array would otherwise silently stop routing while
// the schemas stay green.
// kill_status_result has no classification array: isKillStatusFrame
// (shared/enclave.ts) classifies by full-schema parse, whose `type` literal
// the diff above already pins.
export const CLASSIFIED_TAGS: Record<Group, ReadonlySet<string>> = {
  enclave: new Set([...ENCLAVE_FRAME_TYPES, ...PRESENCE_FRAME_TYPES]),
  admin: new Set([...ADMIN_RESULT_FRAME_TYPES, "kill_status_result"]),
  policy: new Set(POLICY_FRAME_TYPES),
};

// Ceremony tags classified WITHOUT an inbound plan, deliberately (ADR-0025):
// these are extension->host ("rust-parsed") frames, and classifying the
// inbound direction too makes the extension handle a copy arriving inbound
// as ceremony traffic - dropped/refused by the handler - instead of
// dispatching it (see ENCLAVE_FRAME_TYPES in shared/enclave.ts). Not a
// missing validator, so do not "fix" the exception away; each entry is
// cross-checked below to stay classified and stay "rust-parsed".
const CLASSIFIED_OUTBOUND_TAGS: Record<Group, ReadonlySet<string>> = {
  enclave: new Set(["enclave_challenge", "enclave_revoke"]),
  admin: new Set(),
  policy: new Set(),
};

// ---- pinned parser refinements (invisible to the structural diff) ------------
//
// A refinement (.superRefine / .refine) never appears in z.toJSONSchema
// output, so the structural diff below can neither see one appear nor see one
// vanish. Every deliberate refinement on a wrapped frame validator is
// therefore pinned HERE, RECONCILED_FIELDS-style, and the pins bind both
// ways: every { zod } plan's custom-check count - walked RECURSIVELY, so a
// nested .refine cannot ride in unpinned either - must equal its pinned
// refinement count (an unpinned refinement is refused, and so is a pinned one
// that is gone), and each pin carries probe frames the refinement must refuse
// and must keep accepting. Precisely what that guarantees: count stability
// and the probe behavior, nothing more - a refinement that keeps the count
// and passes every probe while doing something ELSE as well is beyond any
// finite probe list, and is owned by review of the schema's documented
// charter (the ASYMMETRY comment in enclave.ts). Enforced by
// refinementProblems below, run against every { zod } plan.

export type RefinementPin = {
  /** Which deliberate asymmetry this is, for the failure message; the full
   * why lives on the schema in enclave.ts. */
  name: string;
  /** Frames the per-field validation accepts that the refinement must
   * refuse. */
  refuses: readonly unknown[];
  /** Legitimate frames the refinement must keep accepting. */
  accepts: readonly unknown[];
};

export const FRAME_REFINEMENTS: Readonly<
  Partial<Record<ControlFrameKind, readonly RefinementPin[]>>
> = {
  // The policy_current ok-split (enclave.ts): PolicyStatus::into_frame
  // (protocol.rs) emits exactly two flat shapes, and the extension refuses
  // everything per-field validation would pass outside them - `ok: true`
  // requires `baseline` and never carries `reason` or `error`; `ok: false`
  // requires `error` and never carries `baseline`, `sig`, or `overlay`. The
  // Phase-4 legacy-import send-once gates on
  // `ok === false && reason === "absent"`, so a reason must never be able to
  // ride a frame that also claims success.
  policy_current: [
    {
      name: "ok-split",
      refuses: [
        { type: "policy_current", ok: true, baseline: "e30=", reason: "absent" },
        { type: "policy_current", ok: true, baseline: "e30=", error: "boom" },
        { type: "policy_current", ok: true },
        { type: "policy_current", ok: false, baseline: "e30=", error: "boom" },
        { type: "policy_current", ok: false, sig: "c2ln", error: "boom" },
        { type: "policy_current", ok: false, overlay: {}, error: "boom" },
        { type: "policy_current", ok: false, reason: "absent" },
      ],
      accepts: [
        { type: "policy_current", ok: true, baseline: "e30=", sig: "c2ln", overlay: {} },
        { type: "policy_current", ok: false, reason: "absent", error: "no policy baseline" },
      ],
    },
  ],
};

/** Count the CUSTOM checks (refinements) in a Zod schema, recursively:
 * z.toJSONSchema cannot represent them, so the gate walks the schema graph
 * (every nested def, with a cycle guard) counting checks whose def.check is
 * "custom" - a superRefine on the frame or a .refine buried on a nested
 * property both land here. Built-in checks (min_length, bounds, formats) DO
 * surface in the JSON Schema derivations and are the structural diff's
 * business, so they are not counted. */
function customCheckCount(schema: z.ZodType): number {
  let count = 0;
  const seen = new Set<object>();
  const visit = (node: unknown): void => {
    if (typeof node !== "object" || node === null || seen.has(node)) return;
    seen.add(node);
    const def = (node as { _zod?: { def?: Record<string, unknown> } })._zod?.def;
    if (def !== undefined) {
      const checks = def.checks;
      if (Array.isArray(checks)) {
        for (const check of checks) {
          const checkDef = (check as { _zod?: { def?: { check?: unknown } } })._zod?.def;
          if (checkDef?.check === "custom") count += 1;
        }
      }
      visit(def);
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

/** The refinement-pin rule (see FRAME_REFINEMENTS): pure over its inputs so
 * scripts/check-envelope-parity.test.ts can prove the refusals fire; the
 * running gate passes each { zod } plan with its pins (an unpinned frame gets
 * the empty list, holding it to zero refinements). Returns the failures,
 * empty meaning the schema carries exactly the pinned number of custom
 * refinements and each probe behaves. */
export function refinementProblems(
  tag: string,
  schema: z.ZodType,
  pins: readonly RefinementPin[],
): string[] {
  const problems: string[] = [];
  const checks = customCheckCount(schema);
  if (checks !== pins.length) {
    problems.push(
      `${tag}: the wrapped validator carries ${checks} custom refinement(s) but ` +
        `FRAME_REFINEMENTS pins ${pins.length} - refinements are invisible to the ` +
        `structural diff, so every one must be pinned there (and no pin may outlive ` +
        `its refinement)`,
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

/** The classifier-coverage rule (see the comment on CLASSIFIED_TAGS): pure
 * over its inputs so scripts/check-envelope-parity.test.ts can prove the
 * refusals fire; the running gate passes the real classified sets and the
 * cargo-emitted Rust tags. Returns the failures, empty meaning covered. */
export function classifierCoverageProblems(
  group: Group,
  classified: ReadonlySet<string>,
  rustTags: ReadonlySet<string>,
): string[] {
  const problems: string[] = [];
  const inbound = new Set(
    Object.entries(FRAME_PLANS[group])
      .filter(([, plan]) => plan !== "rust-parsed")
      .map(([tag]) => tag),
  );
  for (const tag of classified) {
    // Every classified tag must be a real frame of the matching Rust enum...
    if (!rustTags.has(tag)) {
      problems.push(`classifier: ${tag} is not a frame of the Rust ${group} enum`);
    }
    // ...with an inbound validator plan behind it, unless pinned as a
    // deliberately-classified outbound tag.
    if (!inbound.has(tag) && !CLASSIFIED_OUTBOUND_TAGS[group].has(tag)) {
      problems.push(
        `classifier: ${group} tag ${tag} is classified inbound but no plan gives it an ` +
          `inbound validator ({ zod } / "bare-tag") - a frame wearing it would route unvalidated`,
      );
    }
  }
  // The exception pins bind both ways too.
  for (const tag of CLASSIFIED_OUTBOUND_TAGS[group]) {
    if (!classified.has(tag)) {
      problems.push(
        `classifier: pinned outbound tag ${tag} is no longer classified by the ${group} arrays`,
      );
    }
    if (FRAME_PLANS[group][tag] !== "rust-parsed") {
      problems.push(
        `classifier: pinned outbound tag ${tag} is not a "rust-parsed" ${group} plan - an ` +
          `inbound frame needs a validator, not an exception pin`,
      );
    }
  }
  // ...and every gated inbound frame must still be routed by a classifier.
  for (const tag of inbound) {
    if (!classified.has(tag)) {
      problems.push(`${group}: inbound frame ${tag} is gated but no runtime classifier routes it`);
    }
  }
  return problems;
}

function main(): void {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");

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
    throw new Error(`check-envelope-parity: cargo emit failed with status ${emitted.exitCode}`);
  }
  const fromRust = JSON.parse(emitted.stdout.toString()) as {
    request: unknown;
    response: unknown;
    enclave: unknown;
    admin: unknown;
    policy: unknown;
  };

  let failed = false;
  function fail(message: string): void {
    console.error(message);
    failed = true;
  }

  // ---- the BridgeReq/BridgeResp envelope pair ---------------------------------

  for (const [kind, name, rustSchema, zodSchema] of [
    ["request", "request (BridgeReq)", fromRust.request, z.toJSONSchema(BridgeReqSchema)],
    ["response", "response (BridgeResp)", fromRust.response, z.toJSONSchema(BridgeRespSchema)],
  ] as const) {
    const diff = diffSchemas(
      normalizeEnvelopeSchema(rustSchema, kind, "rust"),
      normalizeEnvelopeSchema(zodSchema, kind, "zod"),
    );
    if (diff.length > 0) {
      fail(
        `${name}: the Rust wire type and the Zod validator have drifted apart ` +
          `(left = Rust, right = Zod):\n  ${diff.join("\n  ")}`,
      );
    } else {
      console.log(`${name}: Rust and Zod derivations are structurally equivalent`);
    }
  }

  // ---- the EnclaveControl / AdminControl frames -------------------------------

  // Generation coverage: the frames planned as { zod } must be exactly the
  // frames gen-envelope.ts generates a base schema for. A mismatch either way
  // means a validator without a generated base (hand-written from scratch
  // again) or a generated base no plan holds to the contract.
  for (const group of GROUPS) {
    const generated = new Set<string>(GENERATED_WIRE_FRAMES[group]);
    const planned = new Set(
      Object.entries(FRAME_PLANS[group])
        .filter(([, plan]) => typeof plan === "object")
        .map(([tag]) => tag),
    );
    for (const tag of planned) {
      if (!generated.has(tag))
        fail(`${group}: ${tag} is planned as { zod } but has no generated base`);
    }
    for (const tag of generated) {
      if (!planned.has(tag)) fail(`${group}: ${tag} has a generated base but no { zod } plan`);
    }
  }

  // Writer coverage, same both-ways shape: the frames planned as "rust-parsed"
  // (extension->host; the extension constructs them, the Rust serde parser is
  // the enforcing reader) must be exactly the frames gen-envelope.ts emits a
  // writer schema for. A mismatch either way means a constructor site with no
  // generated type to `satisfies` (hand-typed frame shapes again) or a
  // generated writer schema no plan accounts for.
  for (const group of GROUPS) {
    const generated = new Set<string>(GENERATED_WRITER_FRAMES[group]);
    const planned = new Set(
      Object.entries(FRAME_PLANS[group])
        .filter(([, plan]) => plan === "rust-parsed")
        .map(([tag]) => tag),
    );
    for (const tag of planned) {
      if (!generated.has(tag))
        fail(`${group}: ${tag} is planned as "rust-parsed" but has no generated writer schema`);
    }
    for (const tag of generated) {
      if (!planned.has(tag))
        fail(`${group}: ${tag} has a generated writer schema but no "rust-parsed" plan`);
    }
  }

  const rustTags: Record<Group, Set<string>> = {
    enclave: new Set(),
    admin: new Set(),
    policy: new Set(),
  };

  for (const group of GROUPS) {
    const variants = splitTaggedUnionSchema(fromRust[group]);
    const plans = FRAME_PLANS[group];
    rustTags[group] = new Set(variants.keys());

    for (const tag of variants.keys()) {
      if (!(tag in plans)) fail(`${group}: Rust frame ${tag} has no coverage plan in FRAME_PLANS`);
    }
    for (const [tag, plan] of Object.entries(plans)) {
      const variant = variants.get(tag);
      if (variant === undefined) {
        fail(`${group}: FRAME_PLANS covers ${tag} but the Rust enum no longer emits it`);
        continue;
      }
      const kind = tag as ControlFrameKind;
      const name = `${group} frame ${tag}`;
      const rustNorm = normalizeEnvelopeSchema(variant, kind, "rust");
      if (plan === "rust-parsed") {
        // Normalizing rust-side already ran the R5 strictness walk (a variant
        // that stops refusing unknown fields throws); nothing to diff. The
        // writer side is covered by the generated-writer cross-check above.
        console.log(`${name}: strict Rust parser (extension->host; no Zod reader to diff)`);
        continue;
      }
      const other =
        plan === "bare-tag"
          ? bareTag(tag)
          : normalizeEnvelopeSchema(z.toJSONSchema(plan.zod), kind, "zod");
      const diff = diffSchemas(rustNorm, other);
      if (diff.length > 0) {
        fail(
          plan === "bare-tag"
            ? `${name}: no longer the bare tag the extension classifies on ` +
                `(left = Rust, right = expected):\n  ${diff.join("\n  ")}`
            : `${name}: the Rust wire type and the Zod validator have drifted apart ` +
                `(left = Rust, right = Zod):\n  ${diff.join("\n  ")}`,
        );
      } else {
        console.log(
          plan === "bare-tag"
            ? `${name}: Rust derivation is the bare classification tag`
            : `${name}: Rust and Zod derivations are structurally equivalent`,
        );
      }
    }
  }

  for (const group of GROUPS) {
    for (const problem of classifierCoverageProblems(
      group,
      CLASSIFIED_TAGS[group],
      rustTags[group],
    )) {
      fail(problem);
    }
  }

  // Pinned refinements (FRAME_REFINEMENTS): invisible to the structural diff
  // above, so every { zod } plan is held to its pinned refinement count and
  // probe behavior - the unpinned ones to zero.
  const zodPlannedTags = new Set<string>();
  for (const group of GROUPS) {
    for (const [tag, plan] of Object.entries(FRAME_PLANS[group])) {
      if (typeof plan !== "object") continue;
      zodPlannedTags.add(tag);
      const pins = FRAME_REFINEMENTS[tag as ControlFrameKind] ?? [];
      const problems = refinementProblems(tag, plan.zod, pins);
      for (const problem of problems) fail(problem);
      if (pins.length > 0 && problems.length === 0) {
        console.log(`${group} frame ${tag}: pinned refinement(s) present and behaving`);
      }
    }
  }
  // The pins bind both ways: one on a frame without a { zod } plan is stale.
  for (const tag of Object.keys(FRAME_REFINEMENTS)) {
    if (!zodPlannedTags.has(tag)) {
      fail(`FRAME_REFINEMENTS pins ${tag} but no { zod } plan carries a validator for it`);
    }
  }

  if (failed) process.exit(1);
}

if (import.meta.main) main();
