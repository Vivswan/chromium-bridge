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
// tautological because the wrapper is hand-written. The same asymmetries are
// exercised behaviorally in
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

  if (failed) process.exit(1);
}

if (import.meta.main) main();
