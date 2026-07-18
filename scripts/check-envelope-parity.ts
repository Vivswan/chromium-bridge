#!/usr/bin/env bun

// The envelope double-derivation gate (ADR-0028). The Rust wire types in
// src/packages/core/src/protocol.rs are the canonical contract: the
// BridgeReq/BridgeResp envelope pair, and the host-handled control frames
// (EnclaveControl and AdminControl, the latter embedding
// allowlist::ClientEntry). The extension enforces hand-written Zod
// validators (src/packages/shared/src/envelope.ts for the envelopes,
// enclave.ts for the control frames). Neither side checks in a schema:
// this script derives one from each side - schemars on the Rust side
// (behind the gen-only `envelope-schema` cargo feature, absent from every
// binary), z.toJSONSchema on the Zod side - normalizes both through the
// documented erasure rules in src/packages/shared/src/json-schema-normalize.ts,
// and fails on any remaining difference. Run via `just check-envelope`
// (part of `just ci`).

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
  PRESENCE_FRAME_TYPES,
  PresenceErrorFrameSchema,
  PresenceProofFrameSchema,
} from "../src/packages/shared/src/enclave";
import { BridgeReqSchema, BridgeRespSchema } from "../src/packages/shared/src/envelope";
import {
  type ControlFrameKind,
  diffSchemas,
  normalizeEnvelopeSchema,
  splitTaggedUnionSchema,
} from "../src/packages/shared/src/json-schema-normalize";

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
};

let failed = false;
function fail(message: string): void {
  console.error(message);
  failed = true;
}

// ---- the BridgeReq/BridgeResp envelope pair -----------------------------------

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

// ---- the EnclaveControl / AdminControl frames ---------------------------------

// How each control-frame tag is covered, one entry per Rust enum variant:
//
//   { zod }       a host->extension frame with a hand-written Zod mirror in
//                 shared/enclave.ts (the extension's contract surface for
//                 it); its two derivations are diffed exactly like the
//                 envelopes.
//   "bare-tag"    a host->extension frame that must stay fieldless: the
//                 `type` classification IS its whole shape, so there is no
//                 per-frame Zod validator. Pinned to the bare tag - a field
//                 grown on the Rust side fails the gate until the extension
//                 gets a validator for it.
//   "rust-parsed" an extension->host frame: the enforcing reader is the
//                 Rust serde parser itself, and there is no Zod reader to
//                 diff. Still normalized rust-side, so the R5 strictness
//                 walk fails the gate if the variant ever stops refusing
//                 unknown fields (deny_unknown_fields lost anywhere).
//
// Both directions are checked against the emitted enum, so adding, renaming,
// or removing a variant fails here until this plan says how it is covered.
type FramePlan = { zod: z.ZodType } | "bare-tag" | "rust-parsed";

const FRAME_PLANS: Record<"enclave" | "admin", Readonly<Record<string, FramePlan>>> = {
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
};

function bareTag(tag: string): unknown {
  return {
    type: "object",
    properties: { type: { type: "string", const: tag } },
    required: ["type"],
  };
}

const rustTags: Record<"enclave" | "admin", Set<string>> = { enclave: new Set(), admin: new Set() };

for (const group of ["enclave", "admin"] as const) {
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
      // that stops refusing unknown fields throws); nothing to diff.
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

// The runtime classifiers the extension routes inbound frames on. Checked
// both ways: every classified tag must be a real frame of the matching Rust
// enum, and every gated inbound frame ({ zod } / "bare-tag") must still be
// reachable through a classifier - a tag dropped from its classification
// array would otherwise silently stop routing while the schemas stay green.
// kill_status_result has no classification array: isKillStatusFrame
// (shared/enclave.ts) classifies by full-schema parse, whose `type` literal
// the diff above already pins.
const CLASSIFIED_TAGS: Record<"enclave" | "admin", ReadonlySet<string>> = {
  enclave: new Set([...ENCLAVE_FRAME_TYPES, ...PRESENCE_FRAME_TYPES]),
  admin: new Set([...ADMIN_RESULT_FRAME_TYPES, "kill_status_result"]),
};

for (const group of ["enclave", "admin"] as const) {
  // Every classified tag (the arrays above plus the hardcoded
  // kill_status_result) must be a real frame of the matching Rust enum...
  for (const tag of CLASSIFIED_TAGS[group]) {
    if (!rustTags[group].has(tag)) {
      fail(`classifier: ${tag} is not a frame of the Rust ${group} enum`);
    }
  }
  // ...and every gated inbound frame must still be routed by a classifier.
  for (const [tag, plan] of Object.entries(FRAME_PLANS[group])) {
    if (plan !== "rust-parsed" && !CLASSIFIED_TAGS[group].has(tag)) {
      fail(`${group}: inbound frame ${tag} is gated but no runtime classifier routes it`);
    }
  }
}

if (failed) process.exit(1);
