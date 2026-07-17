#!/usr/bin/env bun

// The envelope double-derivation gate (ADR-0028). The Rust wire types
// (BridgeReq/BridgeResp in src/packages/core/src/protocol.rs) are the canonical
// envelope contract; the extension enforces hand-written Zod validators
// (src/packages/shared/src/envelope.ts). Neither side checks in a schema:
// this script derives one from each side - schemars on the Rust side
// (behind the gen-only `envelope-schema` cargo feature, absent from every
// binary), z.toJSONSchema on the Zod side - normalizes both through the
// documented erasure rules in src/packages/shared/src/json-schema-normalize.ts,
// and fails on any remaining difference. Run via `just check-envelope`
// (part of `just ci`).

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { BridgeReqSchema, BridgeRespSchema } from "../src/packages/shared/src/envelope";
import {
  diffSchemas,
  normalizeEnvelopeSchema,
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
const fromRust = JSON.parse(emitted.stdout.toString()) as { request: unknown; response: unknown };

let failed = false;
for (const [kind, name, rustSchema, zodSchema] of [
  ["request", "request (BridgeReq)", fromRust.request, z.toJSONSchema(BridgeReqSchema)],
  ["response", "response (BridgeResp)", fromRust.response, z.toJSONSchema(BridgeRespSchema)],
] as const) {
  const diff = diffSchemas(
    normalizeEnvelopeSchema(rustSchema, kind, "rust"),
    normalizeEnvelopeSchema(zodSchema, kind, "zod"),
  );
  if (diff.length > 0) {
    console.error(
      `${name}: the Rust wire type and the Zod validator have drifted apart ` +
        `(left = Rust, right = Zod):\n  ${diff.join("\n  ")}`,
    );
    failed = true;
  } else {
    console.log(`${name}: Rust and Zod derivations are structurally equivalent`);
  }
}

if (failed) process.exit(1);
