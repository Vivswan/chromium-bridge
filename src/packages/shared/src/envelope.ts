// The internal bridge envelope: the Zod validators the extension enforces at
// the native-messaging boundary, and the request/response types inferred from
// them.
//
// The canonical envelope contract is the Rust wire types (BridgeReq /
// BridgeResp in src/packages/core/src/protocol.rs, ADR-0028). The base wire
// schemas are GENERATED from them (envelope-wire.gen.ts, `just gen`), so the
// field inventory, required-ness, and envelope strictness come straight from
// the contract. This module layers the extension's DELIBERATE parser
// asymmetries on top of the generated base - each field override below is
// one asymmetry, named and pinned in RECONCILED_FIELDS
// (json-schema-normalize.ts), held to exactly that list by the parity gate
// (scripts/check-envelope-parity.ts, CI + `just ci`), and exercised
// behaviorally in tests/envelope-wire.gen.test.ts.

import { z } from "zod";
import { BridgeReqWireSchema, BridgeRespWireSchema } from "./envelope-wire.gen";
import { type BridgeCommand, isOpName, OP_ARG_SCHEMAS, OpArgsSchema } from "./ops.gen";

// ASYMMETRY (id): a JS-safe integer (the extension is a JS runtime, so larger
// integers have already lost precision in JSON.parse) or a string for
// forward-compatibility. Deliberately wider than the Rust side's u64-only id
// (see BridgeReq::id in src/packages/core/src/protocol.rs).
export const BridgeIdSchema = z.union([z.int(), z.string()]);

// The request envelope (BridgeReq on the wire): { id, op, tabId?, browser?, args }.
// The generated base contributes the shape and the strict envelope (unknown
// top-level fields rejected); every override below is a pinned asymmetry.
export const BridgeReqSchema = BridgeReqWireSchema.extend({
  // ASYMMETRY (id): see BridgeIdSchema.
  id: BridgeIdSchema,
  // ASYMMETRY (op): refuse the empty string early; the Rust side leaves op
  // validation to the catalogue lookup. The per-op narrowing happens against
  // OP_ARG_SCHEMAS in parseBridgeReq.
  op: z.string().min(1),
  // ASYMMETRY (tabId): no null arm (serde's Option accepts an explicit null;
  // our writers omit absent fields) and JS-safe bounds. When omitted, the
  // handler resolves the active tab.
  tabId: z.int().optional(),
  // ASYMMETRY (browser): no null arm, and the browser-label grammar enforced
  // early. The label of the browser connection the MCP server routed this
  // request to - informational for the extension: each native-messaging port
  // already belongs to exactly one browser.
  browser: z
    .string()
    .min(1)
    .max(32)
    .regex(/^[A-Za-z0-9._-]+$/)
    .optional(),
  // ASYMMETRY (args, rule R3): free-form on the Rust side (validated per-op
  // downstream), narrowed here to the generated OpArgs union before the
  // per-op validation in parseBridgeReq.
  args: OpArgsSchema,
});

// The wide (envelope-level) request shape. Consumers should prefer BridgeReq,
// the per-op narrowed form parseBridgeReq produces.
export type BridgeReqEnvelope = z.infer<typeof BridgeReqSchema>;

// The response envelope posted back to the native host over the Port.
// The generated base contributes the shape and strictness; the overrides are
// pinned asymmetries plus one type-level tightening.
export const BridgeRespSchema = BridgeRespWireSchema.extend({
  // ASYMMETRY (id): see BridgeIdSchema.
  id: BridgeIdSchema,
  // Type-level only: the op's payload on success is intentionally
  // unconstrained on both sides; `unknown` instead of the generated base's
  // `any` so consumers must narrow it. Same instance set, no wire asymmetry.
  data: z.unknown().optional(),
  // ASYMMETRY (error): no null arm (serde's Option; writers omit absent
  // errors). Human-readable failure reason when ok is false. The stable
  // programmatic code (errors.gen.ts) is assigned on the Rust side.
  error: z.string().optional(),
});

export type BridgeResp = z.infer<typeof BridgeRespSchema>;

// A fully validated request: the generated per-op command union intersected
// with the envelope fields. The intersection distributes over the union, so
// consumers narrow on `op` and get exactly the args that tool accepts.
export type BridgeReq = BridgeCommand & { id: number | string; tabId?: number; browser?: string };

export type ParseBridgeReqResult =
  | { ok: true; req: BridgeReq }
  | { ok: false; id?: number | string; error: string };

// Best-effort id extraction from a frame that failed validation, so the
// refusal can still be correlated with the request that caused it. Only an id
// the schema itself vouches for is echoed - a fractional, non-finite, or
// unsafe-integer id would make the refusal response malformed too.
function extractId(msg: unknown): number | string | undefined {
  if (typeof msg !== "object" || msg === null) return undefined;
  const id = BridgeIdSchema.safeParse((msg as { id?: unknown }).id);
  return id.success ? id.data : undefined;
}

// One-line issue summary for refusal messages. The input comes from the
// native host (already inside the trust boundary being enforced), so echoing
// paths and expectations back is diagnostic, not a leak.
function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "invalid";
  const path = issue.path.length ? `${issue.path.join(".")}: ` : "";
  return `${path}${issue.message}`;
}

/**
 * Validate one inbound native-messaging frame as a bridge request, fail
 * closed. Three layers, all of which must pass before anything dispatches:
 *
 *   1. the envelope (the Rust BridgeReq wire shape): unknown top-level
 *      fields and unknown args are rejected outright;
 *   2. the op must be in the generated catalogue (OP_NAMES);
 *   3. the args must satisfy that op's validator (required fields, types).
 *
 * On failure the caller gets the extracted id (when there is one) so it can
 * answer with a refusal instead of leaving the host waiting for a timeout.
 */
export function parseBridgeReq(msg: unknown): ParseBridgeReqResult {
  const envelope = BridgeReqSchema.safeParse(msg);
  if (!envelope.success) {
    return {
      ok: false,
      id: extractId(msg),
      error: `malformed bridge request: ${firstIssue(envelope.error)}`,
    };
  }
  const { op, id } = envelope.data;
  if (!isOpName(op)) {
    return { ok: false, id, error: `unknown op: ${op}` };
  }
  const args = OP_ARG_SCHEMAS[op].safeParse(envelope.data.args);
  if (!args.success) {
    return { ok: false, id, error: `invalid args for ${op}: ${firstIssue(args.error)}` };
  }
  return {
    ok: true,
    req: {
      ...envelope.data,
      op,
      args: args.data,
    } as BridgeReq,
  };
}
