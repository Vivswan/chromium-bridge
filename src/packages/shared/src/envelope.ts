// The native-messaging boundary for bridge requests: parseBridgeReq validates one inbound frame against the
// generated request envelope (BridgeReqSchema in envelope.gen.ts, the Rust BridgeReq plus the asymmetry table)
// and then against the op's own generated validator, fail closed.

import type { z } from "zod";
import { BridgeReqSchema } from "./envelope.gen";
import { type BridgeCommand, isOpName, OP_ARG_SCHEMAS } from "./ops.gen";

// A fully validated request: the generated per-op command union intersected with the envelope fields. The
// intersection distributes over the union, so consumers narrow on `op` and get exactly the args that tool
// accepts.
export type BridgeReq = BridgeCommand & { id: number | string; browser?: string };

export type ParseBridgeReqResult =
  | { ok: true; req: BridgeReq }
  | { ok: false; id?: number | string; error: string };

// Best-effort id extraction from a frame that failed validation, so the refusal can still be correlated with
// the request that caused it. Only an id the envelope's own parse found no fault with is echoed - a
// fractional, negative, or unsafe-integer id would make the refusal response malformed too.
function extractId(msg: unknown, issues: readonly z.core.$ZodIssue[]): number | string | undefined {
  if (typeof msg !== "object" || msg === null || Array.isArray(msg)) return undefined;
  if (issues.some((issue) => issue.path[0] === "id")) return undefined;
  const { id } = msg as { id?: unknown };
  return typeof id === "number" || typeof id === "string" ? id : undefined;
}

// One-line issue summary for refusal messages. The input comes from the native host (already inside the trust
// boundary being enforced), so echoing paths and expectations back is diagnostic, not a leak.
function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "invalid";
  const path = issue.path.length ? `${issue.path.join(".")}: ` : "";
  return `${path}${issue.message}`;
}

/**
 * Validate one inbound native-messaging frame as a bridge request, fail closed. On failure the caller gets the
 * extracted id (when there is one) so it can answer with a refusal instead of leaving the host waiting for a
 * timeout.
 */
export function parseBridgeReq(msg: unknown): ParseBridgeReqResult {
  const envelope = BridgeReqSchema.safeParse(msg);
  if (!envelope.success) {
    return {
      ok: false,
      id: extractId(msg, envelope.error.issues),
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
