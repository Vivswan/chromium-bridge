// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs;
// AdminControl embeds allowlist::ClientEntry) by scripts/gen-envelope.ts -
// DO NOT EDIT. Edit the Rust types, then run `moon run gen`.
//
// The FAITHFUL base wire schemas: strict objects (deny_unknown_fields ->
// .strict()), required fields required, no defaults (see the fail-closed
// generation rules G1-G5 in scripts/gen-envelope.ts). The extension never
// consumes these directly: envelope.ts and enclave.ts layer the deliberate
// parser asymmetries on top - each pinned by scripts/check-envelope-parity.ts
// (`moon run check-envelope`) and exercised in tests/envelope-wire.gen.test.ts.

import { z } from "zod";

// The request envelope (BridgeReq) and the response envelope (BridgeResp).
export const BridgeReqWireSchema = z
  .object({
    "args": z.any(),
    "browser": z.union([z.string(), z.null()]).optional(),
    "id": z.number().int().gte(0),
    "op": z.string(),
    "tabId": z.union([z.number().int(), z.null()]).optional(),
  })
  .strict();

export const BridgeRespWireSchema = z
  .object({
    "data": z.any().optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "id": z.number().int().gte(0),
    "ok": z.boolean(),
  })
  .strict();

// One trusted-client entry (allowlist::ClientEntry), embedded in
// client_list_result's `clients` array.
export const ClientEntryWireSchema = z
  .object({
    "added_unix": z.number().int().gte(0).optional(),
    "anchor": z.union([
      z.object({ "kind": z.literal("hash"), "value": z.string() }).strict(),
      z.object({ "kind": z.literal("team_id"), "value": z.string() }).strict(),
    ]),
    "name": z.string(),
  })
  .strict();

// The host->extension control frames (ADR-0021/0025/0030/0031).
export const EnclaveProofWireSchema = z
  .object({
    "key_id": z.string(),
    "pubkey": z.string(),
    "sig": z.string(),
    "type": z.literal("enclave_proof"),
  })
  .strict();

export const EnclaveErrorWireSchema = z
  .object({ "reason": z.string(), "type": z.literal("enclave_error") })
  .strict();

export const PresenceProofWireSchema = z
  .object({
    "key_id": z.string(),
    "pubkey": z.string(),
    "sig": z.string(),
    "type": z.literal("presence_proof"),
  })
  .strict();

export const PresenceErrorWireSchema = z
  .object({ "reason": z.string(), "type": z.literal("presence_error") })
  .strict();

export const ClientListResultWireSchema = z
  .object({
    "clients": z.array(ClientEntryWireSchema),
    "enrolled": z.boolean(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_list_result"),
  })
  .strict();

export const ClientRevokeResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_revoke_result"),
  })
  .strict();

export const KillStatusResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "killed": z.union([z.boolean(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("kill_status_result"),
  })
  .strict();

// Which control-frame tags have a generated base schema above.
// scripts/check-envelope-parity.ts cross-checks this against its per-frame
// coverage plan, so a frame cannot silently drop out of generation.
export const GENERATED_WIRE_FRAMES = {
  enclave: ["enclave_proof", "enclave_error", "presence_proof", "presence_error"],
  admin: ["client_list_result", "client_revoke_result", "kill_status_result"],
} as const;
