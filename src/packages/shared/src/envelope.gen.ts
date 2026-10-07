// GENERATED from the Rust core wire types (src/packages/core/src/protocol.rs and
// protocol/control.rs; AdminControl embeds allowlist::ClientEntry, PolicyControl embeds
// policy::PolicyOverlay, WebAuthnControl carries the WebAuthn ceremonies) by scripts/gen-envelope.ts -
// DO NOT EDIT. Edit the Rust types or
// src/packages/shared/src/envelope-asymmetries.ts, then run `moon run gen`.
//
// Per envelope, per server->extension signal frame, and per host->extension control frame: the FAITHFUL base
// (*WireSchema: strict objects, required fields required, no defaults; rules G1-G7 in scripts/gen-envelope.ts)
// and the ENFORCED validator the extension runs, which is the base plus exactly the asymmetry table
// (direction and reason per entry in envelope-asymmetries.ts; proved per entry by scripts/check-envelope.ts,
// `moon run check-envelope`). Each validator is the Zod source json-schema-to-zod wrote from the Rust JSON
// Schema and each type is json-schema-to-typescript's reading of the same schema. The request's `args` and
// policy_current's `overlay` carry the schemas ops.gen.ts and policy.gen.ts export, inlined and held equal at
// generation. The extension->host writer schemas exist for their types only (constructor-site `satisfies`);
// the enforcing reader for those frames is the Rust serde parser.

import { z } from "zod";

// The request envelope (BridgeReq) and the response envelope (BridgeResp): the faithful bases, then the
// enforced validators the extension runs (the base plus the asymmetry table; strict like the host).
export const BridgeReqWireSchema = z
  .object({
    "args": z.any(),
    "browser": z.union([z.string(), z.null()]).optional(),
    "id": z.number().int().gte(0),
    "op": z.string(),
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

export interface BridgeReqEnvelope {
  args: {
    tabId?: number;
    url?: string;
    ref?: string;
    selector?: string;
    value?: string;
    direction?: string;
    pixels?: number;
    nav?: boolean;
    text?: string;
    timeoutMs?: number;
    code?: string;
    frameId?: string;
    domain?: string;
    name?: string;
    key?: string;
    type?: string;
    keys?: string;
    limit?: number;
    action?: string;
    promptText?: string;
    path?: string;
  };
  browser?: string;
  id: number | string;
  op: string;
}

export const BridgeReqSchema = z
  .object({
    "args": z
      .object({
        "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
        "url": z.string().optional(),
        "ref": z.string().optional(),
        "selector": z.string().optional(),
        "value": z.string().optional(),
        "direction": z.string().optional(),
        "pixels": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
        "nav": z.boolean().optional(),
        "text": z.string().optional(),
        "timeoutMs": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
        "code": z.string().optional(),
        "frameId": z.string().optional(),
        "domain": z.string().optional(),
        "name": z.string().optional(),
        "key": z.string().optional(),
        "type": z.string().optional(),
        "keys": z.string().optional(),
        "limit": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
        "action": z.string().optional(),
        "promptText": z.string().optional(),
        "path": z.string().optional(),
      })
      .strict(),
    "browser": z
      .string()
      .regex(/^[A-Za-z0-9._-]+$/)
      .min(1)
      .max(32)
      .optional(),
    "id": z.union([z.number().int().gte(0), z.string()]),
    "op": z.string().min(1),
  })
  .strict() as z.ZodType<BridgeReqEnvelope>;

export interface BridgeResp {
  data?: unknown;
  error?: string;
  id: number | string;
  ok: boolean;
}

export const BridgeRespSchema = z
  .object({
    "data": z.any().optional(),
    "error": z.string().optional(),
    "id": z.union([z.number().int().gte(0), z.string()]),
    "ok": z.boolean(),
  })
  .strict() as z.ZodType<BridgeResp>;

// The server->extension signal frames (BridgeSignal), one strict reader per variant: the faithful base,
// then the enforced validator the extension runs.
export const BridgeCancelWireSchema = z
  .object({ "id": z.number().int().gte(0), "type": z.literal("cancel") })
  .strict();

export interface BridgeCancel {
  id: number | string;
  type: "cancel";
}

export const BridgeCancelSchema = z
  .object({ "id": z.union([z.number().int().gte(0), z.string()]), "type": z.literal("cancel") })
  .strict() as z.ZodType<BridgeCancel>;

// One trusted-client entry (allowlist::ClientEntry), embedded in client_list_result's `clients` array.
export const ClientEntryWireSchema = z
  .object({
    "added_unix": z.number().int().gte(0),
    "anchor": z.union([
      z.object({ "kind": z.literal("hash"), "value": z.string() }).strict(),
      z.object({ "kind": z.literal("signer"), "value": z.string() }).strict(),
    ]),
    "name": z.string(),
  })
  .strict();

export interface TrustedClient {
  added_unix: number;
  anchor: {
    kind: "hash" | "signer";
    value: string;
    [k: string]: unknown;
  };
  name: string;
  [k: string]: unknown;
}

export const TrustedClientSchema = z
  .object({
    "added_unix": z.number().int().gte(0),
    "anchor": z
      .object({ "kind": z.enum(["hash", "signer"]), "value": z.string().min(1) })
      .catchall(z.any()),
    "name": z.string(),
  })
  .catchall(z.any()) as z.ZodType<TrustedClient>;

// One browser's registration row (protocol::control::RegistrationRow), embedded in registration_status_result's `browsers` array.
export const RegistrationRowWireSchema = z
  .object({
    "browser": z.string(),
    "detected": z.boolean(),
    "location": z.string(),
    "state": z.union([
      z.object({ "kind": z.literal("missing") }).strict(),
      z.object({ "kind": z.literal("ok") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("stale") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("foreign") }).strict(),
      z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).strict(),
    ]),
  })
  .strict();

export interface RegistrationRow {
  browser: string;
  detected: boolean;
  location: string;
  state:
    | {
        kind: "missing";
        [k: string]: unknown;
      }
    | {
        kind: "ok";
        [k: string]: unknown;
      }
    | {
        detail: string;
        kind: "stale";
        [k: string]: unknown;
      }
    | {
        detail: string;
        kind: "foreign";
        [k: string]: unknown;
      }
    | {
        detail: string;
        kind: "unreadable";
        [k: string]: unknown;
      };
  [k: string]: unknown;
}

export const RegistrationRowSchema = z
  .object({
    "browser": z.string(),
    "detected": z.boolean(),
    "location": z.string(),
    "state": z.union([
      z.object({ "kind": z.literal("missing") }).catchall(z.any()),
      z.object({ "kind": z.literal("ok") }).catchall(z.any()),
      z.object({ "detail": z.string(), "kind": z.literal("stale") }).catchall(z.any()),
      z.object({ "detail": z.string(), "kind": z.literal("foreign") }).catchall(z.any()),
      z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).catchall(z.any()),
    ]),
  })
  .catchall(z.any()) as z.ZodType<RegistrationRow>;

// One line of the host's audit trail (protocol::control::AuditTrailEntry), embedded in audit_read_result's `entries` array.
export const AuditTrailEntryWireSchema = z.union([
  z
    .object({
      "entry": z.literal("record"),
      "fields": z.string(),
      "kind": z.string(),
      "ts_ms": z.number().int().gte(0).lte(9007199254740991),
    })
    .strict(),
  z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).strict(),
]);

export type AuditTrailEntry =
  | {
      entry: "record";
      fields: string;
      kind: string;
      ts_ms: number;
      [k: string]: unknown;
    }
  | {
      entry: "unrecognized";
      text: string;
      [k: string]: unknown;
    };

export const AuditTrailEntrySchema = z.union([
  z
    .object({
      "entry": z.literal("record"),
      "fields": z.string(),
      "kind": z.string(),
      "ts_ms": z.number().int().gte(0).lte(9007199254740991),
    })
    .catchall(z.any()),
  z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).catchall(z.any()),
]) as z.ZodType<AuditTrailEntry>;

// The health report (protocol::control::HealthReport), embedded as doctor_report_result's `report`.
export const HealthReportWireSchema = z
  .object({
    "healthy": z.boolean(),
    "host_key": z.string(),
    "kill_switch": z.object({ "details": z.array(z.string()), "value": z.string() }).strict(),
    "lock_file": z.object({ "details": z.array(z.string()), "value": z.string() }).strict(),
    "mcp_server": z.object({ "details": z.array(z.string()), "value": z.string() }).strict(),
    "platform": z.string(),
    "policy_baseline": z.object({ "details": z.array(z.string()), "value": z.string() }).strict(),
    "summary": z.string(),
    "version": z.string(),
  })
  .strict();

export interface HealthReport {
  healthy: boolean;
  host_key: string;
  kill_switch: {
    details: string[];
    value: string;
    [k: string]: unknown;
  };
  lock_file: {
    details: string[];
    value: string;
    [k: string]: unknown;
  };
  mcp_server: {
    details: string[];
    value: string;
    [k: string]: unknown;
  };
  platform: string;
  policy_baseline: {
    details: string[];
    value: string;
    [k: string]: unknown;
  };
  summary: string;
  version: string;
  [k: string]: unknown;
}

export const HealthReportSchema = z
  .object({
    "healthy": z.boolean(),
    "host_key": z.string(),
    "kill_switch": z
      .object({ "details": z.array(z.string()), "value": z.string() })
      .catchall(z.any()),
    "lock_file": z
      .object({ "details": z.array(z.string()), "value": z.string() })
      .catchall(z.any()),
    "mcp_server": z
      .object({ "details": z.array(z.string()), "value": z.string() })
      .catchall(z.any()),
    "platform": z.string(),
    "policy_baseline": z
      .object({ "details": z.array(z.string()), "value": z.string() })
      .catchall(z.any()),
    "summary": z.string(),
    "version": z.string(),
  })
  .catchall(z.any()) as z.ZodType<HealthReport>;

// The host->extension control frames: the faithful base, then the enforced reader (the base plus the
// asymmetry table, read loose under its loose-frames rule).
export const EnclaveProofWireSchema = z
  .object({
    "key_id": z.string(),
    "pubkey": z.string(),
    "sig": z.string(),
    "type": z.literal("enclave_proof"),
  })
  .strict();

export interface EnclaveProofFrame {
  key_id: string;
  pubkey: string;
  sig: string;
  type: "enclave_proof";
  [k: string]: unknown;
}

export const EnclaveProofFrameSchema = z
  .object({
    "key_id": z.string().min(1),
    "pubkey": z.string().min(1),
    "sig": z.string().min(1),
    "type": z.literal("enclave_proof"),
  })
  .catchall(z.any()) as z.ZodType<EnclaveProofFrame>;

export const EnclaveErrorWireSchema = z
  .object({ "reason": z.string(), "type": z.literal("enclave_error") })
  .strict();

export interface EnclaveErrorFrame {
  reason: string;
  type: "enclave_error";
  [k: string]: unknown;
}

export const EnclaveErrorFrameSchema = z
  .object({ "reason": z.string(), "type": z.literal("enclave_error") })
  .catchall(z.any()) as z.ZodType<EnclaveErrorFrame>;

export const ClientListResultWireSchema = z
  .object({
    "clients": z.array(
      z
        .object({
          "added_unix": z.number().int().gte(0),
          "anchor": z.union([
            z.object({ "kind": z.literal("hash"), "value": z.string() }).strict(),
            z.object({ "kind": z.literal("signer"), "value": z.string() }).strict(),
          ]),
          "name": z.string(),
        })
        .strict(),
    ),
    "enrolled": z.boolean(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_list_result"),
  })
  .strict();

export interface ClientListResult {
  clients: {
    added_unix: number;
    anchor: {
      kind: "hash" | "signer";
      value: string;
      [k: string]: unknown;
    };
    name: string;
    [k: string]: unknown;
  }[];
  enrolled: boolean;
  error?: string;
  ok: boolean;
  type: "client_list_result";
  [k: string]: unknown;
}

export const ClientListResultSchema = z
  .object({
    "clients": z.array(
      z
        .object({
          "added_unix": z.number().int().gte(0),
          "anchor": z
            .object({ "kind": z.enum(["hash", "signer"]), "value": z.string().min(1) })
            .catchall(z.any()),
          "name": z.string(),
        })
        .catchall(z.any()),
    ),
    "enrolled": z.boolean(),
    "error": z.string().optional(),
    "ok": z.boolean(),
    "type": z.literal("client_list_result"),
  })
  .catchall(z.any()) as z.ZodType<ClientListResult>;

export const ClientRevokeResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("client_revoke_result"),
  })
  .strict();

export interface ClientRevokeResult {
  error?: string;
  ok: boolean;
  type: "client_revoke_result";
  [k: string]: unknown;
}

export const ClientRevokeResultSchema = z
  .object({
    "error": z.string().optional(),
    "ok": z.boolean(),
    "type": z.literal("client_revoke_result"),
  })
  .catchall(z.any()) as z.ZodType<ClientRevokeResult>;

export const KillStatusResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "killed": z.union([z.boolean(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("kill_status_result"),
  })
  .strict();

export interface KillStatusResult {
  error?: string;
  killed?: boolean;
  ok: boolean;
  type: "kill_status_result";
  [k: string]: unknown;
}

export const KillStatusResultSchema = z
  .object({
    "error": z.string().optional(),
    "killed": z.boolean().optional(),
    "ok": z.boolean(),
    "type": z.literal("kill_status_result"),
  })
  .catchall(z.any()) as z.ZodType<KillStatusResult>;

export const RegistrationStatusResultWireSchema = z
  .object({
    "browsers": z
      .union([
        z.array(
          z
            .object({
              "browser": z.string(),
              "detected": z.boolean(),
              "location": z.string(),
              "state": z.union([
                z.object({ "kind": z.literal("missing") }).strict(),
                z.object({ "kind": z.literal("ok") }).strict(),
                z.object({ "detail": z.string(), "kind": z.literal("stale") }).strict(),
                z.object({ "detail": z.string(), "kind": z.literal("foreign") }).strict(),
                z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).strict(),
              ]),
            })
            .strict(),
        ),
        z.null(),
      ])
      .optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("registration_status_result"),
  })
  .strict();

export type RegistrationStatusResult =
  | {
      browsers: {
        browser: string;
        detected: boolean;
        location: string;
        state:
          | {
              kind: "missing";
              [k: string]: unknown;
            }
          | {
              kind: "ok";
              [k: string]: unknown;
            }
          | {
              detail: string;
              kind: "stale";
              [k: string]: unknown;
            }
          | {
              detail: string;
              kind: "foreign";
              [k: string]: unknown;
            }
          | {
              detail: string;
              kind: "unreadable";
              [k: string]: unknown;
            };
        [k: string]: unknown;
      }[];
      error?: never;
      ok: true;
      type: "registration_status_result";
      [k: string]: unknown;
    }
  | {
      browsers?: never;
      error: string;
      ok: false;
      type: "registration_status_result";
      [k: string]: unknown;
    };

export const RegistrationStatusResultSchema = z.union([
  z
    .object({
      "browsers": z.array(
        z
          .object({
            "browser": z.string(),
            "detected": z.boolean(),
            "location": z.string(),
            "state": z.union([
              z.object({ "kind": z.literal("missing") }).catchall(z.any()),
              z.object({ "kind": z.literal("ok") }).catchall(z.any()),
              z.object({ "detail": z.string(), "kind": z.literal("stale") }).catchall(z.any()),
              z.object({ "detail": z.string(), "kind": z.literal("foreign") }).catchall(z.any()),
              z.object({ "detail": z.string(), "kind": z.literal("unreadable") }).catchall(z.any()),
            ]),
          })
          .catchall(z.any()),
      ),
      "error": z.never().optional(),
      "ok": z.literal(true),
      "type": z.literal("registration_status_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "browsers": z.never().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "type": z.literal("registration_status_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<RegistrationStatusResult>;

export const AuditReadResultWireSchema = z
  .object({
    "entries": z
      .union([
        z.array(
          z.union([
            z
              .object({
                "entry": z.literal("record"),
                "fields": z.string(),
                "kind": z.string(),
                "ts_ms": z.number().int().gte(0).lte(9007199254740991),
              })
              .strict(),
            z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).strict(),
          ]),
        ),
        z.null(),
      ])
      .optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "older": z.union([z.number().int().gte(0), z.null()]).optional(),
    "path": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("audit_read_result"),
  })
  .strict();

export type AuditReadResult =
  | {
      entries: (
        | {
            entry: "record";
            fields: string;
            kind: string;
            ts_ms: number;
            [k: string]: unknown;
          }
        | {
            entry: "unrecognized";
            text: string;
            [k: string]: unknown;
          }
      )[];
      error?: never;
      ok: true;
      older: number;
      path: string;
      type: "audit_read_result";
      [k: string]: unknown;
    }
  | {
      entries?: never;
      error: string;
      ok: false;
      older?: never;
      path?: never;
      type: "audit_read_result";
      [k: string]: unknown;
    };

export const AuditReadResultSchema = z.union([
  z
    .object({
      "entries": z.array(
        z.union([
          z
            .object({
              "entry": z.literal("record"),
              "fields": z.string(),
              "kind": z.string(),
              "ts_ms": z.number().int().gte(0).lte(9007199254740991),
            })
            .catchall(z.any()),
          z.object({ "entry": z.literal("unrecognized"), "text": z.string() }).catchall(z.any()),
        ]),
      ),
      "error": z.never().optional(),
      "ok": z.literal(true),
      "older": z.number().int().gte(0),
      "path": z.string(),
      "type": z.literal("audit_read_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "entries": z.never().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "older": z.never().optional(),
      "path": z.never().optional(),
      "type": z.literal("audit_read_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<AuditReadResult>;

export const DoctorReportResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "report": z
      .union([
        z
          .object({
            "healthy": z.boolean(),
            "host_key": z.string(),
            "kill_switch": z
              .object({ "details": z.array(z.string()), "value": z.string() })
              .strict(),
            "lock_file": z.object({ "details": z.array(z.string()), "value": z.string() }).strict(),
            "mcp_server": z
              .object({ "details": z.array(z.string()), "value": z.string() })
              .strict(),
            "platform": z.string(),
            "policy_baseline": z
              .object({ "details": z.array(z.string()), "value": z.string() })
              .strict(),
            "summary": z.string(),
            "version": z.string(),
          })
          .strict(),
        z.null(),
      ])
      .optional(),
    "type": z.literal("doctor_report_result"),
  })
  .strict();

export type DoctorReportResult =
  | {
      error?: never;
      ok: true;
      report: {
        healthy: boolean;
        host_key: string;
        kill_switch: {
          details: string[];
          value: string;
          [k: string]: unknown;
        };
        lock_file: {
          details: string[];
          value: string;
          [k: string]: unknown;
        };
        mcp_server: {
          details: string[];
          value: string;
          [k: string]: unknown;
        };
        platform: string;
        policy_baseline: {
          details: string[];
          value: string;
          [k: string]: unknown;
        };
        summary: string;
        version: string;
        [k: string]: unknown;
      };
      type: "doctor_report_result";
      [k: string]: unknown;
    }
  | {
      error: string;
      ok: false;
      report?: never;
      type: "doctor_report_result";
      [k: string]: unknown;
    };

export const DoctorReportResultSchema = z.union([
  z
    .object({
      "error": z.never().optional(),
      "ok": z.literal(true),
      "report": z
        .object({
          "healthy": z.boolean(),
          "host_key": z.string(),
          "kill_switch": z
            .object({ "details": z.array(z.string()), "value": z.string() })
            .catchall(z.any()),
          "lock_file": z
            .object({ "details": z.array(z.string()), "value": z.string() })
            .catchall(z.any()),
          "mcp_server": z
            .object({ "details": z.array(z.string()), "value": z.string() })
            .catchall(z.any()),
          "platform": z.string(),
          "policy_baseline": z
            .object({ "details": z.array(z.string()), "value": z.string() })
            .catchall(z.any()),
          "summary": z.string(),
          "version": z.string(),
        })
        .catchall(z.any()),
      "type": z.literal("doctor_report_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "error": z.string(),
      "ok": z.literal(false),
      "report": z.never().optional(),
      "type": z.literal("doctor_report_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<DoctorReportResult>;

export const PolicyCurrentWireSchema = z
  .object({
    "baseline": z.union([z.string(), z.null()]).optional(),
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "overlay": z
      .union([
        z
          .object({
            "cdpMode": z.union([z.boolean(), z.null()]).optional(),
            "clickToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "confirmGraceMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "confirmHighRiskClick": z.union([z.boolean(), z.null()]).optional(),
            "confirmPageEval": z.union([z.boolean(), z.null()]).optional(),
            "confirmTabClose": z.union([z.boolean(), z.null()]).optional(),
            "disabledTools": z.union([z.array(z.string()), z.null()]).optional(),
            "evalMask": z.union([z.boolean(), z.null()]).optional(),
            "evalToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "fileUploadEnabled": z.union([z.boolean(), z.null()]).optional(),
            "handleDialogEnabled": z.union([z.boolean(), z.null()]).optional(),
            "hostReverifyMs": z.union([z.number().int().gte(0), z.null()]).optional(),
            "pageEvalEnabled": z.union([z.boolean(), z.null()]).optional(),
            "presenceConfirm": z.union([z.boolean(), z.null()]).optional(),
            "warnPreciseSnapshot": z.union([z.boolean(), z.null()]).optional(),
          })
          .strict(),
        z.null(),
      ])
      .optional(),
    "sig": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("policy_current"),
  })
  .strict();

export type PolicyCurrentFrame =
  | {
      baseline: string;
      error?: never;
      ok: true;
      overlay?: {
        cdpMode?: boolean;
        fileUploadEnabled?: boolean;
        handleDialogEnabled?: boolean;
        pageEvalEnabled?: boolean;
        confirmHighRiskClick?: boolean;
        confirmPageEval?: boolean;
        presenceConfirm?: boolean;
        confirmTabClose?: boolean;
        warnPreciseSnapshot?: boolean;
        evalMask?: boolean;
        hostReverifyMs?: number;
        confirmGraceMs?: number;
        clickToastTimeoutMs?: number;
        evalToastTimeoutMs?: number;
        /**
         * @maxItems 256
         */
        disabledTools?: string[];
      };
      sig?: string;
      type: "policy_current";
      [k: string]: unknown;
    }
  | {
      baseline?: never;
      error: string;
      ok: false;
      overlay?: never;
      sig?: never;
      type: "policy_current";
      [k: string]: unknown;
    };

export const PolicyCurrentFrameSchema = z.union([
  z
    .object({
      "baseline": z.string().min(1),
      "error": z.never().optional(),
      "ok": z.literal(true),
      "overlay": z
        .object({
          "cdpMode": z.boolean().optional(),
          "fileUploadEnabled": z.boolean().optional(),
          "handleDialogEnabled": z.boolean().optional(),
          "pageEvalEnabled": z.boolean().optional(),
          "confirmHighRiskClick": z.boolean().optional(),
          "confirmPageEval": z.boolean().optional(),
          "presenceConfirm": z.boolean().optional(),
          "confirmTabClose": z.boolean().optional(),
          "warnPreciseSnapshot": z.boolean().optional(),
          "evalMask": z.boolean().optional(),
          "hostReverifyMs": z.number().int().gte(0).optional(),
          "confirmGraceMs": z.number().int().gte(0).optional(),
          "clickToastTimeoutMs": z.number().int().gte(0).optional(),
          "evalToastTimeoutMs": z.number().int().gte(0).optional(),
          "disabledTools": z.array(z.string().min(1).max(128)).max(256).optional(),
        })
        .strict()
        .optional(),
      "sig": z.string().min(1).optional(),
      "type": z.literal("policy_current"),
    })
    .catchall(z.any()),
  z
    .object({
      "baseline": z.never().optional(),
      "error": z.string(),
      "ok": z.literal(false),
      "overlay": z.never().optional(),
      "sig": z.never().optional(),
      "type": z.literal("policy_current"),
    })
    .catchall(z.any()),
]) as z.ZodType<PolicyCurrentFrame>;

export const PolicyRestrictResultWireSchema = z
  .object({
    "error": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "type": z.literal("policy_restrict_result"),
  })
  .strict();

export type PolicyRestrictResult =
  | {
      error?: never;
      ok: true;
      type: "policy_restrict_result";
      [k: string]: unknown;
    }
  | {
      error: string;
      ok: false;
      type: "policy_restrict_result";
      [k: string]: unknown;
    };

export const PolicyRestrictResultSchema = z.union([
  z
    .object({
      "error": z.never().optional(),
      "ok": z.literal(true),
      "type": z.literal("policy_restrict_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "error": z.string(),
      "ok": z.literal(false),
      "type": z.literal("policy_restrict_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<PolicyRestrictResult>;

export const LangCurrentWireSchema = z
  .object({
    "seq": z.number().int().gte(0),
    "type": z.literal("lang_current"),
    "value": z.string(),
  })
  .strict();

export interface LangCurrentFrame {
  seq: number;
  type: "lang_current";
  value: string;
  [k: string]: unknown;
}

export const LangCurrentFrameSchema = z
  .object({
    "seq": z.number().int().gte(0),
    "type": z.literal("lang_current"),
    "value": z.string(),
  })
  .catchall(z.any()) as z.ZodType<LangCurrentFrame>;

export const EnrollOptionsWireSchema = z
  .object({
    "challenge": z.string(),
    "exclude_credential_ids": z.array(z.string()),
    "nonce": z.string(),
    "type": z.literal("enroll_options"),
    "user_id": z.string(),
    "user_name": z.string(),
  })
  .strict();

export interface EnrollOptionsFrame {
  challenge: string;
  exclude_credential_ids: string[];
  nonce: string;
  type: "enroll_options";
  user_id: string;
  user_name: string;
  [k: string]: unknown;
}

export const EnrollOptionsFrameSchema = z
  .object({
    "challenge": z.string().min(1),
    "exclude_credential_ids": z.array(z.string()),
    "nonce": z.string(),
    "type": z.literal("enroll_options"),
    "user_id": z.string(),
    "user_name": z.string(),
  })
  .catchall(z.any()) as z.ZodType<EnrollOptionsFrame>;

export const EnrollResultWireSchema = z
  .object({
    "credential_id": z.union([z.string(), z.null()]).optional(),
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("enroll_result"),
  })
  .strict();

export type EnrollResultFrame =
  | {
      credential_id: string;
      ok: true;
      reason?: never;
      type: "enroll_result";
      [k: string]: unknown;
    }
  | {
      credential_id?: never;
      ok: false;
      reason: string;
      type: "enroll_result";
      [k: string]: unknown;
    };

export const EnrollResultFrameSchema = z.union([
  z
    .object({
      "credential_id": z.string().min(1),
      "ok": z.literal(true),
      "reason": z.never().optional(),
      "type": z.literal("enroll_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "credential_id": z.never().optional(),
      "ok": z.literal(false),
      "reason": z.string(),
      "type": z.literal("enroll_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<EnrollResultFrame>;

export const PresenceRequestWireSchema = z
  .object({
    "action": z.string(),
    "allowed_credential_ids": z.array(z.string()),
    "challenge": z.string(),
    "nonce": z.string(),
    "type": z.literal("presence_request"),
  })
  .strict();

export interface PresenceRequestFrame {
  action: string;
  allowed_credential_ids: string[];
  challenge: string;
  nonce: string;
  type: "presence_request";
  [k: string]: unknown;
}

export const PresenceRequestFrameSchema = z
  .object({
    "action": z.string().min(1),
    "allowed_credential_ids": z.array(z.string()),
    "challenge": z.string().min(1),
    "nonce": z.string(),
    "type": z.literal("presence_request"),
  })
  .catchall(z.any()) as z.ZodType<PresenceRequestFrame>;

export const PresenceResultWireSchema = z
  .object({
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("presence_result"),
  })
  .strict();

export type PresenceResultFrame =
  | {
      ok: true;
      reason?: never;
      type: "presence_result";
      [k: string]: unknown;
    }
  | {
      ok: false;
      reason: string;
      type: "presence_result";
      [k: string]: unknown;
    };

export const PresenceResultFrameSchema = z.union([
  z
    .object({
      "ok": z.literal(true),
      "reason": z.never().optional(),
      "type": z.literal("presence_result"),
    })
    .catchall(z.any()),
  z
    .object({ "ok": z.literal(false), "reason": z.string(), "type": z.literal("presence_result") })
    .catchall(z.any()),
]) as z.ZodType<PresenceResultFrame>;

export const BrowserRevokeResultWireSchema = z
  .object({
    "ok": z.boolean(),
    "reason": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("browser_revoke_result"),
  })
  .strict();

export type BrowserRevokeResultFrame =
  | {
      ok: true;
      reason?: never;
      type: "browser_revoke_result";
      [k: string]: unknown;
    }
  | {
      ok: false;
      reason: string;
      type: "browser_revoke_result";
      [k: string]: unknown;
    };

export const BrowserRevokeResultFrameSchema = z.union([
  z
    .object({
      "ok": z.literal(true),
      "reason": z.never().optional(),
      "type": z.literal("browser_revoke_result"),
    })
    .catchall(z.any()),
  z
    .object({
      "ok": z.literal(false),
      "reason": z.string(),
      "type": z.literal("browser_revoke_result"),
    })
    .catchall(z.any()),
]) as z.ZodType<BrowserRevokeResultFrame>;

// Which control-frame tags have a generated reader above, and which are bare classification tags.
// scripts/check-envelope.ts holds the extension's inbound classifiers to these.
export const GENERATED_WIRE_FRAMES = {
  enclave: ["enclave_proof", "enclave_error"],
  admin: [
    "client_list_result",
    "client_revoke_result",
    "kill_status_result",
    "registration_status_result",
    "audit_read_result",
    "doctor_report_result",
  ],
  policy: ["policy_current", "policy_restrict_result", "lang_current"],
  webauthn: [
    "enroll_options",
    "enroll_result",
    "presence_request",
    "presence_result",
    "browser_revoke_result",
  ],
} as const;

export const BARE_TAG_FRAMES = {
  enclave: ["enclave_revoked"],
  admin: [],
  policy: [],
  webauthn: [],
} as const;

// The extension->host writer frames (the extension constructs these; the enforcing reader is the Rust
// serde parser). Emitted for their types: constructor sites claim conformance with `satisfies`, so a
// drifted field or tag is a compile error. Never used as runtime parsers.
export interface EnclaveChallengeWire {
  context?: string | null;
  nonce: string;
  type: "enclave_challenge";
}

export const EnclaveChallengeWireSchema = z
  .object({
    "context": z.union([z.string(), z.null()]).optional(),
    "nonce": z.string(),
    "type": z.literal("enclave_challenge"),
  })
  .strict() as z.ZodType<EnclaveChallengeWire>;

export interface EnclaveRevokeWire {
  type: "enclave_revoke";
}

export const EnclaveRevokeWireSchema = z
  .object({ "type": z.literal("enclave_revoke") })
  .strict() as z.ZodType<EnclaveRevokeWire>;

export interface ClientListWire {
  type: "client_list";
}

export const ClientListWireSchema = z
  .object({ "type": z.literal("client_list") })
  .strict() as z.ZodType<ClientListWire>;

export interface ClientRevokeWire {
  name: string;
  type: "client_revoke";
}

export const ClientRevokeWireSchema = z
  .object({ "name": z.string(), "type": z.literal("client_revoke") })
  .strict() as z.ZodType<ClientRevokeWire>;

export interface KillStatusWire {
  type: "kill_status";
}

export const KillStatusWireSchema = z
  .object({ "type": z.literal("kill_status") })
  .strict() as z.ZodType<KillStatusWire>;

export interface KillEngageWire {
  type: "kill_engage";
}

export const KillEngageWireSchema = z
  .object({ "type": z.literal("kill_engage") })
  .strict() as z.ZodType<KillEngageWire>;

export interface KillReleaseWire {
  type: "kill_release";
}

export const KillReleaseWireSchema = z
  .object({ "type": z.literal("kill_release") })
  .strict() as z.ZodType<KillReleaseWire>;

export interface AuditEventWire {
  cid?: string | null;
  detail?: string | null;
  kind: string;
  name?: string | null;
  outcome?: string | null;
  tool?: string | null;
  type: "audit_event";
}

export const AuditEventWireSchema = z
  .object({
    "cid": z.union([z.string(), z.null()]).optional(),
    "detail": z.union([z.string(), z.null()]).optional(),
    "kind": z.string(),
    "name": z.union([z.string(), z.null()]).optional(),
    "outcome": z.union([z.string(), z.null()]).optional(),
    "tool": z.union([z.string(), z.null()]).optional(),
    "type": z.literal("audit_event"),
  })
  .strict() as z.ZodType<AuditEventWire>;

export interface AuditReadWire {
  limit?: number | null;
  type: "audit_read";
}

export const AuditReadWireSchema = z
  .object({
    "limit": z.union([z.number().int().gte(1).lte(1000), z.null()]).optional(),
    "type": z.literal("audit_read"),
  })
  .strict() as z.ZodType<AuditReadWire>;

export interface DoctorReportWire {
  type: "doctor_report";
}

export const DoctorReportWireSchema = z
  .object({ "type": z.literal("doctor_report") })
  .strict() as z.ZodType<DoctorReportWire>;

export interface RegistrationStatusWire {
  type: "registration_status";
}

export const RegistrationStatusWireSchema = z
  .object({ "type": z.literal("registration_status") })
  .strict() as z.ZodType<RegistrationStatusWire>;

export interface RegistrationRepairWire {
  /**
   * @minItems 1
   */
  browsers?: ("chrome" | "chromium" | "brave" | "edge" | "vivaldi" | "opera")[] | null;
  type: "registration_repair";
}

export const RegistrationRepairWireSchema = z
  .object({
    "browsers": z
      .union([
        z.array(z.enum(["chrome", "chromium", "brave", "edge", "vivaldi", "opera"])).min(1),
        z.null(),
      ])
      .optional(),
    "type": z.literal("registration_repair"),
  })
  .strict() as z.ZodType<RegistrationRepairWire>;

export interface PolicyGetWire {
  type: "policy_get";
}

export const PolicyGetWireSchema = z
  .object({ "type": z.literal("policy_get") })
  .strict() as z.ZodType<PolicyGetWire>;

export interface PolicyRestrictWire {
  overlay: {
    cdpMode?: boolean | null;
    clickToastTimeoutMs?: number | null;
    confirmGraceMs?: number | null;
    confirmHighRiskClick?: boolean | null;
    confirmPageEval?: boolean | null;
    confirmTabClose?: boolean | null;
    disabledTools?: string[] | null;
    evalMask?: boolean | null;
    evalToastTimeoutMs?: number | null;
    fileUploadEnabled?: boolean | null;
    handleDialogEnabled?: boolean | null;
    hostReverifyMs?: number | null;
    pageEvalEnabled?: boolean | null;
    presenceConfirm?: boolean | null;
    warnPreciseSnapshot?: boolean | null;
  };
  type: "policy_restrict";
}

export const PolicyRestrictWireSchema = z
  .object({
    "overlay": z
      .object({
        "cdpMode": z.union([z.boolean(), z.null()]).optional(),
        "clickToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
        "confirmGraceMs": z.union([z.number().int().gte(0), z.null()]).optional(),
        "confirmHighRiskClick": z.union([z.boolean(), z.null()]).optional(),
        "confirmPageEval": z.union([z.boolean(), z.null()]).optional(),
        "confirmTabClose": z.union([z.boolean(), z.null()]).optional(),
        "disabledTools": z.union([z.array(z.string()), z.null()]).optional(),
        "evalMask": z.union([z.boolean(), z.null()]).optional(),
        "evalToastTimeoutMs": z.union([z.number().int().gte(0), z.null()]).optional(),
        "fileUploadEnabled": z.union([z.boolean(), z.null()]).optional(),
        "handleDialogEnabled": z.union([z.boolean(), z.null()]).optional(),
        "hostReverifyMs": z.union([z.number().int().gte(0), z.null()]).optional(),
        "pageEvalEnabled": z.union([z.boolean(), z.null()]).optional(),
        "presenceConfirm": z.union([z.boolean(), z.null()]).optional(),
        "warnPreciseSnapshot": z.union([z.boolean(), z.null()]).optional(),
      })
      .strict(),
    "type": z.literal("policy_restrict"),
  })
  .strict() as z.ZodType<PolicyRestrictWire>;

export interface LangSetWire {
  type: "lang_set";
  value: string;
}

export const LangSetWireSchema = z
  .object({ "type": z.literal("lang_set"), "value": z.string() })
  .strict() as z.ZodType<LangSetWire>;

export interface LangGetWire {
  type: "lang_get";
}

export const LangGetWireSchema = z
  .object({ "type": z.literal("lang_get") })
  .strict() as z.ZodType<LangGetWire>;

export interface EnrollBeginWire {
  type: "enroll_begin";
}

export const EnrollBeginWireSchema = z
  .object({ "type": z.literal("enroll_begin") })
  .strict() as z.ZodType<EnrollBeginWire>;

export interface EnrollFinishWire {
  attestation_object: string;
  client_data_json: string;
  type: "enroll_finish";
}

export const EnrollFinishWireSchema = z
  .object({
    "attestation_object": z.string(),
    "client_data_json": z.string(),
    "type": z.literal("enroll_finish"),
  })
  .strict() as z.ZodType<EnrollFinishWire>;

export interface PresenceBeginWire {
  action: string;
  origin: string;
  type: "presence_begin";
}

export const PresenceBeginWireSchema = z
  .object({ "action": z.string(), "origin": z.string(), "type": z.literal("presence_begin") })
  .strict() as z.ZodType<PresenceBeginWire>;

export interface PresenceAssertWire {
  authenticator_data: string;
  client_data_json: string;
  credential_id: string;
  signature: string;
  type: "presence_assert";
}

export const PresenceAssertWireSchema = z
  .object({
    "authenticator_data": z.string(),
    "client_data_json": z.string(),
    "credential_id": z.string(),
    "signature": z.string(),
    "type": z.literal("presence_assert"),
  })
  .strict() as z.ZodType<PresenceAssertWire>;

export interface PresenceConfirmWire {
  nonce: string;
  type: "presence_confirm";
}

export const PresenceConfirmWireSchema = z
  .object({ "nonce": z.string(), "type": z.literal("presence_confirm") })
  .strict() as z.ZodType<PresenceConfirmWire>;

export interface BrowserRevokeWire {
  type: "browser_revoke";
}

export const BrowserRevokeWireSchema = z
  .object({ "type": z.literal("browser_revoke") })
  .strict() as z.ZodType<BrowserRevokeWire>;

// Which extension->host frames have a generated writer schema above.
export const GENERATED_WRITER_FRAMES = {
  enclave: ["enclave_challenge", "enclave_revoke"],
  admin: [
    "client_list",
    "client_revoke",
    "kill_status",
    "kill_engage",
    "kill_release",
    "audit_event",
    "audit_read",
    "doctor_report",
    "registration_status",
    "registration_repair",
  ],
  policy: ["policy_get", "policy_restrict", "lang_set", "lang_get"],
  webauthn: [
    "enroll_begin",
    "enroll_finish",
    "presence_begin",
    "presence_assert",
    "presence_confirm",
    "browser_revoke",
  ],
} as const;
