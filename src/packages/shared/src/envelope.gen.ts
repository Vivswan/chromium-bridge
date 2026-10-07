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
// `moon run check-envelope`). Each validator is zod's reading of the JSON Schema beside it and each type is
// json-schema-to-typescript's reading of the same schema. The request's `args` and policy_current's
// `overlay` carry the schemas ops.gen.ts and policy.gen.ts export, inlined and held equal at generation. The
// extension->host writer schemas exist for their types only (constructor-site `satisfies`); the enforcing
// reader for those frames is the Rust serde parser.

import { z } from "zod";

// The request envelope (BridgeReq) and the response envelope (BridgeResp): the faithful bases, then the
// enforced validators the extension runs (the base plus the asymmetry table; strict like the host).
export const BridgeReqWireSchema = z.fromJSONSchema({
  "properties": {
    "args": {},
    "browser": { "type": ["string", "null"] },
    "id": { "minimum": 0, "type": "integer" },
    "op": { "type": "string" },
  },
  "required": ["id", "args", "op"],
  "type": "object",
  "additionalProperties": false,
});

export const BridgeRespWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "data": {},
    "error": { "type": ["string", "null"] },
    "id": { "minimum": 0, "type": "integer" },
    "ok": { "type": "boolean" },
  },
  "required": ["id", "ok"],
  "type": "object",
});

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

export const BridgeReqSchema = z.fromJSONSchema({
  "properties": {
    "args": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "tabId": { "maximum": 9007199254740991, "minimum": -9007199254740991, "type": "integer" },
        "url": { "type": "string" },
        "ref": { "type": "string" },
        "selector": { "type": "string" },
        "value": { "type": "string" },
        "direction": { "type": "string" },
        "pixels": { "maximum": 9007199254740991, "minimum": -9007199254740991, "type": "integer" },
        "nav": { "type": "boolean" },
        "text": { "type": "string" },
        "timeoutMs": {
          "maximum": 9007199254740991,
          "minimum": -9007199254740991,
          "type": "integer",
        },
        "code": { "type": "string" },
        "frameId": { "type": "string" },
        "domain": { "type": "string" },
        "name": { "type": "string" },
        "key": { "type": "string" },
        "type": { "type": "string" },
        "keys": { "type": "string" },
        "limit": { "maximum": 9007199254740991, "minimum": -9007199254740991, "type": "integer" },
        "action": { "type": "string" },
        "promptText": { "type": "string" },
        "path": { "type": "string" },
      },
      "required": [],
    },
    "browser": {
      "type": "string",
      "minLength": 1,
      "maxLength": 32,
      "pattern": "^[A-Za-z0-9._-]+$",
    },
    "id": { "anyOf": [{ "minimum": 0, "type": "integer" }, { "type": "string" }] },
    "op": { "type": "string", "minLength": 1 },
  },
  "required": ["id", "args", "op"],
  "type": "object",
  "additionalProperties": false,
}) as z.ZodType<BridgeReqEnvelope>;

export interface BridgeResp {
  data?: unknown;
  error?: string;
  id: number | string;
  ok: boolean;
}

export const BridgeRespSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "data": {},
    "error": { "type": "string" },
    "id": { "anyOf": [{ "minimum": 0, "type": "integer" }, { "type": "string" }] },
    "ok": { "type": "boolean" },
  },
  "required": ["id", "ok"],
  "type": "object",
}) as z.ZodType<BridgeResp>;

// The server->extension signal frames (BridgeSignal), one strict reader per variant: the faithful base,
// then the enforced validator the extension runs.
export const BridgeCancelWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "id": { "minimum": 0, "type": "integer" },
    "type": { "const": "cancel", "type": "string" },
  },
  "required": ["type", "id"],
  "type": "object",
});

export interface BridgeCancel {
  id: number | string;
  type: "cancel";
}

export const BridgeCancelSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "id": { "anyOf": [{ "minimum": 0, "type": "integer" }, { "type": "string" }] },
    "type": { "const": "cancel", "type": "string" },
  },
  "required": ["type", "id"],
  "type": "object",
}) as z.ZodType<BridgeCancel>;

// One trusted-client entry (allowlist::ClientEntry), embedded in client_list_result's `clients` array.
export const ClientEntryWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "added_unix": { "minimum": 0, "type": "integer" },
    "anchor": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "kind": { "const": "hash", "type": "string" },
            "value": { "type": "string" },
          },
          "required": ["kind", "value"],
          "type": "object",
        },
        {
          "additionalProperties": false,
          "properties": {
            "kind": { "const": "signer", "type": "string" },
            "value": { "type": "string" },
          },
          "required": ["kind", "value"],
          "type": "object",
        },
      ],
    },
    "name": { "type": "string" },
  },
  "required": ["name", "anchor", "added_unix"],
  "type": "object",
});

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

export const TrustedClientSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "added_unix": { "minimum": 0, "type": "integer" },
    "anchor": {
      "type": "object",
      "properties": {
        "kind": { "type": "string", "enum": ["hash", "signer"] },
        "value": { "type": "string", "minLength": 1 },
      },
      "required": ["kind", "value"],
      "additionalProperties": true,
    },
    "name": { "type": "string" },
  },
  "required": ["name", "anchor", "added_unix"],
  "type": "object",
}) as z.ZodType<TrustedClient>;

// One browser's registration row (protocol::control::RegistrationRow), embedded in registration_status_result's `browsers` array.
export const RegistrationRowWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "browser": { "type": "string" },
    "detected": { "type": "boolean" },
    "location": { "type": "string" },
    "state": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": { "kind": { "const": "missing", "type": "string" } },
          "required": ["kind"],
          "type": "object",
        },
        {
          "additionalProperties": false,
          "properties": { "kind": { "const": "ok", "type": "string" } },
          "required": ["kind"],
          "type": "object",
        },
        {
          "additionalProperties": false,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "stale", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
        {
          "additionalProperties": false,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "foreign", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
        {
          "additionalProperties": false,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "unreadable", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
      ],
    },
  },
  "required": ["browser", "detected", "state", "location"],
  "type": "object",
});

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

export const RegistrationRowSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "browser": { "type": "string" },
    "detected": { "type": "boolean" },
    "location": { "type": "string" },
    "state": {
      "anyOf": [
        {
          "additionalProperties": true,
          "properties": { "kind": { "const": "missing", "type": "string" } },
          "required": ["kind"],
          "type": "object",
        },
        {
          "additionalProperties": true,
          "properties": { "kind": { "const": "ok", "type": "string" } },
          "required": ["kind"],
          "type": "object",
        },
        {
          "additionalProperties": true,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "stale", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
        {
          "additionalProperties": true,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "foreign", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
        {
          "additionalProperties": true,
          "properties": {
            "detail": { "type": "string" },
            "kind": { "const": "unreadable", "type": "string" },
          },
          "required": ["kind", "detail"],
          "type": "object",
        },
      ],
    },
  },
  "required": ["browser", "detected", "state", "location"],
  "type": "object",
}) as z.ZodType<RegistrationRow>;

// One line of the host's audit trail (protocol::control::AuditTrailEntry), embedded in audit_read_result's `entries` array.
export const AuditTrailEntryWireSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": false,
      "properties": {
        "entry": { "const": "record", "type": "string" },
        "fields": { "type": "string" },
        "kind": { "type": "string" },
        "ts_ms": { "maximum": 9007199254740991, "minimum": 0, "type": "integer" },
      },
      "required": ["entry", "ts_ms", "kind", "fields"],
      "type": "object",
    },
    {
      "additionalProperties": false,
      "properties": {
        "entry": { "const": "unrecognized", "type": "string" },
        "text": { "type": "string" },
      },
      "required": ["entry", "text"],
      "type": "object",
    },
  ],
});

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

export const AuditTrailEntrySchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "entry": { "const": "record", "type": "string" },
        "fields": { "type": "string" },
        "kind": { "type": "string" },
        "ts_ms": { "maximum": 9007199254740991, "minimum": 0, "type": "integer" },
      },
      "required": ["entry", "ts_ms", "kind", "fields"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "entry": { "const": "unrecognized", "type": "string" },
        "text": { "type": "string" },
      },
      "required": ["entry", "text"],
      "type": "object",
    },
  ],
}) as z.ZodType<AuditTrailEntry>;

// The health report (protocol::control::HealthReport), embedded as doctor_report_result's `report`.
export const HealthReportWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "healthy": { "type": "boolean" },
    "host_key": { "type": "string" },
    "kill_switch": {
      "additionalProperties": false,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "lock_file": {
      "additionalProperties": false,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "mcp_server": {
      "additionalProperties": false,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "platform": { "type": "string" },
    "policy_baseline": {
      "additionalProperties": false,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "summary": { "type": "string" },
    "version": { "type": "string" },
  },
  "required": [
    "version",
    "platform",
    "lock_file",
    "mcp_server",
    "kill_switch",
    "policy_baseline",
    "host_key",
    "summary",
    "healthy",
  ],
  "type": "object",
});

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

export const HealthReportSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "healthy": { "type": "boolean" },
    "host_key": { "type": "string" },
    "kill_switch": {
      "additionalProperties": true,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "lock_file": {
      "additionalProperties": true,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "mcp_server": {
      "additionalProperties": true,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "platform": { "type": "string" },
    "policy_baseline": {
      "additionalProperties": true,
      "properties": {
        "details": { "items": { "type": "string" }, "type": "array" },
        "value": { "type": "string" },
      },
      "required": ["value", "details"],
      "type": "object",
    },
    "summary": { "type": "string" },
    "version": { "type": "string" },
  },
  "required": [
    "version",
    "platform",
    "lock_file",
    "mcp_server",
    "kill_switch",
    "policy_baseline",
    "host_key",
    "summary",
    "healthy",
  ],
  "type": "object",
}) as z.ZodType<HealthReport>;

// The host->extension control frames: the faithful base, then the enforced reader (the base plus the
// asymmetry table, read loose under its loose-frames rule).
export const EnclaveProofWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "key_id": { "type": "string" },
    "pubkey": { "type": "string" },
    "sig": { "type": "string" },
    "type": { "const": "enclave_proof", "type": "string" },
  },
  "required": ["type", "sig", "key_id", "pubkey"],
  "type": "object",
});

export interface EnclaveProofFrame {
  key_id: string;
  pubkey: string;
  sig: string;
  type: "enclave_proof";
  [k: string]: unknown;
}

export const EnclaveProofFrameSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "key_id": { "type": "string", "minLength": 1 },
    "pubkey": { "type": "string", "minLength": 1 },
    "sig": { "type": "string", "minLength": 1 },
    "type": { "const": "enclave_proof", "type": "string" },
  },
  "required": ["type", "sig", "key_id", "pubkey"],
  "type": "object",
}) as z.ZodType<EnclaveProofFrame>;

export const EnclaveErrorWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "reason": { "type": "string" },
    "type": { "const": "enclave_error", "type": "string" },
  },
  "required": ["type", "reason"],
  "type": "object",
});

export interface EnclaveErrorFrame {
  reason: string;
  type: "enclave_error";
  [k: string]: unknown;
}

export const EnclaveErrorFrameSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "reason": { "type": "string" },
    "type": { "const": "enclave_error", "type": "string" },
  },
  "required": ["type", "reason"],
  "type": "object",
}) as z.ZodType<EnclaveErrorFrame>;

export const ClientListResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "clients": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "added_unix": { "minimum": 0, "type": "integer" },
          "anchor": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": {
                  "kind": { "const": "hash", "type": "string" },
                  "value": { "type": "string" },
                },
                "required": ["kind", "value"],
                "type": "object",
              },
              {
                "additionalProperties": false,
                "properties": {
                  "kind": { "const": "signer", "type": "string" },
                  "value": { "type": "string" },
                },
                "required": ["kind", "value"],
                "type": "object",
              },
            ],
          },
          "name": { "type": "string" },
        },
        "required": ["name", "anchor", "added_unix"],
        "type": "object",
      },
      "type": "array",
    },
    "enrolled": { "type": "boolean" },
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "type": { "const": "client_list_result", "type": "string" },
  },
  "required": ["type", "ok", "enrolled", "clients"],
  "type": "object",
});

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

export const ClientListResultSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "clients": {
      "items": {
        "additionalProperties": true,
        "properties": {
          "added_unix": { "minimum": 0, "type": "integer" },
          "anchor": {
            "type": "object",
            "properties": {
              "kind": { "type": "string", "enum": ["hash", "signer"] },
              "value": { "type": "string", "minLength": 1 },
            },
            "required": ["kind", "value"],
            "additionalProperties": true,
          },
          "name": { "type": "string" },
        },
        "required": ["name", "anchor", "added_unix"],
        "type": "object",
      },
      "type": "array",
    },
    "enrolled": { "type": "boolean" },
    "error": { "type": "string" },
    "ok": { "type": "boolean" },
    "type": { "const": "client_list_result", "type": "string" },
  },
  "required": ["type", "ok", "enrolled", "clients"],
  "type": "object",
}) as z.ZodType<ClientListResult>;

export const ClientRevokeResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "type": { "const": "client_revoke_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

export interface ClientRevokeResult {
  error?: string;
  ok: boolean;
  type: "client_revoke_result";
  [k: string]: unknown;
}

export const ClientRevokeResultSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "error": { "type": "string" },
    "ok": { "type": "boolean" },
    "type": { "const": "client_revoke_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
}) as z.ZodType<ClientRevokeResult>;

export const KillStatusResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "error": { "type": ["string", "null"] },
    "killed": { "type": ["boolean", "null"] },
    "ok": { "type": "boolean" },
    "type": { "const": "kill_status_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

export interface KillStatusResult {
  error?: string;
  killed?: boolean;
  ok: boolean;
  type: "kill_status_result";
  [k: string]: unknown;
}

export const KillStatusResultSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "error": { "type": "string" },
    "killed": { "type": "boolean" },
    "ok": { "type": "boolean" },
    "type": { "const": "kill_status_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
}) as z.ZodType<KillStatusResult>;

export const RegistrationStatusResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "browsers": {
      "items": {
        "additionalProperties": false,
        "properties": {
          "browser": { "type": "string" },
          "detected": { "type": "boolean" },
          "location": { "type": "string" },
          "state": {
            "anyOf": [
              {
                "additionalProperties": false,
                "properties": { "kind": { "const": "missing", "type": "string" } },
                "required": ["kind"],
                "type": "object",
              },
              {
                "additionalProperties": false,
                "properties": { "kind": { "const": "ok", "type": "string" } },
                "required": ["kind"],
                "type": "object",
              },
              {
                "additionalProperties": false,
                "properties": {
                  "detail": { "type": "string" },
                  "kind": { "const": "stale", "type": "string" },
                },
                "required": ["kind", "detail"],
                "type": "object",
              },
              {
                "additionalProperties": false,
                "properties": {
                  "detail": { "type": "string" },
                  "kind": { "const": "foreign", "type": "string" },
                },
                "required": ["kind", "detail"],
                "type": "object",
              },
              {
                "additionalProperties": false,
                "properties": {
                  "detail": { "type": "string" },
                  "kind": { "const": "unreadable", "type": "string" },
                },
                "required": ["kind", "detail"],
                "type": "object",
              },
            ],
          },
        },
        "required": ["browser", "detected", "state", "location"],
        "type": "object",
      },
      "type": ["array", "null"],
    },
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "type": { "const": "registration_status_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const RegistrationStatusResultSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "browsers": {
          "items": {
            "additionalProperties": true,
            "properties": {
              "browser": { "type": "string" },
              "detected": { "type": "boolean" },
              "location": { "type": "string" },
              "state": {
                "anyOf": [
                  {
                    "additionalProperties": true,
                    "properties": { "kind": { "const": "missing", "type": "string" } },
                    "required": ["kind"],
                    "type": "object",
                  },
                  {
                    "additionalProperties": true,
                    "properties": { "kind": { "const": "ok", "type": "string" } },
                    "required": ["kind"],
                    "type": "object",
                  },
                  {
                    "additionalProperties": true,
                    "properties": {
                      "detail": { "type": "string" },
                      "kind": { "const": "stale", "type": "string" },
                    },
                    "required": ["kind", "detail"],
                    "type": "object",
                  },
                  {
                    "additionalProperties": true,
                    "properties": {
                      "detail": { "type": "string" },
                      "kind": { "const": "foreign", "type": "string" },
                    },
                    "required": ["kind", "detail"],
                    "type": "object",
                  },
                  {
                    "additionalProperties": true,
                    "properties": {
                      "detail": { "type": "string" },
                      "kind": { "const": "unreadable", "type": "string" },
                    },
                    "required": ["kind", "detail"],
                    "type": "object",
                  },
                ],
              },
            },
            "required": ["browser", "detected", "state", "location"],
            "type": "object",
          },
          "type": "array",
        },
        "error": false,
        "ok": { "type": "boolean", "const": true },
        "type": { "const": "registration_status_result", "type": "string" },
      },
      "required": ["type", "ok", "browsers"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "browsers": false,
        "error": { "type": "string" },
        "ok": { "type": "boolean", "const": false },
        "type": { "const": "registration_status_result", "type": "string" },
      },
      "required": ["type", "ok", "error"],
      "type": "object",
    },
  ],
}) as z.ZodType<RegistrationStatusResult>;

export const AuditReadResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "entries": {
      "items": {
        "anyOf": [
          {
            "additionalProperties": false,
            "properties": {
              "entry": { "const": "record", "type": "string" },
              "fields": { "type": "string" },
              "kind": { "type": "string" },
              "ts_ms": { "maximum": 9007199254740991, "minimum": 0, "type": "integer" },
            },
            "required": ["entry", "ts_ms", "kind", "fields"],
            "type": "object",
          },
          {
            "additionalProperties": false,
            "properties": {
              "entry": { "const": "unrecognized", "type": "string" },
              "text": { "type": "string" },
            },
            "required": ["entry", "text"],
            "type": "object",
          },
        ],
      },
      "type": ["array", "null"],
    },
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "older": { "minimum": 0, "type": ["integer", "null"] },
    "path": { "type": ["string", "null"] },
    "type": { "const": "audit_read_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const AuditReadResultSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "entries": {
          "items": {
            "anyOf": [
              {
                "additionalProperties": true,
                "properties": {
                  "entry": { "const": "record", "type": "string" },
                  "fields": { "type": "string" },
                  "kind": { "type": "string" },
                  "ts_ms": { "maximum": 9007199254740991, "minimum": 0, "type": "integer" },
                },
                "required": ["entry", "ts_ms", "kind", "fields"],
                "type": "object",
              },
              {
                "additionalProperties": true,
                "properties": {
                  "entry": { "const": "unrecognized", "type": "string" },
                  "text": { "type": "string" },
                },
                "required": ["entry", "text"],
                "type": "object",
              },
            ],
          },
          "type": "array",
        },
        "error": false,
        "ok": { "type": "boolean", "const": true },
        "older": { "minimum": 0, "type": "integer" },
        "path": { "type": "string" },
        "type": { "const": "audit_read_result", "type": "string" },
      },
      "required": ["type", "ok", "entries", "older", "path"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "entries": false,
        "error": { "type": "string" },
        "ok": { "type": "boolean", "const": false },
        "older": false,
        "path": false,
        "type": { "const": "audit_read_result", "type": "string" },
      },
      "required": ["type", "ok", "error"],
      "type": "object",
    },
  ],
}) as z.ZodType<AuditReadResult>;

export const DoctorReportResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "report": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "healthy": { "type": "boolean" },
            "host_key": { "type": "string" },
            "kill_switch": {
              "additionalProperties": false,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "lock_file": {
              "additionalProperties": false,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "mcp_server": {
              "additionalProperties": false,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "platform": { "type": "string" },
            "policy_baseline": {
              "additionalProperties": false,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "summary": { "type": "string" },
            "version": { "type": "string" },
          },
          "required": [
            "version",
            "platform",
            "lock_file",
            "mcp_server",
            "kill_switch",
            "policy_baseline",
            "host_key",
            "summary",
            "healthy",
          ],
          "type": "object",
        },
        { "type": "null" },
      ],
    },
    "type": { "const": "doctor_report_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const DoctorReportResultSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "error": false,
        "ok": { "type": "boolean", "const": true },
        "report": {
          "additionalProperties": true,
          "properties": {
            "healthy": { "type": "boolean" },
            "host_key": { "type": "string" },
            "kill_switch": {
              "additionalProperties": true,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "lock_file": {
              "additionalProperties": true,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "mcp_server": {
              "additionalProperties": true,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "platform": { "type": "string" },
            "policy_baseline": {
              "additionalProperties": true,
              "properties": {
                "details": { "items": { "type": "string" }, "type": "array" },
                "value": { "type": "string" },
              },
              "required": ["value", "details"],
              "type": "object",
            },
            "summary": { "type": "string" },
            "version": { "type": "string" },
          },
          "required": [
            "version",
            "platform",
            "lock_file",
            "mcp_server",
            "kill_switch",
            "policy_baseline",
            "host_key",
            "summary",
            "healthy",
          ],
          "type": "object",
        },
        "type": { "const": "doctor_report_result", "type": "string" },
      },
      "required": ["type", "ok", "report"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "error": { "type": "string" },
        "ok": { "type": "boolean", "const": false },
        "report": false,
        "type": { "const": "doctor_report_result", "type": "string" },
      },
      "required": ["type", "ok", "error"],
      "type": "object",
    },
  ],
}) as z.ZodType<DoctorReportResult>;

export const PolicyCurrentWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "baseline": { "type": ["string", "null"] },
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "overlay": {
      "anyOf": [
        {
          "additionalProperties": false,
          "properties": {
            "cdpMode": { "type": ["boolean", "null"] },
            "clickToastTimeoutMs": { "minimum": 0, "type": ["integer", "null"] },
            "confirmGraceMs": { "minimum": 0, "type": ["integer", "null"] },
            "confirmHighRiskClick": { "type": ["boolean", "null"] },
            "confirmPageEval": { "type": ["boolean", "null"] },
            "confirmTabClose": { "type": ["boolean", "null"] },
            "disabledTools": { "items": { "type": "string" }, "type": ["array", "null"] },
            "evalMask": { "type": ["boolean", "null"] },
            "evalToastTimeoutMs": { "minimum": 0, "type": ["integer", "null"] },
            "fileUploadEnabled": { "type": ["boolean", "null"] },
            "handleDialogEnabled": { "type": ["boolean", "null"] },
            "hostReverifyMs": { "minimum": 0, "type": ["integer", "null"] },
            "pageEvalEnabled": { "type": ["boolean", "null"] },
            "presenceConfirm": { "type": ["boolean", "null"] },
            "warnPreciseSnapshot": { "type": ["boolean", "null"] },
          },
          "type": "object",
        },
        { "type": "null" },
      ],
    },
    "sig": { "type": ["string", "null"] },
    "type": { "const": "policy_current", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const PolicyCurrentFrameSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "baseline": { "type": "string", "minLength": 1 },
        "error": false,
        "ok": { "type": "boolean", "const": true },
        "overlay": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "cdpMode": { "type": "boolean" },
            "fileUploadEnabled": { "type": "boolean" },
            "handleDialogEnabled": { "type": "boolean" },
            "pageEvalEnabled": { "type": "boolean" },
            "confirmHighRiskClick": { "type": "boolean" },
            "confirmPageEval": { "type": "boolean" },
            "presenceConfirm": { "type": "boolean" },
            "confirmTabClose": { "type": "boolean" },
            "warnPreciseSnapshot": { "type": "boolean" },
            "evalMask": { "type": "boolean" },
            "hostReverifyMs": { "type": "integer", "minimum": 0 },
            "confirmGraceMs": { "type": "integer", "minimum": 0 },
            "clickToastTimeoutMs": { "type": "integer", "minimum": 0 },
            "evalToastTimeoutMs": { "type": "integer", "minimum": 0 },
            "disabledTools": {
              "type": "array",
              "items": { "type": "string", "minLength": 1, "maxLength": 128 },
              "maxItems": 256,
            },
          },
          "required": [],
        },
        "sig": { "type": "string", "minLength": 1 },
        "type": { "const": "policy_current", "type": "string" },
      },
      "required": ["type", "ok", "baseline"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "baseline": false,
        "error": { "type": "string" },
        "ok": { "type": "boolean", "const": false },
        "overlay": false,
        "sig": false,
        "type": { "const": "policy_current", "type": "string" },
      },
      "required": ["type", "ok", "error"],
      "type": "object",
    },
  ],
}) as z.ZodType<PolicyCurrentFrame>;

export const PolicyRestrictResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "error": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "type": { "const": "policy_restrict_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const PolicyRestrictResultSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "error": false,
        "ok": { "type": "boolean", "const": true },
        "type": { "const": "policy_restrict_result", "type": "string" },
      },
      "required": ["type", "ok"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "error": { "type": "string" },
        "ok": { "type": "boolean", "const": false },
        "type": { "const": "policy_restrict_result", "type": "string" },
      },
      "required": ["type", "ok", "error"],
      "type": "object",
    },
  ],
}) as z.ZodType<PolicyRestrictResult>;

export const LangCurrentWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "seq": { "minimum": 0, "type": "integer" },
    "type": { "const": "lang_current", "type": "string" },
    "value": { "type": "string" },
  },
  "required": ["type", "value", "seq"],
  "type": "object",
});

export interface LangCurrentFrame {
  seq: number;
  type: "lang_current";
  value: string;
  [k: string]: unknown;
}

export const LangCurrentFrameSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "seq": { "minimum": 0, "type": "integer" },
    "type": { "const": "lang_current", "type": "string" },
    "value": { "type": "string" },
  },
  "required": ["type", "value", "seq"],
  "type": "object",
}) as z.ZodType<LangCurrentFrame>;

export const EnrollOptionsWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "challenge": { "type": "string" },
    "exclude_credential_ids": { "items": { "type": "string" }, "type": "array" },
    "nonce": { "type": "string" },
    "type": { "const": "enroll_options", "type": "string" },
    "user_id": { "type": "string" },
    "user_name": { "type": "string" },
  },
  "required": ["type", "challenge", "nonce", "user_id", "user_name", "exclude_credential_ids"],
  "type": "object",
});

export interface EnrollOptionsFrame {
  challenge: string;
  exclude_credential_ids: string[];
  nonce: string;
  type: "enroll_options";
  user_id: string;
  user_name: string;
  [k: string]: unknown;
}

export const EnrollOptionsFrameSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "challenge": { "type": "string", "minLength": 1 },
    "exclude_credential_ids": { "items": { "type": "string" }, "type": "array" },
    "nonce": { "type": "string" },
    "type": { "const": "enroll_options", "type": "string" },
    "user_id": { "type": "string" },
    "user_name": { "type": "string" },
  },
  "required": ["type", "challenge", "nonce", "user_id", "user_name", "exclude_credential_ids"],
  "type": "object",
}) as z.ZodType<EnrollOptionsFrame>;

export const EnrollResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "credential_id": { "type": ["string", "null"] },
    "ok": { "type": "boolean" },
    "reason": { "type": ["string", "null"] },
    "type": { "const": "enroll_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const EnrollResultFrameSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "credential_id": { "type": "string", "minLength": 1 },
        "ok": { "type": "boolean", "const": true },
        "reason": false,
        "type": { "const": "enroll_result", "type": "string" },
      },
      "required": ["type", "ok", "credential_id"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "credential_id": false,
        "ok": { "type": "boolean", "const": false },
        "reason": { "type": "string" },
        "type": { "const": "enroll_result", "type": "string" },
      },
      "required": ["type", "ok", "reason"],
      "type": "object",
    },
  ],
}) as z.ZodType<EnrollResultFrame>;

export const PresenceRequestWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "action": { "type": "string" },
    "allowed_credential_ids": { "items": { "type": "string" }, "type": "array" },
    "challenge": { "type": "string" },
    "nonce": { "type": "string" },
    "type": { "const": "presence_request", "type": "string" },
  },
  "required": ["type", "challenge", "nonce", "action", "allowed_credential_ids"],
  "type": "object",
});

export interface PresenceRequestFrame {
  action: string;
  allowed_credential_ids: string[];
  challenge: string;
  nonce: string;
  type: "presence_request";
  [k: string]: unknown;
}

export const PresenceRequestFrameSchema = z.fromJSONSchema({
  "additionalProperties": true,
  "properties": {
    "action": { "type": "string", "minLength": 1 },
    "allowed_credential_ids": { "items": { "type": "string" }, "type": "array" },
    "challenge": { "type": "string", "minLength": 1 },
    "nonce": { "type": "string" },
    "type": { "const": "presence_request", "type": "string" },
  },
  "required": ["type", "challenge", "nonce", "action", "allowed_credential_ids"],
  "type": "object",
}) as z.ZodType<PresenceRequestFrame>;

export const PresenceResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "ok": { "type": "boolean" },
    "reason": { "type": ["string", "null"] },
    "type": { "const": "presence_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const PresenceResultFrameSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "ok": { "type": "boolean", "const": true },
        "reason": false,
        "type": { "const": "presence_result", "type": "string" },
      },
      "required": ["type", "ok"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "ok": { "type": "boolean", "const": false },
        "reason": { "type": "string" },
        "type": { "const": "presence_result", "type": "string" },
      },
      "required": ["type", "ok", "reason"],
      "type": "object",
    },
  ],
}) as z.ZodType<PresenceResultFrame>;

export const BrowserRevokeResultWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "ok": { "type": "boolean" },
    "reason": { "type": ["string", "null"] },
    "type": { "const": "browser_revoke_result", "type": "string" },
  },
  "required": ["type", "ok"],
  "type": "object",
});

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

export const BrowserRevokeResultFrameSchema = z.fromJSONSchema({
  "anyOf": [
    {
      "additionalProperties": true,
      "properties": {
        "ok": { "type": "boolean", "const": true },
        "reason": false,
        "type": { "const": "browser_revoke_result", "type": "string" },
      },
      "required": ["type", "ok"],
      "type": "object",
    },
    {
      "additionalProperties": true,
      "properties": {
        "ok": { "type": "boolean", "const": false },
        "reason": { "type": "string" },
        "type": { "const": "browser_revoke_result", "type": "string" },
      },
      "required": ["type", "ok", "reason"],
      "type": "object",
    },
  ],
}) as z.ZodType<BrowserRevokeResultFrame>;

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

export const EnclaveChallengeWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "context": { "type": ["string", "null"] },
    "nonce": { "type": "string" },
    "type": { "const": "enclave_challenge", "type": "string" },
  },
  "required": ["type", "nonce"],
  "type": "object",
}) as z.ZodType<EnclaveChallengeWire>;

export interface EnclaveRevokeWire {
  type: "enclave_revoke";
}

export const EnclaveRevokeWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "enclave_revoke", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<EnclaveRevokeWire>;

export interface ClientListWire {
  type: "client_list";
}

export const ClientListWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "client_list", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<ClientListWire>;

export interface ClientRevokeWire {
  name: string;
  type: "client_revoke";
}

export const ClientRevokeWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "name": { "type": "string" },
    "type": { "const": "client_revoke", "type": "string" },
  },
  "required": ["type", "name"],
  "type": "object",
}) as z.ZodType<ClientRevokeWire>;

export interface KillStatusWire {
  type: "kill_status";
}

export const KillStatusWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "kill_status", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<KillStatusWire>;

export interface KillEngageWire {
  type: "kill_engage";
}

export const KillEngageWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "kill_engage", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<KillEngageWire>;

export interface KillReleaseWire {
  type: "kill_release";
}

export const KillReleaseWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "kill_release", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<KillReleaseWire>;

export interface AuditEventWire {
  cid?: string | null;
  detail?: string | null;
  kind: string;
  name?: string | null;
  outcome?: string | null;
  tool?: string | null;
  type: "audit_event";
}

export const AuditEventWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "cid": { "type": ["string", "null"] },
    "detail": { "type": ["string", "null"] },
    "kind": { "type": "string" },
    "name": { "type": ["string", "null"] },
    "outcome": { "type": ["string", "null"] },
    "tool": { "type": ["string", "null"] },
    "type": { "const": "audit_event", "type": "string" },
  },
  "required": ["type", "kind"],
  "type": "object",
}) as z.ZodType<AuditEventWire>;

export interface AuditReadWire {
  limit?: number | null;
  type: "audit_read";
}

export const AuditReadWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "limit": { "maximum": 1000, "minimum": 1, "type": ["integer", "null"] },
    "type": { "const": "audit_read", "type": "string" },
  },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<AuditReadWire>;

export interface DoctorReportWire {
  type: "doctor_report";
}

export const DoctorReportWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "doctor_report", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<DoctorReportWire>;

export interface RegistrationStatusWire {
  type: "registration_status";
}

export const RegistrationStatusWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "registration_status", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<RegistrationStatusWire>;

export interface RegistrationRepairWire {
  /**
   * @minItems 1
   */
  browsers?: ("chrome" | "chromium" | "brave" | "edge" | "vivaldi" | "opera")[] | null;
  type: "registration_repair";
}

export const RegistrationRepairWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "browsers": {
      "items": {
        "enum": ["chrome", "chromium", "brave", "edge", "vivaldi", "opera"],
        "type": "string",
      },
      "minItems": 1,
      "type": ["array", "null"],
    },
    "type": { "const": "registration_repair", "type": "string" },
  },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<RegistrationRepairWire>;

export interface PolicyGetWire {
  type: "policy_get";
}

export const PolicyGetWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "policy_get", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<PolicyGetWire>;

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

export const PolicyRestrictWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "overlay": {
      "additionalProperties": false,
      "properties": {
        "cdpMode": { "type": ["boolean", "null"] },
        "clickToastTimeoutMs": { "minimum": 0, "type": ["integer", "null"] },
        "confirmGraceMs": { "minimum": 0, "type": ["integer", "null"] },
        "confirmHighRiskClick": { "type": ["boolean", "null"] },
        "confirmPageEval": { "type": ["boolean", "null"] },
        "confirmTabClose": { "type": ["boolean", "null"] },
        "disabledTools": { "items": { "type": "string" }, "type": ["array", "null"] },
        "evalMask": { "type": ["boolean", "null"] },
        "evalToastTimeoutMs": { "minimum": 0, "type": ["integer", "null"] },
        "fileUploadEnabled": { "type": ["boolean", "null"] },
        "handleDialogEnabled": { "type": ["boolean", "null"] },
        "hostReverifyMs": { "minimum": 0, "type": ["integer", "null"] },
        "pageEvalEnabled": { "type": ["boolean", "null"] },
        "presenceConfirm": { "type": ["boolean", "null"] },
        "warnPreciseSnapshot": { "type": ["boolean", "null"] },
      },
      "type": "object",
    },
    "type": { "const": "policy_restrict", "type": "string" },
  },
  "required": ["type", "overlay"],
  "type": "object",
}) as z.ZodType<PolicyRestrictWire>;

export interface LangSetWire {
  type: "lang_set";
  value: string;
}

export const LangSetWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "type": { "const": "lang_set", "type": "string" },
    "value": { "type": "string" },
  },
  "required": ["type", "value"],
  "type": "object",
}) as z.ZodType<LangSetWire>;

export interface LangGetWire {
  type: "lang_get";
}

export const LangGetWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "lang_get", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<LangGetWire>;

export interface EnrollBeginWire {
  type: "enroll_begin";
}

export const EnrollBeginWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "enroll_begin", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<EnrollBeginWire>;

export interface EnrollFinishWire {
  attestation_object: string;
  client_data_json: string;
  type: "enroll_finish";
}

export const EnrollFinishWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "attestation_object": { "type": "string" },
    "client_data_json": { "type": "string" },
    "type": { "const": "enroll_finish", "type": "string" },
  },
  "required": ["type", "attestation_object", "client_data_json"],
  "type": "object",
}) as z.ZodType<EnrollFinishWire>;

export interface PresenceBeginWire {
  action: string;
  origin: string;
  type: "presence_begin";
}

export const PresenceBeginWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "action": { "type": "string" },
    "origin": { "type": "string" },
    "type": { "const": "presence_begin", "type": "string" },
  },
  "required": ["type", "action", "origin"],
  "type": "object",
}) as z.ZodType<PresenceBeginWire>;

export interface PresenceAssertWire {
  authenticator_data: string;
  client_data_json: string;
  credential_id: string;
  signature: string;
  type: "presence_assert";
}

export const PresenceAssertWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "authenticator_data": { "type": "string" },
    "client_data_json": { "type": "string" },
    "credential_id": { "type": "string" },
    "signature": { "type": "string" },
    "type": { "const": "presence_assert", "type": "string" },
  },
  "required": ["type", "credential_id", "authenticator_data", "client_data_json", "signature"],
  "type": "object",
}) as z.ZodType<PresenceAssertWire>;

export interface PresenceConfirmWire {
  nonce: string;
  type: "presence_confirm";
}

export const PresenceConfirmWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": {
    "nonce": { "type": "string" },
    "type": { "const": "presence_confirm", "type": "string" },
  },
  "required": ["type", "nonce"],
  "type": "object",
}) as z.ZodType<PresenceConfirmWire>;

export interface BrowserRevokeWire {
  type: "browser_revoke";
}

export const BrowserRevokeWireSchema = z.fromJSONSchema({
  "additionalProperties": false,
  "properties": { "type": { "const": "browser_revoke", "type": "string" } },
  "required": ["type"],
  "type": "object",
}) as z.ZodType<BrowserRevokeWire>;

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
