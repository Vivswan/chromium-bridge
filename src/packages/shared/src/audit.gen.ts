// GENERATED from the Rust core (src/packages/core/src/audit.rs
// EXTENSION_AUDIT_KINDS) by scripts/gen-ops.ts - DO NOT EDIT. Edit the kind
// list, then run `moon run gen`.
//
// The audit kinds the host accepts over the extension's audit_event control
// frame (audit::extension_kind, ADR-0030). The extension's forwarding set
// (background/audit-log.ts) and the forwarded prefix of its audit-ring
// vocabulary (shared/enclave.ts AUDIT_EVENT_KINDS) build on this, so the two
// sides of the forwarding boundary cannot drift apart.

export const AUDIT_FORWARDED_KINDS = [
  "confirm_shown",
  "confirm_allowed",
  "confirm_denied",
  "enroll_approved",
  "enroll_rejected",
  "enroll_revoked",
] as const;

export type AuditForwardedKind = (typeof AUDIT_FORWARDED_KINDS)[number];
