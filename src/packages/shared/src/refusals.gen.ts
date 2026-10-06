// GENERATED from the Rust core (src/packages/core/src/webauthn/refusal.rs
// RefusalCode) by scripts/gen-ops.ts - DO NOT EDIT. Add the variant, then run
// `moon run gen`.
//
// Every reason code a refused presence_result or enroll_result can carry; the "<code>: <detail>" form keeps
// the code first. The extension's pages key their sentences on this union (lib/refusals.ts), so a
// code the host adds has no sentence until a row is added there, and that is a type error until it is.

export const REFUSAL_CODES = [
  "encoding",
  "authdata_too_short",
  "authdata_reserved_flags",
  "authdata_extensions",
  "authdata_backup_state_without_eligibility",
  "authdata_attested_truncated",
  "authdata_trailing_bytes",
  "credential_id_invalid",
  "public_key_invalid",
  "unexpected_attested_credential",
  "rp_id_mismatch",
  "user_not_present",
  "sign_count_not_increased",
  "backup_eligibility_changed",
  "client_data_malformed",
  "client_data_type",
  "challenge_mismatch",
  "origin_mismatch",
  "cross_origin",
  "signature_malformed",
  "signature_invalid",
  "attestation_malformed",
  "attestation_trailing_bytes",
  "attestation_format",
  "attestation_statement_not_empty",
  "no_attested_credential",
  "not_interactive",
  "declined",
  "io_error",
  "credential_not_enrolled",
  "wrong_browser_label",
  "software_confirmation_not_allowed",
  "request_mismatch",
  "store_error",
  "presence_required",
  "nonce",
  "no_request_outstanding",
  "no_enrollment_outstanding",
  "machine_already_enrolled",
  "not_enrolled",
  "invalid_action",
  "invalid_origin",
] as const;

export type RefusalCode = (typeof REFUSAL_CODES)[number];
