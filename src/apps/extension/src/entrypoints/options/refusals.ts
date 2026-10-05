import type { MessageKey } from "@/lib/i18n";

// The sentences the options page shows for a refused WebAuthn step. The host's presence_result and
// enroll_result carry a stable snake_case code (src/packages/core/src/presence/mod.rs, webauthn/refusal.rs,
// native_host/presence.rs), sometimes followed by ": <detail>"; the browser's own ceremony failures are
// DOMException names. Both end here as one lowercase phrase that fits after "Enrollment refused:" or
// "Release refused:". tests/entrypoints/refusals.test.ts holds this table to the host's roster, so a code the
// host can emit never reaches the user bare.
//
//   store_error: disk full          -> the store sentence, "(disk full)" appended
//   authdata_reserved_flags         -> the malformed-answer sentence, naming the code
//   some_future_code                -> "the host refused with code some_future_code"
//   native host not connected       -> as it came: the worker's own refusals are phrases already

const MALFORMED_ANSWER: MessageKey = "webauthn.reason_malformed_answer";
const WRONG_ORIGIN: MessageKey = "webauthn.reason_wrong_origin";

const REASON_KEYS: Readonly<Record<string, MessageKey>> = {
  // presence/mod.rs PresenceError::code and native_host/presence.rs
  presence_required: "webauthn.reason_presence_required",
  software_confirmation_not_allowed: "webauthn.reason_software_confirmation_not_allowed",
  request_mismatch: "webauthn.reason_request_mismatch",
  credential_not_enrolled: "webauthn.reason_credential_not_enrolled",
  wrong_browser_label: "webauthn.reason_wrong_browser_label",
  no_request_outstanding: "webauthn.reason_no_request_outstanding",
  no_enrollment_outstanding: "webauthn.reason_no_enrollment_outstanding",
  machine_already_enrolled: "webauthn.reason_machine_already_enrolled",
  store_error: "webauthn.reason_store_error",
  nonce: "webauthn.reason_nonce",
  not_interactive: "webauthn.reason_terminal",
  declined: "webauthn.reason_terminal",
  io_error: "webauthn.reason_terminal",
  // webauthn/refusal.rs Refusal::code
  sign_count_not_increased: "webauthn.reason_sign_count_not_increased",
  challenge_mismatch: "webauthn.reason_challenge_mismatch",
  signature_invalid: "webauthn.reason_signature_invalid",
  user_not_present: "webauthn.reason_user_not_present",
  backup_eligibility_changed: "webauthn.reason_backup_eligibility_changed",
  rp_id_mismatch: WRONG_ORIGIN,
  origin_mismatch: WRONG_ORIGIN,
  cross_origin: WRONG_ORIGIN,
  encoding: MALFORMED_ANSWER,
  authdata_too_short: MALFORMED_ANSWER,
  authdata_reserved_flags: MALFORMED_ANSWER,
  authdata_extensions: MALFORMED_ANSWER,
  authdata_backup_state_without_eligibility: MALFORMED_ANSWER,
  authdata_attested_truncated: MALFORMED_ANSWER,
  authdata_trailing_bytes: MALFORMED_ANSWER,
  credential_id_invalid: MALFORMED_ANSWER,
  public_key_invalid: MALFORMED_ANSWER,
  unexpected_attested_credential: MALFORMED_ANSWER,
  no_attested_credential: MALFORMED_ANSWER,
  client_data_malformed: MALFORMED_ANSWER,
  client_data_type: MALFORMED_ANSWER,
  signature_malformed: MALFORMED_ANSWER,
  attestation_malformed: MALFORMED_ANSWER,
  attestation_trailing_bytes: MALFORMED_ANSWER,
  attestation_format: MALFORMED_ANSWER,
  attestation_statement_not_empty: MALFORMED_ANSWER,
  // the browser's ceremony (ceremonyFailure below)
  prompt_dismissed: "webauthn.reason_prompt_dismissed",
  credential_exists: "webauthn.reason_credential_exists",
  no_webauthn: "webauthn.reason_no_webauthn",
};

const CODE = /^[a-z][a-z0-9_]*$/;

type Translate = (key: MessageKey, substitutions?: string[]) => string;

/** The phrase for one refusal, in the active locale. */
export function refusalSentence(t: Translate, reason: string): string {
  const colon = reason.indexOf(": ");
  const code = colon === -1 ? reason : reason.slice(0, colon);
  const detail = colon === -1 ? "" : reason.slice(colon + 2);
  const key = REASON_KEYS[code];
  if (key) {
    const sentence = t(key, [code]);
    return detail ? `${sentence} (${detail})` : sentence;
  }
  return CODE.test(reason) ? t("webauthn.reason_unknown_code", [reason]) : reason;
}

/** Whether `reason` is one the table names; the roster test reads it. */
export function hasRefusalSentence(code: string): boolean {
  return code in REASON_KEYS;
}

/** The code for a `navigator.credentials` failure: the names Chrome's WebAuthn client throws for the user
 * dismissing the prompt and for an authenticator that already holds an excluded credential, and a browser
 * with no WebAuthn API at all (the ceremony's static helpers are missing). */
export function ceremonyFailure(e: unknown): string {
  if (e instanceof DOMException) {
    if (e.name === "NotAllowedError") return "prompt_dismissed";
    if (e.name === "InvalidStateError") return "credential_exists";
    return e.message;
  }
  if (e instanceof ReferenceError || e instanceof TypeError) return "no_webauthn";
  return e instanceof Error ? e.message : String(e);
}
