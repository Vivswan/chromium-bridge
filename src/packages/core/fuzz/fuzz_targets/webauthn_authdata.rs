#![no_main]
//! The WebAuthn authenticatorData layout parser, with the attestation object and the assertion verifier
//! fed the same bytes; the body is `targets::webauthn_authdata`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| chromium_bridge_fuzz::targets::webauthn_authdata(data));
