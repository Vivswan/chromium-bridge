#![no_main]
//! Fuzz the WebAuthn byte parsers the extension's frames feed: authenticatorData (the one hand-written
//! layout parser), the attestation object, the COSE key, and the assertion verifier over them. Every
//! field is attacker-controlled once a page or a substituted host speaks to the native host, so each must
//! fail closed on hostile bytes, never panic. Oracles beyond no-panic: a credential key parsed out of
//! attested data round-trips through its storage spelling (the bytes trust.json will hold), and the
//! base64url decoder accepts exactly one spelling per byte string (decode then encode reproduces the input).
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use chromium_bridge_core::ipc::BrowserLabel;
use chromium_bridge_core::webauthn::{
    base64url_decode, base64url_encode, parse_registration, verify_assertion, Action, Assertion,
    AuthenticatorData, CosePublicKey, Credential, CredentialId, Nonce, Registration, RpId,
    Statement, StatementDomain,
};

#[derive(Arbitrary, Debug)]
struct Input {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
    attestation_object: Vec<u8>,
    sign_count: u32,
    encoded: String,
}

/// A fixed, obviously synthetic P-256 point: the generator of the curve, which is on the curve by
/// definition, so the verifier has a key to check hostile signatures against.
const GENERATOR_SEC1: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

fuzz_target!(|input: Input| {
    if let Ok(parsed) = AuthenticatorData::parse(&input.authenticator_data) {
        if let Some(attested) = parsed.attested {
            assert_eq!(
                CosePublicKey::from_sec1(&attested.public_key.to_sec1_bytes()),
                Ok(attested.public_key),
                "a parsed credential key must round-trip through its storage spelling"
            );
        }
    }
    let statement = Statement {
        domain: StatementDomain::Presence,
        browser_label: BrowserLabel::default_label(),
        action: Action::parse("fuzz").expect("a fixed valid action"),
        nonce: Nonce::parse("fuzz-nonce").expect("a fixed valid nonce"),
    };
    let credential = Credential {
        id: CredentialId::parse(vec![0xc1; 16]).expect("a fixed valid id"),
        public_key: CosePublicKey::from_sec1(&GENERATOR_SEC1).expect("the curve generator is on the curve"),
        sign_count: input.sign_count,
        backup_eligible: false,
    };
    let _ = verify_assertion(
        &credential,
        &statement,
        &RpId::pinned(),
        &Assertion {
            authenticator_data: input.authenticator_data.clone(),
            client_data_json: input.client_data_json.clone(),
            signature: input.signature,
        },
    );
    let enrollment = Statement {
        domain: StatementDomain::Enrollment,
        ..statement
    };
    let _ = parse_registration(
        &enrollment,
        &RpId::pinned(),
        &Registration {
            attestation_object: input.attestation_object,
            client_data_json: input.client_data_json,
        },
    );
    if let Ok(bytes) = base64url_decode(&input.encoded) {
        assert_eq!(
            base64url_encode(&bytes),
            input.encoded,
            "base64url must accept exactly one spelling"
        );
    }
});
