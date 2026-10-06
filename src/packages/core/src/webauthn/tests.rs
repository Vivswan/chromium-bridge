//! Hand-authored vectors: a fixed test scalar signs over byte strings built here to the WebAuthn layouts, so
//! every check has one input that trips exactly it. Nothing is captured from a real authenticator.

use coset::iana;
use coset::{CborSerializable as _, CoseKeyBuilder};

use super::encode;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::ipc::BrowserLabel;

const UP: u8 = encode::flags::UP;
const UV: u8 = encode::flags::UV;
const BE_BS: u8 = encode::flags::BE | encode::flags::BS;
const AT: u8 = encode::flags::AT;
const ED: u8 = encode::flags::ED;

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[0x11; 32]).unwrap()
}

fn other_key() -> SigningKey {
    SigningKey::from_slice(&[0x22; 32]).unwrap()
}

fn public_key(sk: &SigningKey) -> CosePublicKey {
    CosePublicKey::from_sec1(&sk.verifying_key().to_sec1_bytes()).unwrap()
}

fn cose_es256(sk: &SigningKey) -> Vec<u8> {
    encode::cose_ec2_key(&sk.verifying_key().to_sec1_bytes(), encode::ES256)
}

fn statement() -> Statement {
    Statement {
        domain: StatementDomain::Presence,
        browser_label: BrowserLabel::parse("brave").unwrap(),
        action: Action::parse("pair_client:codex").unwrap(),
        nonce: Nonce::parse("nonce-0001").unwrap(),
    }
}

fn credential_id() -> CredentialId {
    CredentialId::parse(vec![0xc1; 32]).unwrap()
}

fn credential(sign_count: u32) -> Credential {
    Credential {
        id: credential_id(),
        public_key: public_key(&signing_key()),
        sign_count,
        backup_eligible: false,
    }
}

fn client_data(kind: &str, challenge: &str, origin: &str, extra: serde_json::Value) -> Vec<u8> {
    let mut data = json!({ "type": kind, "challenge": challenge, "origin": origin });
    for (k, v) in extra.as_object().into_iter().flatten() {
        data[k] = v.clone();
    }
    serde_json::to_vec(&data).unwrap()
}

fn sign(sk: &SigningKey, authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    let sig: Signature = sk.sign(&signed);
    sig.to_der().to_bytes().into_vec()
}

/// The pieces of a valid assertion, each mutable before signing.
struct Parts {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<Vec<u8>>,
    kind: &'static str,
    challenge: String,
    origin: String,
    extra: serde_json::Value,
    signer: SigningKey,
    /// Applied to the signed bytes AFTER signing: a tamper the signature cannot cover.
    post_sign: fn(&mut Assertion),
    /// The enrolled credential's backup eligibility the assertion is verified against.
    enrolled_eligible: bool,
}

impl Parts {
    fn valid() -> Self {
        Parts {
            rp_id_hash: RpId::pinned().hash(),
            flags: UP | UV,
            sign_count: 7,
            attested: None,
            kind: "webauthn.get",
            challenge: statement().challenge().to_base64url(),
            origin: RpId::pinned().origin().to_string(),
            extra: json!({}),
            signer: signing_key(),
            post_sign: |_| {},
            enrolled_eligible: false,
        }
    }

    fn build(self) -> Assertion {
        let mut authenticator_data =
            encode::authenticator_data(&self.rp_id_hash, self.flags, self.sign_count, None);
        if let Some(attested) = &self.attested {
            authenticator_data.extend_from_slice(attested);
        }
        let client_data_json = client_data(self.kind, &self.challenge, &self.origin, self.extra);
        let signature = sign(&self.signer, &authenticator_data, &client_data_json);
        let mut assertion = Assertion {
            authenticator_data,
            client_data_json,
            signature,
        };
        (self.post_sign)(&mut assertion);
        assertion
    }
}

fn attested_block(sk: &SigningKey) -> Vec<u8> {
    let cose = cose_es256(sk);
    let mut block = vec![0xaa; 16];
    block.extend_from_slice(&32u16.to_be_bytes());
    block.extend_from_slice(credential_id().as_bytes());
    block.extend_from_slice(&cose);
    block
}

#[test]
fn a_valid_assertion_verifies_and_reports_uv_and_the_new_count() {
    // The spec's verification procedure, end to end, on a vector built to its layouts: the whole outcome,
    // including the count the store must record next.
    let verified = verify_assertion(
        &credential(6),
        &statement(),
        &RpId::pinned(),
        &Parts::valid().build(),
    );
    assert_eq!(
        verified,
        Ok(Verified {
            user_verified: true,
            sign_count: 7
        })
    );
    // UP alone (a security key without a PIN) verifies, with UV reported false; a synced passkey (BE and
    // BS set) verifies against the credential enrolled as backup-eligible.
    let mut parts = Parts::valid();
    parts.flags = UP | BE_BS;
    let enrolled = Credential {
        backup_eligible: true,
        ..credential(6)
    };
    let verified = verify_assertion(&enrolled, &statement(), &RpId::pinned(), &parts.build());
    assert_eq!(
        verified,
        Ok(Verified {
            user_verified: false,
            sign_count: 7
        })
    );
}

#[test]
fn assertion_checks_each_refuse_with_their_named_variant() {
    // One input per check, each tripping exactly that check: a missing check would turn its row green with
    // the wrong verdict. Rows that must still verify pin the tolerated shapes (extra clientData fields, an
    // explicit crossOrigin false, non-counting authenticators).
    let other_statement = Statement {
        nonce: Nonce::parse("nonce-0002").unwrap(),
        ..statement()
    };
    type Case = (
        &'static str,
        u32,
        Box<dyn Fn(&mut Parts)>,
        Result<Verified, Refusal>,
    );
    let cases: Vec<Case> = vec![
        (
            "attested credential data inside an assertion",
            6,
            Box::new(|p| {
                p.flags |= AT;
                p.attested = Some(attested_block(&signing_key()));
            }),
            Err(Refusal::UnexpectedAttestedCredential),
        ),
        (
            "rpIdHash of another RP",
            6,
            Box::new(|p| p.rp_id_hash = Sha256::digest(b"example.com").into()),
            Err(Refusal::RpIdMismatch),
        ),
        (
            "UP clear (UV set alone is a verification without a gesture)",
            6,
            Box::new(|p| p.flags = UV),
            Err(Refusal::UserNotPresent),
        ),
        (
            "BS set without BE: a flag pair the spec forbids",
            6,
            Box::new(|p| p.flags = UP | UV | 0x10),
            Err(Refusal::AuthenticatorData(
                AuthDataError::BackupStateWithoutEligibility,
            )),
        ),
        (
            "backup-eligible assertion for a credential enrolled as not eligible",
            6,
            Box::new(|p| p.flags = UP | UV | BE_BS),
            Err(Refusal::BackupEligibilityChanged {
                stored: false,
                received: true,
            }),
        ),
        (
            "not-eligible assertion for a credential enrolled as eligible",
            6,
            Box::new(|p| p.enrolled_eligible = true),
            Err(Refusal::BackupEligibilityChanged {
                stored: true,
                received: false,
            }),
        ),
        (
            "signCount equal to the stored one",
            7,
            Box::new(|_| {}),
            Err(Refusal::SignCountNotIncreased {
                stored: 7,
                received: 7,
            }),
        ),
        (
            "signCount behind the stored one",
            9,
            Box::new(|_| {}),
            Err(Refusal::SignCountNotIncreased {
                stored: 9,
                received: 7,
            }),
        ),
        (
            "signCount zero against a counting record",
            3,
            Box::new(|p| p.sign_count = 0),
            Err(Refusal::SignCountNotIncreased {
                stored: 3,
                received: 0,
            }),
        ),
        (
            "an authenticator that never counts (both zero) still verifies",
            0,
            Box::new(|p| p.sign_count = 0),
            Ok(Verified {
                user_verified: true,
                sign_count: 0,
            }),
        ),
        (
            "clientDataJSON that is not JSON",
            6,
            Box::new(|p| p.post_sign = |a| a.client_data_json = b"{not json".to_vec()),
            Err(Refusal::ClientDataMalformed),
        ),
        (
            "a registration's clientDataJSON answering a presence request",
            6,
            Box::new(|p| p.kind = "webauthn.create"),
            Err(Refusal::ClientDataType {
                got: "webauthn.create".into(),
                want: "webauthn.get",
            }),
        ),
        (
            "a challenge minted for another nonce",
            6,
            Box::new(move |p| p.challenge = other_statement.challenge().to_base64url()),
            Err(Refusal::ChallengeMismatch),
        ),
        (
            "an origin of another extension",
            6,
            Box::new(|p| p.origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop".into()),
            Err(Refusal::OriginMismatch {
                got: "chrome-extension://abcdefghijklmnopabcdefghijklmnop".into(),
            }),
        ),
        (
            "crossOrigin true",
            6,
            Box::new(|p| p.extra = json!({ "crossOrigin": true })),
            Err(Refusal::CrossOrigin),
        ),
        (
            "a topOrigin beside crossOrigin false: a cross-origin ceremony however it is spelled",
            6,
            Box::new(|p| {
                p.extra = json!({ "crossOrigin": false, "topOrigin": "https://example.com" })
            }),
            Err(Refusal::CrossOrigin),
        ),
        (
            "crossOrigin that is not a boolean",
            6,
            Box::new(|p| p.extra = json!({ "crossOrigin": "true" })),
            Err(Refusal::ClientDataMalformed),
        ),
        (
            "crossOrigin false and a client's extra fields verify",
            6,
            Box::new(|p| {
                p.extra = json!({ "crossOrigin": false, "other_keys_can_be_added_here": "do not compare" })
            }),
            Ok(Verified {
                user_verified: true,
                sign_count: 7,
            }),
        ),
        (
            "a signature that is not DER",
            6,
            Box::new(|p| p.post_sign = |a| a.signature = vec![0x30, 0x02, 0x01]),
            Err(Refusal::SignatureMalformed),
        ),
        (
            "a signature by another key",
            6,
            Box::new(|p| p.signer = other_key()),
            Err(Refusal::SignatureInvalid),
        ),
        (
            "authenticator data altered after signing",
            6,
            Box::new(|p| p.post_sign = |a| a.authenticator_data[32] ^= UV),
            Err(Refusal::SignatureInvalid),
        ),
    ];
    for (name, stored, mutate, want) in cases {
        let mut parts = Parts::valid();
        mutate(&mut parts);
        let enrolled = Credential {
            backup_eligible: parts.enrolled_eligible,
            ..credential(stored)
        };
        let got = verify_assertion(&enrolled, &statement(), &RpId::pinned(), &parts.build());
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn authenticator_data_layout_faults_are_named() {
    // The byte layout is the spec's, not ours: each fault names what the parser could not place.
    let valid = encode::authenticator_data(&RpId::pinned().hash(), UP, 1, None);
    let cases: Vec<(&str, Vec<u8>, AuthDataError)> = vec![
        (
            "36 bytes",
            valid[..36].to_vec(),
            AuthDataError::TooShort { len: 36 },
        ),
        ("empty", Vec::new(), AuthDataError::TooShort { len: 0 }),
        (
            "reserved bit 1",
            encode::authenticator_data(&RpId::pinned().hash(), UP | 0x02, 1, None),
            AuthDataError::ReservedFlags { flags: UP | 0x02 },
        ),
        (
            "ED flag",
            encode::authenticator_data(&RpId::pinned().hash(), UP | ED, 1, None),
            AuthDataError::Extensions,
        ),
        (
            "BS without BE",
            encode::authenticator_data(&RpId::pinned().hash(), UP | 0x10, 1, None),
            AuthDataError::BackupStateWithoutEligibility,
        ),
        (
            "bytes after the header",
            [valid.clone(), vec![0x00]].concat(),
            AuthDataError::TrailingBytes { len: 1 },
        ),
        (
            "AT set with nothing after the header",
            encode::authenticator_data(&RpId::pinned().hash(), UP | AT, 1, None),
            AuthDataError::AttestedCredentialTruncated,
        ),
        (
            "credIdLen past the end",
            encode::authenticator_data(&RpId::pinned().hash(), UP | AT, 1, Some((&[0xc1; 8], &[])))
                .iter()
                .copied()
                .take(37 + 16 + 2 + 4)
                .collect(),
            AuthDataError::AttestedCredentialTruncated,
        ),
        (
            "a 15-byte credential id",
            encode::authenticator_data(
                &RpId::pinned().hash(),
                UP | AT,
                1,
                Some((&[0xc1; 15], &cose_es256(&signing_key()))),
            ),
            AuthDataError::CredentialId(CredentialIdError::Length { len: 15 }),
        ),
        (
            "bytes after the COSE key",
            [
                encode::authenticator_data(
                    &RpId::pinned().hash(),
                    UP | AT,
                    1,
                    Some((&[0xc1; 32], &cose_es256(&signing_key()))),
                ),
                vec![0xa0],
            ]
            .concat(),
            AuthDataError::TrailingBytes { len: 1 },
        ),
    ];
    for (name, bytes, want) in cases {
        assert_eq!(AuthenticatorData::parse(&bytes), Err(want), "{name}");
    }
    let parsed = AuthenticatorData::parse(&encode::authenticator_data(
        &RpId::pinned().hash(),
        UP | AT,
        5,
        Some((&[0xc1; 32], &cose_es256(&signing_key()))),
    ))
    .unwrap();
    assert_eq!(
        parsed,
        AuthenticatorData {
            rp_id_hash: RpId::pinned().hash(),
            flags: Flags {
                user_present: true,
                user_verified: false,
                backup: BackupState::NotEligible,
            },
            sign_count: 5,
            attested: Some(AttestedCredential {
                aaguid: [0xaa; 16],
                id: credential_id(),
                public_key: public_key(&signing_key()),
            }),
        }
    );
}

fn attestation_object(fmt: &str, att_stmt: ciborium::Value, auth_data: ciborium::Value) -> Vec<u8> {
    let value = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".into()),
            ciborium::Value::Text(fmt.into()),
        ),
        (ciborium::Value::Text("attStmt".into()), att_stmt),
        (ciborium::Value::Text("authData".into()), auth_data),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

fn enrollment() -> Statement {
    Statement {
        domain: StatementDomain::Enrollment,
        action: Action::parse("enroll").unwrap(),
        ..statement()
    }
}

fn registration_with(cose: &[u8], flags: u8) -> Registration {
    let auth =
        encode::authenticator_data(&RpId::pinned().hash(), flags, 0, Some((&[0xc1; 32], cose)));
    Registration {
        attestation_object: attestation_object(
            "none",
            ciborium::Value::Map(Vec::new()),
            ciborium::Value::Bytes(auth),
        ),
        client_data_json: client_data(
            "webauthn.create",
            &enrollment().challenge().to_base64url(),
            RpId::pinned().origin(),
            json!({}),
        ),
    }
}

#[test]
fn a_none_attestation_registers_the_es256_credential() {
    // Registration takes the key from attestedCredentialData and trusts nothing else in the object; the
    // BE flag at creation becomes the eligibility every later assertion is held to.
    let registered = parse_registration(
        &enrollment(),
        &RpId::pinned(),
        &registration_with(&cose_es256(&signing_key()), UP | UV | AT),
    );
    assert_eq!(
        registered,
        Ok(Registered {
            credential: credential(0),
            user_verified: true,
        })
    );
    let synced = parse_registration(
        &enrollment(),
        &RpId::pinned(),
        &registration_with(&cose_es256(&signing_key()), UP | AT | BE_BS),
    );
    assert_eq!(
        synced,
        Ok(Registered {
            credential: Credential {
                backup_eligible: true,
                ..credential(0)
            },
            user_verified: false,
        })
    );
}

#[test]
fn registration_checks_each_refuse_with_their_named_variant() {
    // The COSE_Key rows pin the only algorithm this host verifies: every other kty/alg/crv is a key it
    // would store and then never be able to check an assertion against.
    let sec1 = signing_key().verifying_key().to_sec1_bytes();
    let (x, y) = (sec1[1..33].to_vec(), sec1[33..65].to_vec());
    let ec2 = |crv: iana::EllipticCurve, alg: iana::Algorithm, x: Vec<u8>, y: Vec<u8>| {
        CoseKeyBuilder::new_ec2_pub_key(crv, x, y)
            .algorithm(alg)
            .build()
            .to_vec()
            .unwrap()
    };
    let good = cose_es256(&signing_key());
    let valid_auth = || {
        encode::authenticator_data(
            &RpId::pinned().hash(),
            UP | AT,
            0,
            Some((&[0xc1; 32], &good)),
        )
    };
    let cases: Vec<(&str, Registration, Refusal)> = vec![
        (
            "type webauthn.get on a registration",
            Registration {
                client_data_json: client_data(
                    "webauthn.get",
                    &enrollment().challenge().to_base64url(),
                    RpId::pinned().origin(),
                    json!({}),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::ClientDataType {
                got: "webauthn.get".into(),
                want: "webauthn.create",
            },
        ),
        (
            "a presence statement's challenge on a registration",
            Registration {
                client_data_json: client_data(
                    "webauthn.create",
                    &statement().challenge().to_base64url(),
                    RpId::pinned().origin(),
                    json!({}),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::ChallengeMismatch,
        ),
        (
            "attestationObject that is not CBOR",
            Registration {
                attestation_object: vec![0xff, 0xff],
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationMalformed,
        ),
        (
            "a fourth key in the attestation map",
            Registration {
                attestation_object: {
                    let mut v: ciborium::Value = ciborium::from_reader(
                        attestation_object(
                            "none",
                            ciborium::Value::Map(Vec::new()),
                            ciborium::Value::Bytes(valid_auth()),
                        )
                        .as_slice(),
                    )
                    .unwrap();
                    v.as_map_mut()
                        .unwrap()
                        .push((ciborium::Value::Text("extra".into()), ciborium::Value::Null));
                    let mut out = Vec::new();
                    ciborium::into_writer(&v, &mut out).unwrap();
                    out
                },
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationMalformed,
        ),
        (
            "bytes after the attestation map",
            Registration {
                attestation_object: [
                    attestation_object(
                        "none",
                        ciborium::Value::Map(Vec::new()),
                        ciborium::Value::Bytes(valid_auth()),
                    ),
                    vec![0xff],
                ]
                .concat(),
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationTrailingBytes { len: 1 },
        ),
        (
            "authData that is not a byte string",
            Registration {
                attestation_object: attestation_object(
                    "none",
                    ciborium::Value::Map(Vec::new()),
                    ciborium::Value::Text("not bytes".into()),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationMalformed,
        ),
        (
            "fmt packed",
            Registration {
                attestation_object: attestation_object(
                    "packed",
                    ciborium::Value::Map(Vec::new()),
                    ciborium::Value::Bytes(valid_auth()),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationFormat {
                got: "packed".into(),
            },
        ),
        (
            "fmt none with a statement",
            Registration {
                attestation_object: attestation_object(
                    "none",
                    ciborium::Value::Map(vec![(
                        ciborium::Value::Text("sig".into()),
                        ciborium::Value::Bytes(vec![1]),
                    )]),
                    ciborium::Value::Bytes(valid_auth()),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::AttestationStatementNotEmpty,
        ),
        (
            "rpIdHash of another RP",
            Registration {
                attestation_object: attestation_object(
                    "none",
                    ciborium::Value::Map(Vec::new()),
                    ciborium::Value::Bytes(encode::authenticator_data(
                        &Sha256::digest(b"example.com").into(),
                        UP | AT,
                        0,
                        Some((&[0xc1; 32], &good)),
                    )),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::RpIdMismatch,
        ),
        (
            "UP clear",
            registration_with(&good, AT),
            Refusal::UserNotPresent,
        ),
        (
            "AT clear: no credential to enroll",
            Registration {
                attestation_object: attestation_object(
                    "none",
                    ciborium::Value::Map(Vec::new()),
                    ciborium::Value::Bytes(encode::authenticator_data(
                        &RpId::pinned().hash(),
                        UP,
                        0,
                        None,
                    )),
                ),
                ..registration_with(&good, UP | AT)
            },
            Refusal::NoAttestedCredential,
        ),
        (
            "RS256 key",
            registration_with(
                &ec2(
                    iana::EllipticCurve::P_256,
                    iana::Algorithm::RS256,
                    x.clone(),
                    y.clone(),
                ),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Algorithm {
                alg: Some(-257),
            })),
        ),
        (
            "ES256 key with no alg",
            registration_with(
                &CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
                    .build()
                    .to_vec()
                    .unwrap(),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Algorithm {
                alg: None,
            })),
        ),
        (
            "OKP key",
            registration_with(
                &CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::ES256)
                    .build()
                    .to_vec()
                    .unwrap(),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::NotEc2)),
        ),
        (
            "P-384 curve",
            registration_with(
                &ec2(
                    iana::EllipticCurve::P_384,
                    iana::Algorithm::ES256,
                    x.clone(),
                    y.clone(),
                ),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Curve)),
        ),
        (
            "31-byte coordinates",
            registration_with(
                &ec2(
                    iana::EllipticCurve::P_256,
                    iana::Algorithm::ES256,
                    x[..31].to_vec(),
                    y[..31].to_vec(),
                ),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Coordinates)),
        ),
        (
            "a point off the curve",
            registration_with(
                &ec2(
                    iana::EllipticCurve::P_256,
                    iana::Algorithm::ES256,
                    x.clone(),
                    vec![0x01; 32],
                ),
                UP | AT,
            ),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Point)),
        ),
        (
            "not a COSE_Key",
            registration_with(&[0x42, 0x01, 0x02], UP | AT),
            Refusal::AuthenticatorData(AuthDataError::PublicKey(KeyRefusal::Cbor)),
        ),
    ];
    for (name, registration, want) in cases {
        assert_eq!(
            parse_registration(&enrollment(), &RpId::pinned(), &registration),
            Err(want),
            "{name}"
        );
    }
}

#[test]
fn client_data_outside_the_spec_object_shape_is_refused_not_read_leniently() {
    // The spec's clientDataJSON is one object with distinct members; JSON readers are lenient in three ways
    // a signed frame could exploit: a repeated member read last-wins (`"challenge": 0, "challenge": "<good>"`
    // reads as the good challenge), a present `null` read as an absent member, and a positional array read
    // as the struct. Each must be refused, for the assertion and the registration alike; the row names
    // which refusal.
    let good = statement().challenge().to_base64url();
    let rp_id = RpId::pinned();
    let origin = rp_id.origin();
    // Signed over the raw body, so the signature check cannot be what refuses the frame.
    let raw = |body: String| {
        let authenticator_data =
            encode::authenticator_data(&RpId::pinned().hash(), UP | UV, 7, None);
        let client_data_json = body.into_bytes();
        let signature = sign(&signing_key(), &authenticator_data, &client_data_json);
        Assertion {
            authenticator_data,
            client_data_json,
            signature,
        }
    };
    for (name, body, want) in [
        (
            "duplicate challenge, good one last",
            format!(
                r#"{{"type":"webauthn.get","challenge":0,"challenge":"{good}","origin":"{origin}"}}"#
            ),
            Refusal::ClientDataMalformed,
        ),
        (
            "duplicate crossOrigin, false last",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good}","origin":"{origin}","crossOrigin":true,"crossOrigin":false}}"#
            ),
            Refusal::ClientDataMalformed,
        ),
        (
            "crossOrigin null",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good}","origin":"{origin}","crossOrigin":null}}"#
            ),
            Refusal::ClientDataMalformed,
        ),
        (
            "topOrigin null: a present topOrigin is a cross-origin ceremony whatever its value",
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good}","origin":"{origin}","topOrigin":null}}"#
            ),
            Refusal::CrossOrigin,
        ),
        (
            "a positional array in place of the object",
            format!(r#"["webauthn.get","{good}","{origin}",false,null]"#),
            Refusal::ClientDataMalformed,
        ),
    ] {
        assert_eq!(
            verify_assertion(&credential(6), &statement(), &RpId::pinned(), &raw(body)),
            Err(want),
            "{name}"
        );
    }
    let enroll = enrollment().challenge().to_base64url();
    let registration = Registration {
        client_data_json: format!(
            r#"{{"type":"webauthn.create","challenge":0,"challenge":"{enroll}","origin":"{origin}"}}"#
        )
        .into_bytes(),
        ..registration_with(&cose_es256(&signing_key()), UP | AT)
    };
    assert_eq!(
        parse_registration(&enrollment(), &RpId::pinned(), &registration),
        Err(Refusal::ClientDataMalformed),
        "registration with a duplicate challenge"
    );
}

#[test]
fn statements_are_domain_separated_and_the_challenge_is_their_digest() {
    // The challenge the client echoes is SHA-256 of the NUL-separated message; same fields under the other
    // domain give a different challenge, so neither ceremony's signature answers the other.
    let presence = statement();
    let mut expected = PRESENCE_DOMAIN.as_bytes().to_vec();
    for part in ["brave", "pair_client:codex", "nonce-0001"] {
        expected.push(0);
        expected.extend_from_slice(part.as_bytes());
    }
    assert_eq!(presence.message(), expected);
    assert_eq!(
        presence.challenge().as_bytes(),
        &<[u8; 32]>::from(Sha256::digest(&expected))
    );
    let enrollment = Statement {
        domain: StatementDomain::Enrollment,
        ..statement()
    };
    assert_ne!(presence.challenge(), enrollment.challenge());
    assert!(
        !PRESENCE_DOMAIN.starts_with(ENROLL_DOMAIN) && !ENROLL_DOMAIN.starts_with(PRESENCE_DOMAIN)
    );
    // The base64url spelling is unpadded, as PublicKeyCredential.toJSON() spells it.
    assert_eq!(presence.challenge().to_base64url().len(), 43);
    assert!(!presence.challenge().to_base64url().contains('='));
}

#[test]
fn statement_fields_refuse_what_would_break_injectivity() {
    // The NUL separators make the encoding injective only while no field carries a NUL: with one inside a
    // field, two different statements encode to the same bytes.
    assert!(Nonce::parse("a\0b").is_none());
    assert!(Action::parse("a\0b").is_none());
    // A fresh nonce is 32 bytes of base64url: 43 chars, NUL-free, and never repeats.
    let (a, b) = (Nonce::fresh().unwrap(), Nonce::fresh().unwrap());
    assert_eq!(a.as_str().len(), 43);
    assert_ne!(a, b);
}

#[test]
fn credential_storage_spelling_round_trips_and_validates_on_read() {
    // The stored form is what trust.json will carry; a read parses, so a damaged record is refused rather
    // than loaded as a key the verifier would trust.
    let stored = serde_json::to_value(credential(9)).unwrap();
    assert_eq!(
        stored,
        json!({
            "id": base64url_encode(&[0xc1; 32]),
            "public_key": base64url_encode(&signing_key().verifying_key().to_sec1_bytes()),
            "sign_count": 9,
            "backup_eligible": false,
        })
    );
    assert_eq!(
        serde_json::from_value::<Credential>(stored).unwrap(),
        credential(9)
    );
    // Each refused record is the valid stored one with exactly one field changed, so the refusal is that
    // field's and not a second fault's.
    let valid = serde_json::to_value(credential(0)).unwrap();
    let with = |key: &str, value: serde_json::Value| {
        let mut record = valid.clone();
        record[key] = value;
        record
    };
    for (name, record) in [
        (
            "padded id",
            with(
                "id",
                json!(base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE,
                    [0xc1; 32]
                )),
            ),
        ),
        ("short id", with("id", json!(base64url_encode(&[0xc1; 15])))),
        (
            "off-curve key",
            with("public_key", json!(base64url_encode(&[0x04; 65]))),
        ),
        ("missing eligibility", {
            let mut record = valid.clone();
            record.as_object_mut().unwrap().remove("backup_eligible");
            record
        }),
        ("extra field", with("aaguid", json!("x"))),
    ] {
        assert!(
            serde_json::from_value::<Credential>(record).is_err(),
            "{name}"
        );
    }
    // The wire decoders name the field that failed.
    assert_eq!(
        Assertion::from_base64url("AA", "not*base64url", "AA"),
        Err(Refusal::Encoding {
            field: "client_data_json"
        })
    );
    assert_eq!(
        Registration::from_base64url("AA==", "AA"),
        Err(Refusal::Encoding {
            field: "attestation_object"
        })
    );
    assert_eq!(
        CredentialId::from_base64url("AA"),
        Err(CredentialIdError::Length { len: 1 })
    );
}

// ---- Forgetting a browser's enrollments -------------------------------------------------------------------

mod revoke_browser {
    use super::*;
    use crate::audit::{AuditKind, AuditRecord, Surface};
    use crate::presence::{PresenceAttestation, PresencePath};
    use crate::test_support::scratch_runtime_dir;
    use crate::trust::TrustState;

    fn label(s: &str) -> BrowserLabel {
        BrowserLabel::parse(s).unwrap()
    }

    fn credential_with(seed: u8) -> Credential {
        Credential {
            id: CredentialId::parse(vec![seed; 32]).unwrap(),
            public_key: public_key(&SigningKey::from_slice(&[seed; 32]).unwrap()),
            sign_count: 0,
            backup_eligible: false,
        }
    }

    /// Plant `(label, seed)` enrollments as the store writes them: the first on first use, the rest approved.
    fn plant(enrollments: &[(&str, u8)]) {
        for (i, (browser, seed)) in enrollments.iter().enumerate() {
            let authority = if i == 0 {
                EnrollmentAuthority::FirstUse
            } else {
                EnrollmentAuthority::Approved(PresenceAttestation::assume_for_tests(
                    PresencePath::Tty,
                ))
            };
            record(&label(browser), credential_with(*seed), authority).unwrap();
        }
    }

    fn fingerprint(seed: u8) -> String {
        PresencePath::WebAuthn(CredentialId::parse(vec![seed; 32]).unwrap()).audit_label()
    }

    fn json(enrollments: &[Enrollment]) -> Vec<String> {
        enrollments
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect()
    }

    /// `(name, detail)` of every RevokeBrowser record in the trail, in order.
    fn revoke_records() -> Vec<(String, String)> {
        std::fs::read_to_string(crate::audit::audit_path().unwrap())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
            .filter(|r| r.event_kind == AuditKind::RevokeBrowser)
            .map(|r| {
                assert_eq!(r.outcome.as_deref(), Some("ok"), "{r:?}");
                assert_eq!(r.surface, Some(Surface::Cli), "{r:?}");
                (r.name.unwrap(), r.detail.unwrap())
            })
            .collect()
    }

    /// Forgetting a browser takes every enrollment under its label and nothing else: the other browsers'
    /// survive byte for byte, only the epoch moves, the trail carries one record per credential, and a second
    /// forget names the labels still present. The same for `default`, the label every browser on a shared
    /// unlabelled manifest enrolls as, so `revoke default` forgets all of them.
    #[test]
    fn forgets_every_enrollment_under_the_label_and_leaves_the_rest_byte_for_byte() {
        for target in ["brave", BrowserLabel::default_label().as_str()] {
            let _dir = scratch_runtime_dir();
            plant(&[
                (target, 0x31),
                ("chrome", 0x41),
                (target, 0x32),
                ("edge", 0x51),
            ]);
            let before = TrustState::current().unwrap();
            let (gone, kept): (Vec<&Enrollment>, Vec<&Enrollment>) = before
                .enrollments()
                .iter()
                .partition(|e| e.label.as_str() == target);

            let revoked = revoke_browser(&label(target), Surface::Cli).unwrap();

            let after = TrustState::current().unwrap();
            assert_eq!(
                *revoked.trust, *after,
                "the returned snapshot is the record"
            );
            assert_eq!(
                json(&revoked.forgotten),
                gone.iter()
                    .map(|e| serde_json::to_string(e).unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                json(after.enrollments()),
                kept.iter()
                    .map(|e| serde_json::to_string(e).unwrap())
                    .collect::<Vec<_>>()
            );
            assert_eq!(after.epoch(), before.epoch() + 1);
            assert_eq!(
                (
                    after.killed(),
                    after.kill_epoch(),
                    after.host_key_epoch(),
                    after.policy_epoch(),
                    after.lang_epoch(),
                    after.clients(),
                ),
                (
                    before.killed(),
                    before.kill_epoch(),
                    before.host_key_epoch(),
                    before.policy_epoch(),
                    before.lang_epoch(),
                    before.clients(),
                ),
                "nothing but the enrollments and the epoch moved"
            );
            assert_eq!(
                revoke_records(),
                [0x31, 0x32]
                    .map(|seed| (
                        target.to_string(),
                        format!("credential={}", fingerprint(seed))
                    ))
                    .to_vec()
            );
            let Err(RevokeBrowserError::NotEnrolled { enrolled }) =
                revoke_browser(&label(target), Surface::Cli)
            else {
                panic!("{target}: a second forget must name the labels present")
            };
            assert_eq!(
                enrolled
                    .iter()
                    .map(BrowserLabel::as_str)
                    .collect::<Vec<_>>(),
                ["chrome", "edge"]
            );
            assert_eq!(
                revoke_records().len(),
                2,
                "a refused forget writes no record"
            );
        }
    }

    /// The last enrolled browser can be forgotten too, and the machine is then back on first use: the next
    /// enrollment needs no approval, which is what the CLI tells the user.
    #[test]
    fn the_last_browser_is_forgotten_and_the_next_enrollment_is_first_use_again() {
        let _dir = scratch_runtime_dir();
        plant(&[("brave", 0x31)]);

        let revoked = revoke_browser(&label("brave"), Surface::Cli).unwrap();

        assert_eq!(revoked.forgotten.len(), 1);
        assert!(revoked.trust.enrollments().is_empty());
        assert!(TrustState::current().unwrap().enrollments().is_empty());
        record(
            &label("chrome"),
            credential_with(0x41),
            EnrollmentAuthority::FirstUse,
        )
        .expect("an emptied store takes a first-use enrollment");
        assert_eq!(
            revoke_records(),
            vec![(
                "brave".to_string(),
                format!("credential={}", fingerprint(0x31))
            )]
        );
    }
}
