//! Registration: the `navigator.credentials.create` response, accepted with `attestation: "none"` only.
//! The credential public key comes from `attestedCredentialData`; no attestation chain is ever trusted.

use super::authenticator_data::AuthenticatorData;
use super::base64url;
use super::client_data;
use super::credential::{Credential, RpId};
use super::refusal::Refusal;
use super::statement::Statement;

/// The two byte strings a `navigator.credentials.create` response carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

impl Registration {
    /// The wire boundary: the two fields as the `enroll_finish` frame spells them (base64url).
    pub fn from_base64url(
        attestation_object: &str,
        client_data_json: &str,
    ) -> Result<Self, Refusal> {
        let field = |name: &'static str, value: &str| {
            base64url::decode(value).map_err(|_| Refusal::Encoding { field: name })
        };
        Ok(Registration {
            attestation_object: field("attestation_object", attestation_object)?,
            client_data_json: field("client_data_json", client_data_json)?,
        })
    }
}

/// What an accepted registration established: the credential to record, and whether the authenticator
/// verified the user (a biometric or PIN) rather than only testing presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub credential: Credential,
    pub user_verified: bool,
}

pub fn parse_registration(
    statement: &Statement,
    rp_id: &RpId,
    registration: &Registration,
) -> Result<Registered, Refusal> {
    client_data::check(
        &registration.client_data_json,
        "webauthn.create",
        statement,
        rp_id,
    )?;
    let auth_data = attestation_none_auth_data(&registration.attestation_object)?;
    let auth = AuthenticatorData::parse(&auth_data).map_err(Refusal::AuthenticatorData)?;
    if auth.rp_id_hash != rp_id.hash() {
        return Err(Refusal::RpIdMismatch);
    }
    if !auth.flags.user_present {
        return Err(Refusal::UserNotPresent);
    }
    let attested = auth.attested.ok_or(Refusal::NoAttestedCredential)?;
    Ok(Registered {
        credential: Credential {
            id: attested.id,
            public_key: attested.public_key,
            sign_count: auth.sign_count,
            backup_eligible: auth.flags.backup.eligible(),
        },
        user_verified: auth.flags.user_verified,
    })
}

fn attestation_none_auth_data(attestation_object: &[u8]) -> Result<Vec<u8>, Refusal> {
    let mut cursor = attestation_object;
    let value: ciborium::Value =
        ciborium::from_reader(&mut cursor).map_err(|_| Refusal::AttestationMalformed)?;
    if !cursor.is_empty() {
        return Err(Refusal::AttestationTrailingBytes { len: cursor.len() });
    }
    let map = value.as_map().ok_or(Refusal::AttestationMalformed)?;
    if map.len() != 3 {
        return Err(Refusal::AttestationMalformed);
    }
    let entry = |key: &str| {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .ok_or(Refusal::AttestationMalformed)
    };
    let fmt = entry("fmt")?
        .as_text()
        .ok_or(Refusal::AttestationMalformed)?;
    if fmt != "none" {
        return Err(Refusal::AttestationFormat {
            got: fmt.to_string(),
        });
    }
    let statement = entry("attStmt")?
        .as_map()
        .ok_or(Refusal::AttestationMalformed)?;
    if !statement.is_empty() {
        return Err(Refusal::AttestationStatementNotEmpty);
    }
    entry("authData")?
        .as_bytes()
        .cloned()
        .ok_or(Refusal::AttestationMalformed)
}
