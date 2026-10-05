//! The assertion verifier: pure over its inputs, every refusal a [`Refusal`] variant.

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::DerSignature;
use sha2::{Digest, Sha256};

use super::authenticator_data::AuthenticatorData;
use super::base64url;
use super::client_data;
use super::credential::{Credential, RpId};
use super::refusal::Refusal;
use super::statement::Statement;

/// The three byte strings a `navigator.credentials.get` response carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Assertion {
    /// The wire boundary: the three fields as the `presence_assert` frame spells them (base64url).
    pub fn from_base64url(
        authenticator_data: &str,
        client_data_json: &str,
        signature: &str,
    ) -> Result<Self, Refusal> {
        let field = |name: &'static str, value: &str| {
            base64url::decode(value).map_err(|_| Refusal::Encoding { field: name })
        };
        Ok(Assertion {
            authenticator_data: field("authenticator_data", authenticator_data)?,
            client_data_json: field("client_data_json", client_data_json)?,
            signature: field("signature", signature)?,
        })
    }
}

/// What an accepted assertion established. `sign_count` is the value the store records back so the next
/// assertion must exceed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub user_verified: bool,
    pub sign_count: u32,
}

/// Verify one assertion against the enrolled credential and the statement the host issued. The signature
/// covers `authenticatorData || sha256(clientDataJSON)`, the spec's signing input.
pub fn verify_assertion(
    credential: &Credential,
    statement: &Statement,
    rp_id: &RpId,
    assertion: &Assertion,
) -> Result<Verified, Refusal> {
    let auth = AuthenticatorData::parse(&assertion.authenticator_data)
        .map_err(Refusal::AuthenticatorData)?;
    if auth.attested.is_some() {
        return Err(Refusal::UnexpectedAttestedCredential);
    }
    if auth.rp_id_hash != rp_id.hash() {
        return Err(Refusal::RpIdMismatch);
    }
    if !auth.flags.user_present {
        return Err(Refusal::UserNotPresent);
    }
    let (stored, received) = (credential.backup_eligible, auth.flags.backup.eligible());
    if stored != received {
        return Err(Refusal::BackupEligibilityChanged { stored, received });
    }
    // A zero on both sides is an authenticator that does not count; once either side counts, the value
    // must move forward on every assertion.
    let (stored, received) = (credential.sign_count, auth.sign_count);
    if (stored != 0 || received != 0) && received <= stored {
        return Err(Refusal::SignCountNotIncreased { stored, received });
    }
    client_data::check(
        &assertion.client_data_json,
        "webauthn.get",
        statement,
        rp_id,
    )?;
    let signature =
        DerSignature::from_bytes(&assertion.signature).map_err(|_| Refusal::SignatureMalformed)?;
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&assertion.client_data_json));
    credential
        .public_key
        .verifying_key()
        .verify(&signed, &signature)
        .map_err(|_| Refusal::SignatureInvalid)?;
    Ok(Verified {
        user_verified: auth.flags.user_verified,
        sign_count: received,
    })
}
