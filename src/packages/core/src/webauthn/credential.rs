//! Every constructor validates, so a credential value that exists is one the verifier can use.

use std::fmt;

use coset::iana::EnumI64 as _;
use coset::{iana, AsCborValue as _, CoseKey, Label};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::identity::PINNED_EXTENSION_ID;

use super::authenticator_data::{MAX_CREDENTIAL_ID_LEN, MIN_CREDENTIAL_ID_LEN};
use super::base64url;

/// The relying-party id as the authenticator hashes it. The page claims the bare extension id as `rp.id`,
/// but Chromium rewrites an extension's claim to the serialized origin before the authenticator sees it,
/// so the RP ID and the origin are one string: `chrome-extension://<id>` (tests/browser/webauthn_test.ts
/// proves it against Chrome). The host serves exactly one RP, so the pinned id is the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpId(String);

impl RpId {
    pub fn pinned() -> Self {
        RpId(format!("chrome-extension://{PINNED_EXTENSION_ID}"))
    }

    /// What `authenticatorData.rpIdHash` must equal: SHA-256 of the origin string.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    /// What `clientDataJSON.origin` must equal.
    pub fn origin(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialIdError {
    #[error("credential id is not base64url")]
    Encoding,
    #[error(
        "credential id is {len} bytes, outside {MIN_CREDENTIAL_ID_LEN}..={MAX_CREDENTIAL_ID_LEN}"
    )]
    Length { len: usize },
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, CredentialIdError> {
        let len = bytes.len();
        if !(MIN_CREDENTIAL_ID_LEN..=MAX_CREDENTIAL_ID_LEN).contains(&len) {
            return Err(CredentialIdError::Length { len });
        }
        Ok(CredentialId(bytes))
    }

    pub fn from_base64url(s: &str) -> Result<Self, CredentialIdError> {
        let bytes = base64url::decode(s).map_err(|_| CredentialIdError::Encoding)?;
        Self::parse(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        base64url::encode(&self.0)
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId({})", self.to_base64url())
    }
}

impl Serialize for CredentialId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for CredentialId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        CredentialId::from_base64url(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyRefusal {
    #[error("credential public key is not a CBOR COSE_Key")]
    Cbor,
    #[error("credential public key is not an EC2 key")]
    NotEc2,
    /// `alg` is `None` when the key carried a text algorithm or none at all.
    #[error("credential public key algorithm {alg:?} is not ES256 (-7)")]
    Algorithm { alg: Option<i64> },
    #[error("credential public key curve is not P-256")]
    Curve,
    #[error("credential public key coordinates are not two 32-byte scalars")]
    Coordinates,
    #[error("credential public key point is not on P-256")]
    Point,
}

/// An ES256 (ECDSA P-256, SHA-256) credential public key: the only COSE algorithm this host verifies.
#[derive(Clone, PartialEq, Eq)]
pub struct CosePublicKey {
    key: VerifyingKey,
}

impl CosePublicKey {
    /// Parse the COSE_Key at the front of `bytes` and return it with the unconsumed remainder: inside
    /// `attestedCredentialData` the key has no length prefix, so the CBOR item's own extent is the only
    /// way to find where the extensions (or the end) begin.
    pub fn parse_cose_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), KeyRefusal> {
        let mut cursor = bytes;
        let value: ciborium::Value =
            ciborium::from_reader(&mut cursor).map_err(|_| KeyRefusal::Cbor)?;
        let key = CoseKey::from_cbor_value(value).map_err(|_| KeyRefusal::Cbor)?;
        Ok((Self::from_cose_key(&key)?, cursor))
    }

    fn from_cose_key(key: &CoseKey) -> Result<Self, KeyRefusal> {
        if key.kty != coset::KeyType::Assigned(iana::KeyType::EC2) {
            return Err(KeyRefusal::NotEc2);
        }
        let alg = match &key.alg {
            Some(coset::Algorithm::Assigned(alg)) => Some(alg.to_i64()),
            Some(coset::Algorithm::PrivateUse(alg)) => Some(*alg),
            Some(coset::Algorithm::Text(_)) | None => None,
        };
        if alg != Some(iana::Algorithm::ES256.to_i64()) {
            return Err(KeyRefusal::Algorithm { alg });
        }
        let crv = key
            .params
            .iter()
            .find(|(label, _)| *label == Label::Int(iana::Ec2KeyParameter::Crv.to_i64()))
            .and_then(|(_, value)| value.as_integer())
            .and_then(|crv| i64::try_from(crv).ok());
        if crv != Some(iana::EllipticCurve::P_256.to_i64()) {
            return Err(KeyRefusal::Curve);
        }
        // coset accepts a boolean y (a compressed point) and any coordinate length; WebAuthn EC2 keys
        // carry both 32-byte coordinates, so anything else is refused here before the curve check.
        let sec1 = key
            .to_sec1_octet_string()
            .map_err(|_| KeyRefusal::Coordinates)?;
        if sec1.len() != 65 || sec1.first() != Some(&0x04) {
            return Err(KeyRefusal::Coordinates);
        }
        Self::from_sec1(&sec1)
    }

    /// The storage spelling: the 65-byte uncompressed SEC1 point, validated to lie on P-256.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, KeyRefusal> {
        let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| KeyRefusal::Point)?;
        Ok(CosePublicKey { key })
    }

    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.key.to_sec1_bytes().into_vec()
    }

    pub(super) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

impl fmt::Debug for CosePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CosePublicKey(es256:{})",
            base64url::encode(&self.to_sec1_bytes())
        )
    }
}

impl Serialize for CosePublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64url::encode(&self.to_sec1_bytes()))
    }
}

impl<'de> Deserialize<'de> for CosePublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = base64url::decode(&s).map_err(serde::de::Error::custom)?;
        CosePublicKey::from_sec1(&bytes).map_err(serde::de::Error::custom)
    }
}

/// One enrolled credential as trust.json keeps it. `sign_count` and `backup_eligible` are what the next
/// assertion is held to (verify.rs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub id: CredentialId,
    pub public_key: CosePublicKey,
    pub sign_count: u32,
    pub backup_eligible: bool,
}
