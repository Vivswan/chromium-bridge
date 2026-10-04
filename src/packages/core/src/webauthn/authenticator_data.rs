//! The fixed-layout `authenticatorData` byte string, parsed once into typed fields.
//!
//! ```text
//! rpIdHash 32 | flags 1 | signCount 4 BE | [aaguid 16 | credIdLen 2 BE | credId | COSE_Key]   (AT flag)
//! ```
//!
//! No crate owns this layout without bringing a whole relying-party library, so it is the one hand-written
//! byte parser in the module; the COSE key inside it is parsed by coset.

use super::credential::{CosePublicKey, CredentialId, CredentialIdError, KeyRefusal};

/// A WebAuthn client refuses credential ids above 1023 bytes; below 16 an id is no longer a
/// probabilistically unique handle.
pub const MIN_CREDENTIAL_ID_LEN: usize = 16;
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;
const RESERVED_FLAGS: u8 = !(FLAG_USER_PRESENT
    | FLAG_USER_VERIFIED
    | FLAG_BACKUP_ELIGIBLE
    | FLAG_BACKUP_STATE
    | FLAG_ATTESTED_CREDENTIAL
    | FLAG_EXTENSIONS);

/// Why a byte string is not authenticator data this host accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthDataError {
    #[error("authenticator data is {len} bytes, shorter than the 37-byte header")]
    TooShort { len: usize },
    /// A reserved flag bit is set: an authenticator speaking a dialect this host does not know.
    #[error("authenticator data sets reserved flag bits 0x{flags:02x}")]
    ReservedFlags { flags: u8 },
    /// The ED flag: the host requests no extensions, so output it cannot interpret is refused.
    #[error("authenticator data carries extensions")]
    Extensions,
    /// BS set with BE clear: the spec forbids the combination, so the authenticator is not speaking WebAuthn.
    #[error("authenticator data claims a backed-up credential that is not backup-eligible")]
    BackupStateWithoutEligibility,
    #[error("attested credential data is truncated")]
    AttestedCredentialTruncated,
    #[error(transparent)]
    CredentialId(CredentialIdError),
    #[error(transparent)]
    PublicKey(KeyRefusal),
    #[error("{len} unparsed bytes follow the authenticator data")]
    TrailingBytes { len: usize },
}

/// The flag bits the verifier reads. AT and ED are consumed by the parser (the one structures the
/// remainder, the other is refused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    pub user_present: bool,
    pub user_verified: bool,
    pub backup: BackupState,
}

/// The BE/BS pair as the spec allows it: eligibility is fixed at creation and the verifier refuses an
/// assertion whose eligibility differs from the enrolled one; backed-up without eligible is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    NotEligible,
    EligibleNotBackedUp,
    BackedUp,
}

impl BackupState {
    pub fn eligible(self) -> bool {
        match self {
            BackupState::NotEligible => false,
            BackupState::EligibleNotBackedUp | BackupState::BackedUp => true,
        }
    }
}

/// `attestedCredentialData`: present exactly when the AT flag is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub id: CredentialId,
    pub public_key: CosePublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: Flags,
    pub sign_count: u32,
    pub attested: Option<AttestedCredential>,
}

impl AuthenticatorData {
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthDataError> {
        let (rp_id_hash, rest) =
            take::<32>(bytes).ok_or(AuthDataError::TooShort { len: bytes.len() })?;
        let (flag_byte, rest) =
            take::<1>(rest).ok_or(AuthDataError::TooShort { len: bytes.len() })?;
        let (count, rest) = take::<4>(rest).ok_or(AuthDataError::TooShort { len: bytes.len() })?;
        let flags = flag_byte[0];
        if flags & RESERVED_FLAGS != 0 {
            return Err(AuthDataError::ReservedFlags { flags });
        }
        if flags & FLAG_EXTENSIONS != 0 {
            return Err(AuthDataError::Extensions);
        }
        let backup = match (
            flags & FLAG_BACKUP_ELIGIBLE != 0,
            flags & FLAG_BACKUP_STATE != 0,
        ) {
            (false, false) => BackupState::NotEligible,
            (true, false) => BackupState::EligibleNotBackedUp,
            (true, true) => BackupState::BackedUp,
            (false, true) => return Err(AuthDataError::BackupStateWithoutEligibility),
        };
        let (attested, rest) = if flags & FLAG_ATTESTED_CREDENTIAL != 0 {
            let (attested, rest) = parse_attested(rest)?;
            (Some(attested), rest)
        } else {
            (None, rest)
        };
        if !rest.is_empty() {
            return Err(AuthDataError::TrailingBytes { len: rest.len() });
        }
        Ok(AuthenticatorData {
            rp_id_hash,
            flags: Flags {
                user_present: flags & FLAG_USER_PRESENT != 0,
                user_verified: flags & FLAG_USER_VERIFIED != 0,
                backup,
            },
            sign_count: u32::from_be_bytes(count),
            attested,
        })
    }
}

fn parse_attested(bytes: &[u8]) -> Result<(AttestedCredential, &[u8]), AuthDataError> {
    let (aaguid, rest) = take::<16>(bytes).ok_or(AuthDataError::AttestedCredentialTruncated)?;
    let (len, rest) = take::<2>(rest).ok_or(AuthDataError::AttestedCredentialTruncated)?;
    let (id, rest) = rest
        .split_at_checked(usize::from(u16::from_be_bytes(len)))
        .ok_or(AuthDataError::AttestedCredentialTruncated)?;
    let id = CredentialId::parse(id.to_vec()).map_err(AuthDataError::CredentialId)?;
    let (public_key, rest) =
        CosePublicKey::parse_cose_prefix(rest).map_err(AuthDataError::PublicKey)?;
    Ok((
        AttestedCredential {
            aaguid,
            id,
            public_key,
        },
        rest,
    ))
}

/// Split a fixed-size prefix off `bytes`, or `None` when it is shorter than `N`.
fn take<const N: usize>(bytes: &[u8]) -> Option<([u8; N], &[u8])> {
    let (head, rest) = bytes.split_at_checked(N)?;
    let head: [u8; N] = head.try_into().ok()?;
    Some((head, rest))
}
