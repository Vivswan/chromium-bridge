use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};

use crate::ipc::RuntimeLockToken;
use crate::presence::PresenceAttestation;
use crate::protocol::control::EnclaveControl;
use crate::runtime_record::RuntimeRecord as _;

use super::base64_encode;
use super::challenge::{challenge_message, policy_message};
use super::pubkey::EnclavePublicKey;
use super::record::{HostKeyFile, KeyStore, Scalar};
use super::store;
use super::{reason_code, EnclaveError, SIG_LEN};

/// The host identity key, from the file when one exists and from the credential store otherwise: the file's
/// presence IS the `--file-store` choice, so a file machine never needs the store to answer. A handle exists
/// only for a key this host may sign with: the golden-fixture scalar is refused at construction, so no code
/// path can sign with it by forgetting to export the public half first.
pub struct EnrollmentKey {
    signing: SigningKey,
    public: EnclavePublicKey,
    store: KeyStore,
}

impl std::fmt::Debug for EnrollmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrollmentKey(..)")
    }
}

impl EnrollmentKey {
    /// `Ok(None)` is the unenrolled machine: no file and no store entry. On a store machine a store that does
    /// not answer is an error, and `pair` treats anything but a clean absence as suspect.
    pub fn lookup() -> Result<Option<Self>, EnclaveError> {
        if let Some(file) = HostKeyFile::load().map_err(record_error)? {
            return Self::from_scalar(&file.scalar, KeyStore::File).map(Some);
        }
        match store::get()? {
            Some(secret) => {
                Self::from_scalar(&Scalar::from_bytes(&secret)?, KeyStore::CredentialStore)
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    /// Minting is a capability grant (the extension pins what the key signs), so it consumes a
    /// [`PresenceAttestation`] like every grant. The absence check and the mint share one lock hold, so two
    /// `pair` runs cannot both mint and silently replace a key an extension already pinned; `pair --reset`
    /// disposes first.
    ///
    /// The leftover signed baseline is cleared under the same hold and AFTER the absence check: a baseline
    /// signed by a dead key pushed as current is exactly the pin mismatch a genuine host must never produce,
    /// and clearing before the check could remove a concurrent pairing's live policy. Each store is one
    /// write, so nothing is left half-done.
    ///
    /// ```text
    /// a file exists                          -> refused, whichever store was asked for
    /// a store entry exists                   -> refused, whichever store was asked for
    /// the store does not answer, File asked  -> minted into the file: lookup reads the file first, so an
    ///                                           unseen store entry is superseded and a pin on it fails
    ///                                           closed
    /// the store does not answer, store asked -> the store's error
    /// ```
    pub fn mint(
        lock: &RuntimeLockToken,
        store: KeyStore,
        auth: PresenceAttestation,
    ) -> Result<Self, EnclaveError> {
        let exists =
            EnclaveError::KeyInvalid("a host key already exists; `pair --reset` replaces it");
        if HostKeyFile::load().map_err(record_error)?.is_some() {
            return Err(exists);
        }
        match (store, store::get()) {
            (_, Ok(Some(_))) => return Err(exists),
            (_, Ok(None)) => {}
            (KeyStore::CredentialStore, Err(e)) => return Err(e),
            (KeyStore::File, Err(e)) => log_warn!(
                "enclave",
                "the credential store did not answer ({e}); minting into the file as asked"
            ),
        }
        drop(auth);
        if let Err(e) = crate::policy::clear_baseline_locked(lock) {
            log_warn!(
                "enclave",
                "a leftover policy baseline could not be cleared ({e}); until a new policy write \
                 supersedes it, a paired extension will refuse it as unverifiable"
            );
        }
        let scalar = Scalar::random()?;
        let key = Self::from_scalar(&scalar, store)?;
        match store {
            KeyStore::CredentialStore => store::set(&scalar.secret_key().to_bytes())?,
            KeyStore::File => HostKeyFile { scalar }.write(lock).map_err(record_error)?,
        }
        Ok(key)
    }

    /// Removes the key from both places and reports what each confirmed; only the file removal can fail this
    /// call.
    ///
    /// ```text
    /// file, even unreadable  -> removed: `pair --reset` is the advertised recovery from a damaged record
    /// store entry            -> gone only when the read-back says so (store.rs)
    /// store does not answer  -> reported, never hidden: a `--file-store` machine must still revoke and
    ///                           re-pair, a store machine must not claim its key gone
    /// ```
    pub fn revoke(lock: &RuntimeLockToken) -> Result<Revoked, EnclaveError> {
        let file = match HostKeyFile::load() {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                log_warn!(
                    "enclave",
                    "the host key record is unreadable ({e}); removing it"
                );
                true
            }
        };
        HostKeyFile::remove(lock).map_err(record_error)?;
        let store = match store::get().and_then(|held| {
            store::delete()?;
            Ok(held.is_some())
        }) {
            Ok(existed) => StoreOutcome::Cleared { existed },
            Err(e) => StoreOutcome::Unanswered(e),
        };
        Ok(Revoked { file, store })
    }

    fn from_scalar(scalar: &Scalar, store: KeyStore) -> Result<Self, EnclaveError> {
        let signing = SigningKey::from(scalar.secret_key());
        let point = signing.verifying_key().to_sec1_point(false);
        let public = EnclavePublicKey::from_x963(point.as_bytes().to_vec())?;
        super::ensure_not_fixture_key(&public)?;
        Ok(EnrollmentKey {
            signing,
            public,
            store,
        })
    }

    pub fn public_key(&self) -> &EnclavePublicKey {
        &self.public
    }

    pub fn store(&self) -> KeyStore {
        self.store
    }

    pub fn sign_challenge(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<[u8; SIG_LEN], EnclaveError> {
        self.sign_message(&challenge_message(nonce, context)?)
    }

    pub fn sign_policy(&self, doc_bytes: &[u8]) -> Result<[u8; SIG_LEN], EnclaveError> {
        self.sign_message(&policy_message(doc_bytes))
    }

    fn sign_message(&self, message: &[u8]) -> Result<[u8; SIG_LEN], EnclaveError> {
        let signature: Signature = self
            .signing
            .try_sign(message)
            .map_err(|e| EnclaveError::Signing(e.to_string()))?;
        Ok(signature.to_bytes().into())
    }
}

#[derive(Debug)]
pub struct Revoked {
    /// Whether a file key was in use (and is now removed).
    pub file: bool,
    pub store: StoreOutcome,
}

#[derive(Debug)]
pub enum StoreOutcome {
    /// The store answered and holds no entry now; `existed` says whether it held one before.
    Cleared { existed: bool },
    /// The store did not answer, so an entry it may hold could not be removed or ruled out.
    Unanswered(EnclaveError),
}

impl Revoked {
    /// Whether a key this machine was using is confirmed gone: the file key, or a store entry the store
    /// confirmed cleared. A store that did not answer confirms nothing on a store machine.
    pub fn key_in_use_is_gone(&self) -> bool {
        self.file || matches!(self.store, StoreOutcome::Cleared { .. })
    }

    pub fn existed(&self) -> bool {
        self.file || matches!(self.store, StoreOutcome::Cleared { existed: true })
    }
}

fn record_error(e: std::io::Error) -> EnclaveError {
    EnclaveError::Keychain(format!("host key record: {e}"))
}

/// Never leaks key material: the failure detail goes to stderr and the extension sees only the stable reason
/// code.
pub fn respond_to_challenge(nonce: &str, context: Option<&str>) -> EnclaveControl {
    match challenge_proof(nonce, context) {
        Ok(frame) => frame,
        Err(e) => {
            log_warn!("enclave", "challenge failed: {e}");
            EnclaveControl::EnclaveError {
                reason: reason_code(&e).to_string(),
            }
        }
    }
}

fn challenge_proof(nonce: &str, context: Option<&str>) -> Result<EnclaveControl, EnclaveError> {
    // Building the message is the validation; it runs before the store is touched so a malformed frame
    // costs no store round trip.
    challenge_message(nonce, context)?;
    let key = EnrollmentKey::lookup()?.ok_or(EnclaveError::NotEnrolled)?;
    let sig = key.sign_challenge(nonce, context)?;
    Ok(EnclaveControl::EnclaveProof {
        sig: base64_encode(&sig),
        key_id: key.public_key().fingerprint_hex(),
        pubkey: key.public_key().to_base64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::scratch_runtime_dir;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::VerifyingKey;

    fn mint(store: KeyStore) -> Result<EnrollmentKey, EnclaveError> {
        let auth = PresenceAttestation::assume_for_tests(crate::presence::PresencePath::Tty);
        crate::ipc::with_runtime_lock(|lock| Ok(EnrollmentKey::mint(lock, store, auth))).unwrap()
    }

    /// Whether the revoke found a key. A test build's store always answers empty, so the verdict's store side
    /// is pinned here once for every caller.
    fn revoke() -> Result<bool, EnclaveError> {
        let revoked =
            crate::ipc::with_runtime_lock(|lock| Ok(EnrollmentKey::revoke(lock))).unwrap()?;
        let store_cleared_empty = matches!(revoked.store, StoreOutcome::Cleared { existed: false });
        if !store_cleared_empty {
            return Err(EnclaveError::Keychain(format!(
                "a test build's store must answer empty: {revoked:?}"
            )));
        }
        Ok(revoked.existed())
    }

    /// What comes back from a lookup signs under the key the mint printed, the signature covers only its own
    /// challenge, and a second mint over an existing key is refused rather than replacing the pinned key.
    #[test]
    fn a_minted_file_key_is_found_again_signs_its_own_challenge_and_is_not_replaced() {
        let _dir = scratch_runtime_dir();
        assert!(EnrollmentKey::lookup().unwrap().is_none());

        let minted = mint(KeyStore::File).unwrap();
        assert_eq!(minted.store(), KeyStore::File);
        let found = EnrollmentKey::lookup().unwrap().expect("a record exists");
        assert_eq!(found.public_key(), minted.public_key());
        assert_eq!(
            reason_code(&mint(KeyStore::File).unwrap_err()),
            "key_invalid",
            "a second pair without --reset must not replace the key"
        );
        assert_eq!(
            EnrollmentKey::lookup().unwrap().unwrap().public_key(),
            minted.public_key()
        );

        let message = challenge_message("nonce", Some("ctx")).unwrap();
        let raw = found.sign_challenge("nonce", Some("ctx")).unwrap();
        let verifier = VerifyingKey::from_sec1_bytes(found.public_key().as_bytes()).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();
        assert!(verifier.verify(&message, &signature).is_ok());
        assert!(
            verifier
                .verify(
                    &challenge_message("other", Some("ctx")).unwrap(),
                    &signature
                )
                .is_err(),
            "a signature over one challenge must not cover another"
        );

        assert!(revoke().unwrap());
        assert!(EnrollmentKey::lookup().unwrap().is_none());
        assert!(!revoke().unwrap(), "a second revoke finds nothing");
    }

    /// A test build reaches no credential store: a mint into it fails with the stable code and leaves nothing
    /// behind (the file store stays open), and an unenrolled machine reads as such.
    #[test]
    fn an_unreachable_credential_store_refuses_the_mint_and_leaves_nothing() {
        let _dir = scratch_runtime_dir();
        let err = mint(KeyStore::CredentialStore).unwrap_err();
        assert_eq!(reason_code(&err), "keychain_error", "{err}");
        assert!(EnrollmentKey::lookup().unwrap().is_none());
        assert!(HostKeyFile::load().unwrap().is_none());
        assert!(!revoke().unwrap());
    }

    /// `pair --reset` is the advertised recovery from a damaged record, so revoke must remove a record it
    /// cannot read and the next lookup must read as unenrolled.
    #[test]
    fn revoke_removes_a_record_it_cannot_read() {
        let _dir = scratch_runtime_dir();
        std::fs::write(
            HostKeyFile::path().unwrap(),
            format!(r#"{{"version":{},"scalar":"AA=="}}"#, HostKeyFile::VERSION),
        )
        .unwrap();
        assert_eq!(
            reason_code(&EnrollmentKey::lookup().unwrap_err()),
            "keychain_error"
        );
        assert!(revoke().unwrap());
        assert!(EnrollmentKey::lookup().unwrap().is_none());
    }

    /// The NUL-in-nonce refusal happens before any store access (the challenge is parsed first), and an
    /// unenrolled machine answers not_enrolled.
    #[test]
    fn malformed_challenge_and_unenrolled_machine_answer_their_codes() {
        let _dir = scratch_runtime_dir();
        let EnclaveControl::EnclaveError { reason } = respond_to_challenge("a\0b", None) else {
            panic!("expected enclave_error");
        };
        assert_eq!(reason, "invalid_challenge");
        let EnclaveControl::EnclaveError { reason } = respond_to_challenge("nonce", None) else {
            panic!("expected enclave_error");
        };
        assert_eq!(reason, "not_enrolled");
    }

    /// A planted file record carrying the public fixture scalar never becomes a handle at all (so nothing can
    /// sign with it), and a planted zero or short scalar is refused at the record parse.
    #[test]
    fn planted_fixture_and_invalid_scalars_are_refused() {
        let _dir = scratch_runtime_dir();
        crate::ipc::with_runtime_lock(|lock| {
            HostKeyFile {
                scalar: Scalar::from_bytes(&super::super::FIXTURE_KEY_BYTES).unwrap(),
            }
            .write(lock)
        })
        .unwrap();
        assert_eq!(
            reason_code(&EnrollmentKey::lookup().unwrap_err()),
            "key_invalid"
        );
        let EnclaveControl::EnclaveError { reason } = respond_to_challenge("nonce", None) else {
            panic!("expected enclave_error");
        };
        assert_eq!(reason, "key_invalid");

        for (case, bytes) in [("zero", vec![0u8; 32]), ("31 bytes", vec![1u8; 31])] {
            let err = Scalar::from_bytes(&bytes).unwrap_err();
            assert_eq!(reason_code(&err), "key_invalid", "{case}");
        }
    }
}
