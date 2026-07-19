//! macOS keychain / Secure Enclave backend (vetted crate, no bespoke FFI).
// Quarantined unsafe: CoreFoundation constant access for the Secure Enclave
// token-id check (the wrapper crate does not re-export it). unsafe_code is
// denied workspace-wide; this module is one of the audited exceptions.
#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType, ToVoid};
use core_foundation::string::CFString;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};

use super::der::der_to_raw_signature;
use super::pubkey::EnclavePublicKey;
use super::{EnclaveError, KEY_LABEL};

/// Mint the enrollment key inside the Secure Enclave. The ACL requires
/// USER_PRESENCE for every private-key operation (Touch ID or the login
/// password) plus PRIVATE_KEY_USAGE (mandatory for Enclave keys), and the
/// key is accessible only while this device is unlocked and never syncs
/// off the device.
pub(super) fn generate() -> Result<SecKey, EnclaveError> {
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlUserPresence | kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|e| EnclaveError::Keychain(format!("create access control: {e}")))?;

    let mut opts = GenerateKeyOptions::default();
    // Setting a location is what makes the key permanent
    // (GenerateKeyOptions derives kSecAttrIsPermanent from location being
    // set); the data-protection keychain is the only keychain that can
    // hold Secure Enclave keys.
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_label(KEY_LABEL)
        .set_token(Token::SecureEnclave)
        .set_location(Location::DataProtectionKeychain)
        .set_access_control(access);
    let key = SecKey::new(&opts).map_err(|e| {
        EnclaveError::Keychain(format!(
            "SecKeyCreateRandomKey (Secure Enclave): {e}. Note: the \
             data-protection keychain requires this binary to be \
             codesigned with an application identifier; an ad-hoc dev \
             build cannot store Enclave keys."
        ))
    })?;
    // Belt and braces: refuse to hand out a key that does not carry the
    // Secure Enclave token, even one we just asked for.
    if !is_secure_enclave_key(&key) {
        let _ = key.delete();
        return Err(EnclaveError::KeyInvalid(
            "freshly minted key does not carry the Secure Enclave token",
        ));
    }
    Ok(key)
}

/// Whether a key's attributes carry the Secure Enclave token id. Any
/// same-user process can create a keychain key under our label, so a key
/// found by label proves nothing by itself; a software key would sign
/// without the Enclave and without any presence prompt. The token id is
/// the discriminator: a `com.apple.setoken` key is Enclave-resident by
/// construction. (The presence flag on the ACL is not readable back
/// through public API, so an Enclave key minted by an attacker without a
/// presence ACL is still accepted here; see ADR-0021 for why `pair` never
/// trusts a pre-existing key at ceremony time.)
pub(super) fn is_secure_enclave_key(key: &SecKey) -> bool {
    let attrs = key.attributes();
    let Some(v) = attrs.find(unsafe { kSecAttrTokenID }.to_void()) else {
        return false;
    };
    // SAFETY: get-rule wrap (CFRetain only, released on drop) of the borrowed
    // dictionary value, as the type-agnostic CFType - no assumption yet about
    // the value's concrete type.
    let token = unsafe { CFType::wrap_under_get_rule(*v) };
    // The Keychain contract says kSecAttrTokenID's value is a CFString;
    // verify with a checked downcast (CFGetTypeID) rather than trust it. A
    // non-string value fails closed as "not an Enclave key".
    let Some(token) = token.downcast::<CFString>() else {
        return false;
    };
    // SAFETY: get-rule wrap of a non-null framework constant CFString.
    let expected = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
    token == expected
}

/// Find the enrollment key by its stable label, failing closed unless it
/// is unambiguous and Enclave-resident. Cross-process: the `pair` CLI
/// mints it, the Chrome-spawned native host finds it here. Obtaining the
/// reference does not trigger a presence prompt - only using the private
/// key does.
///
/// Two fail-closed rules beyond the label match:
/// - More than one key under the label is ambiguity, not a choice to make
///   silently; refuse rather than pick one.
/// - A key without the Secure Enclave token is a planted or corrupted
///   key; refuse rather than sign with it.
pub(super) fn lookup() -> Result<Option<SecKey>, EnclaveError> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(KEY_LABEL)
        // Search the data-protection keychain, where Enclave keys live.
        .ignore_legacy_keychains()
        .load_refs(true)
        .limit(Limit::Max(2));
    let results = match search.search() {
        Ok(results) => results,
        Err(e) if e.code() == errSecItemNotFound => return Ok(None),
        Err(e) => return Err(EnclaveError::Keychain(format!("keychain search: {e}"))),
    };
    let mut keys: Vec<SecKey> = results
        .into_iter()
        .filter_map(|r| match r {
            SearchResult::Ref(Reference::Key(k)) => Some(k),
            _ => None,
        })
        .collect();
    if keys.len() > 1 {
        return Err(EnclaveError::KeyInvalid(
            "multiple keys exist under the enrollment label",
        ));
    }
    match keys.pop() {
        None => Ok(None),
        Some(key) => {
            if is_secure_enclave_key(&key) {
                Ok(Some(key))
            } else {
                Err(EnclaveError::KeyInvalid(
                    "the key under the enrollment label is not a Secure Enclave key",
                ))
            }
        }
    }
}

/// Delete every key under the enrollment label (including planted
/// duplicates). Returns whether anything existed. Deletion is
/// deliberately not presence-gated: the keychain cannot gate SecItemDelete
/// on the key's usage ACL, and removing the key only ever reduces
/// capability (the extension's pin then fails closed).
pub(super) fn delete() -> Result<bool, EnclaveError> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(KEY_LABEL)
        .ignore_legacy_keychains();
    match search.delete() {
        Ok(()) => Ok(true),
        Err(e) if e.code() == errSecItemNotFound => Ok(false),
        Err(e) => Err(EnclaveError::Keychain(format!("keychain delete: {e}"))),
    }
}

/// Sign `message` with the Enclave key; raises the user-presence prompt.
/// Returns the raw 64-byte P1363 signature the extension verifies.
pub(super) fn sign(key: &SecKey, message: &[u8]) -> Result<[u8; 64], EnclaveError> {
    let der = key
        .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
        .map_err(|e| EnclaveError::Signing(format!("SecKeyCreateSignature: {e}")))?;
    der_to_raw_signature(&der)
}

/// Export the public half as a validated 65-byte X9.63 point.
pub(super) fn public_key(key: &SecKey) -> Result<EnclavePublicKey, EnclaveError> {
    let public = key
        .public_key()
        .ok_or_else(|| EnclaveError::Keychain("key has no public half".into()))?;
    let data = public.external_representation().ok_or_else(|| {
        EnclaveError::Keychain("public key has no external representation".into())
    })?;
    EnclavePublicKey::from_x963(data.bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::super::challenge::challenge_message;
    use super::super::der::raw_to_der;
    use super::*;

    /// Sign/verify roundtrip against a real Security.framework signer, using a
    /// SOFTWARE P-256 key (no Enclave token, no presence ACL, not permanent),
    /// so nothing prompts and nothing is written to any keychain. This pins
    /// the DER conversion against genuine SecKeyCreateSignature output.
    #[test]
    fn software_key_sign_convert_verify_roundtrip() {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        let key = SecKey::new(&opts).expect("software P-256 keygen");

        // The public half is a 65-byte X9.63 uncompressed point, as the
        // contract (and the extension's WebCrypto import) requires.
        let public = key.public_key().expect("public half");
        let point = public.external_representation().expect("export");
        let parsed = EnclavePublicKey::from_x963(point.bytes().to_vec()).unwrap();
        assert_eq!(parsed.as_bytes().len(), 65);

        let message = challenge_message("roundtrip-nonce", Some("roundtrip-ctx")).unwrap();
        for _ in 0..8 {
            let der = key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, &message)
                .expect("sign");
            // The DER form verifies...
            assert!(public
                .verify_signature(Algorithm::ECDSASignatureMessageX962SHA256, &message, &der)
                .expect("verify"));
            // ...and converts to raw and back to an equivalent DER that still
            // verifies, proving the converter preserves (r, s) exactly.
            let raw = der_to_raw_signature(&der).expect("der->raw");
            let r: [u8; 32] = raw[..32].try_into().unwrap();
            let s: [u8; 32] = raw[32..].try_into().unwrap();
            let reencoded = raw_to_der(&r, &s);
            assert!(public
                .verify_signature(
                    Algorithm::ECDSASignatureMessageX962SHA256,
                    &message,
                    &reencoded
                )
                .expect("verify reencoded"));
        }
    }

    /// The signature must not verify under a different message or a tampered
    /// signature - guards against the converter accidentally producing
    /// something "verifiable" by construction.
    #[test]
    fn software_key_rejects_wrong_message_and_tampered_sig() {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        let key = SecKey::new(&opts).expect("software P-256 keygen");
        let public = key.public_key().expect("public half");

        let message = challenge_message("nonce-1", None).unwrap();
        let other = challenge_message("nonce-2", None).unwrap();
        let der = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, &message)
            .expect("sign");
        // Security.framework reports a mismatch either as Ok(false) or as a
        // CSSM verify-failed error; both are a rejection.
        if let Ok(valid) =
            public.verify_signature(Algorithm::ECDSASignatureMessageX962SHA256, &other, &der)
        {
            assert!(!valid);
        }

        let raw = der_to_raw_signature(&der).unwrap();
        let mut tampered = raw;
        tampered[0] ^= 0x01;
        let r: [u8; 32] = tampered[..32].try_into().unwrap();
        let s: [u8; 32] = tampered[32..].try_into().unwrap();
        let bad_der = raw_to_der(&r, &s);
        // Either the point math rejects it (Ok(false)) or Security.framework
        // reports a verification error; both are a rejection.
        if let Ok(valid) = public.verify_signature(
            Algorithm::ECDSASignatureMessageX962SHA256,
            &message,
            &bad_der,
        ) {
            assert!(!valid);
        }
    }

    /// A software key with our label must be rejected by the attribute check:
    /// this is the planted-key defense (a same-user process creating a
    /// non-Enclave key under `KEY_LABEL` must not be signable-with).
    #[test]
    fn software_key_is_rejected_by_the_enclave_token_check() {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        let key = SecKey::new(&opts).expect("software P-256 keygen");
        assert!(!is_secure_enclave_key(&key));
    }
}
