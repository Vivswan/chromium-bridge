//! Secure Enclave enrollment key: mint, look up, sign, revoke.
//!
//! The enrollment ceremony (ADR-0021) establishes trust between the extension
//! and this binary at `claude mcp add` time. The host mints a P-256 key inside
//! the Secure Enclave; the private key never leaves the Enclave and every use
//! is gated on user presence (Touch ID / password). The extension pins the
//! PUBLIC key and later verifies `enclave_proof` frames (see
//! [`crate::protocol::EnclaveControl`]) against it, so only a host that can
//! drive THIS machine's Enclave — with the user physically approving — can
//! complete an enrollment.
//!
//! Layout:
//! - Cross-platform pieces (challenge message construction, DER-to-P1363
//!   signature conversion, base64, the policy config, the CLI runners) live at
//!   the top level and are unit-tested everywhere.
//! - The keychain/Enclave backend is macOS-only (`mod sec`), built on the
//!   vetted `security-framework` crate — no hand-rolled Security.framework
//!   FFI. Other platforms get stubs that fail closed with
//!   [`EnclaveError::Unsupported`].

use std::fs;
use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::EnclaveControl;

/// Keychain label of the enrollment signing key. Stable across processes: the
/// `pair` CLI mints under this label and the Chrome-spawned `--native-host`
/// process finds the key by searching for it. Versioned so a future algorithm
/// change can mint under a new label without colliding with the old key.
pub const KEY_LABEL: &str = "com.browser-bridge.enclave.signing.v1";

/// Domain-separation prefix for challenge signatures. Binds every signature
/// this key produces to the enrollment protocol, so a proof can never be
/// replayed as a signature over some other meaning of the same bytes.
pub const CHALLENGE_DOMAIN: &str = "browser-bridge-enclave-v1";

/// Bounds on attacker-supplied challenge fields (the extension relays them
/// from its own logic today, but zero trust says bound them anyway).
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_CONTEXT_LEN: usize = 4096;

/// Typed failures for the enrollment key operations. The native host maps
/// these to the stable `enclave_error.reason` codes via [`reason_code`].
#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("Secure Enclave enrollment is only supported on macOS")]
    Unsupported,
    #[error("no enrollment key found — run `browser-bridge pair` first")]
    NotEnrolled,
    #[error("invalid challenge: {0}")]
    InvalidChallenge(&'static str),
    #[error("enrollment key rejected: {0}")]
    KeyInvalid(&'static str),
    #[error("keychain: {0}")]
    Keychain(String),
    #[error("signing: {0}")]
    Signing(String),
}

/// Stable machine-readable reason for an `enclave_error` frame. The extension
/// matches on these; keep them append-only.
pub fn reason_code(e: &EnclaveError) -> &'static str {
    match e {
        EnclaveError::Unsupported => "unsupported_platform",
        EnclaveError::NotEnrolled => "not_enrolled",
        EnclaveError::InvalidChallenge(_) => "invalid_challenge",
        EnclaveError::KeyInvalid(_) => "key_invalid",
        EnclaveError::Keychain(_) => "keychain_error",
        EnclaveError::Signing(_) => "signing_failed",
    }
}

// ----------------------------------------------------------------------------
// Challenge message construction (shared contract with the extension)
// ----------------------------------------------------------------------------

/// Build the exact byte string a challenge signature covers:
///
/// ```text
/// UTF8(CHALLENGE_DOMAIN) || 0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")
/// ```
///
/// The NUL separators make the encoding injective (no nonce/context pair can
/// collide with another), so both fields must be NUL-free; they are also
/// length-bounded. The extension must reconstruct this byte string exactly to
/// verify the proof with WebCrypto.
pub fn challenge_message(nonce: &str, context: Option<&str>) -> Result<Vec<u8>, EnclaveError> {
    if nonce.is_empty() {
        return Err(EnclaveError::InvalidChallenge("empty nonce"));
    }
    if nonce.len() > MAX_NONCE_LEN {
        return Err(EnclaveError::InvalidChallenge("nonce too long"));
    }
    if nonce.contains('\0') {
        return Err(EnclaveError::InvalidChallenge("nonce contains NUL"));
    }
    let context = context.unwrap_or("");
    if context.len() > MAX_CONTEXT_LEN {
        return Err(EnclaveError::InvalidChallenge("context too long"));
    }
    if context.contains('\0') {
        return Err(EnclaveError::InvalidChallenge("context contains NUL"));
    }
    let mut msg = Vec::with_capacity(CHALLENGE_DOMAIN.len() + nonce.len() + context.len() + 2);
    msg.extend_from_slice(CHALLENGE_DOMAIN.as_bytes());
    msg.push(0);
    msg.extend_from_slice(nonce.as_bytes());
    msg.push(0);
    msg.extend_from_slice(context.as_bytes());
    Ok(msg)
}

// ----------------------------------------------------------------------------
// DER (X9.62 ECDSA-Sig-Value) -> raw r||s (IEEE P1363, 64 bytes)
// ----------------------------------------------------------------------------

/// Convert a DER-encoded ECDSA P-256 signature (what `SecKeyCreateSignature`
/// returns) to the fixed 64-byte `r || s` form WebCrypto's `verify` expects.
///
/// The parser is strict DER: definite lengths only, positive minimally-encoded
/// integers, no trailing bytes. The input always comes from Security.framework
/// (which emits strict DER), so any deviation is treated as corruption and
/// rejected rather than repaired.
pub fn der_to_raw_signature(der: &[u8]) -> Result<[u8; 64], EnclaveError> {
    let bad = EnclaveError::Signing;

    // SEQUENCE header. A P-256 ECDSA-Sig-Value body is at most 70 bytes
    // (2 INTEGERs of at most 33 value bytes + 2-byte headers), and DER
    // requires the minimal length form, so a valid signature can only ever
    // use the one-byte short form. Any long-form length (0x80..) is either
    // non-minimal or claims an impossible size; reject both outright.
    let (&tag, rest) = der
        .split_first()
        .ok_or_else(|| bad("empty signature".into()))?;
    if tag != 0x30 {
        return Err(bad(format!("expected SEQUENCE (0x30), got 0x{tag:02x}")));
    }
    let (&len_byte, rest) = rest
        .split_first()
        .ok_or_else(|| bad("truncated SEQUENCE length".into()))?;
    if len_byte >= 0x80 {
        return Err(bad(format!(
            "long-form SEQUENCE length 0x{len_byte:02x} cannot occur in a P-256 signature"
        )));
    }
    let (seq_len, body) = (len_byte as usize, rest);
    if body.len() != seq_len {
        return Err(bad(format!(
            "SEQUENCE length {seq_len} does not match body length {}",
            body.len()
        )));
    }

    let (r, body) = der_read_integer(body)?;
    let (s, body) = der_read_integer(body)?;
    if !body.is_empty() {
        return Err(bad("trailing bytes after s".into()));
    }

    let mut out = [0u8; 64];
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Ok(out)
}

/// Read one strict-DER INTEGER holding a positive value of at most 32 bytes.
/// Returns the value bytes with any single sign-padding 0x00 stripped, plus
/// the remaining input.
fn der_read_integer(input: &[u8]) -> Result<(&[u8], &[u8]), EnclaveError> {
    let bad = EnclaveError::Signing;

    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| bad("truncated INTEGER".into()))?;
    if tag != 0x02 {
        return Err(bad(format!("expected INTEGER (0x02), got 0x{tag:02x}")));
    }
    let (&len, rest) = rest
        .split_first()
        .ok_or_else(|| bad("truncated INTEGER length".into()))?;
    let len = len as usize;
    // 33 = 32 value bytes + one 0x00 sign pad. Anything longer cannot be a
    // P-256 scalar; the long length form (>= 0x80) is impossible below 34.
    if len == 0 || len > 33 {
        return Err(bad(format!("INTEGER length {len} out of range")));
    }
    if rest.len() < len {
        return Err(bad("INTEGER runs past end of input".into()));
    }
    let (value, remaining) = rest.split_at(len);

    // Positive, minimally encoded: a leading 0x00 is legal only as sign
    // padding for a value whose top bit is set, and a top bit set without
    // that padding would encode a negative number.
    let stripped = if value[0] == 0x00 {
        if value.len() == 1 {
            // INTEGER 0 — impossible for a valid ECDSA r or s, but it is
            // well-formed DER; map it to 32 zero bytes and let the verifier
            // reject the signature.
            &value[..0]
        } else if value[1] & 0x80 == 0 {
            return Err(bad("non-minimal INTEGER encoding".into()));
        } else {
            &value[1..]
        }
    } else if value[0] & 0x80 != 0 {
        return Err(bad("negative INTEGER".into()));
    } else {
        value
    };
    if stripped.len() > 32 {
        return Err(bad(format!(
            "INTEGER value {} bytes exceeds the 32-byte P-256 scalar",
            stripped.len()
        )));
    }
    Ok((stripped, remaining))
}

// ----------------------------------------------------------------------------
// base64 (encode only — the proof frame carries sig + pubkey as base64)
// ----------------------------------------------------------------------------

/// Standard-alphabet base64 with padding (RFC 4648). Encode-only, so no
/// dependency is pulled in for one direction of one codec.
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ----------------------------------------------------------------------------
// Public key (65-byte X9.63 uncompressed P-256 point)
// ----------------------------------------------------------------------------

/// The enrollment key's public half, validated to be a 65-byte uncompressed
/// X9.63 P-256 point (`0x04 || X || Y`) — exactly what WebCrypto's
/// `importKey("raw", ...)` accepts for ECDSA P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclavePublicKey {
    sec1: Vec<u8>,
}

impl EnclavePublicKey {
    pub fn from_x963(bytes: Vec<u8>) -> Result<Self, EnclaveError> {
        if bytes.len() != 65 {
            return Err(EnclaveError::Keychain(format!(
                "public key is {} bytes, expected 65 (X9.63 uncompressed P-256)",
                bytes.len()
            )));
        }
        if bytes[0] != 0x04 {
            return Err(EnclaveError::Keychain(format!(
                "public key does not start with 0x04 (uncompressed point), got 0x{:02x}",
                bytes[0]
            )));
        }
        Ok(Self { sec1: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.sec1
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.sec1)
    }

    /// SHA-256 of the 65 raw point bytes, lowercase hex. This is the `key_id`
    /// in `enclave_proof` frames and the fingerprint the user compares between
    /// the `pair` terminal output and the extension's enrollment UI.
    pub fn fingerprint_hex(&self) -> String {
        crate::ipc::hex_encode(Sha256::digest(&self.sec1).as_slice())
    }

    /// Fingerprint grouped in 4-char blocks for human comparison.
    pub fn fingerprint_display(&self) -> String {
        let hex = self.fingerprint_hex();
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("hex is ascii"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ----------------------------------------------------------------------------
// Host policy config (runtime_dir()/config.json, 0600)
// ----------------------------------------------------------------------------

/// Enrollment policy recorded on disk. This is policy only — the key material
/// lives exclusively in the Secure Enclave / keychain, never here. The file is
/// informational for `doctor`/`enclave-status` and for the extension-side
/// enrollment flow; the security decisions are enforced by the keychain ACL
/// (presence-gated signing) and the extension's public-key pin, not by these
/// bits, so a same-user process editing this file gains nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// Whether a `pair` ceremony has completed on this machine.
    pub enrolled: bool,
    /// Verification granularity the user selected. Only "session" exists
    /// today (one presence proof per enrollment; reconnects are not
    /// presence-gated — see ADR-0021 for why and what that leaves open).
    pub granularity: String,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            enrolled: false,
            granularity: "session".into(),
        }
    }
}

impl HostConfig {
    pub fn path() -> std::path::PathBuf {
        crate::ipc::runtime_dir().join("config.json")
    }

    pub fn read() -> io::Result<Option<Self>> {
        match fs::read(Self::path()) {
            Ok(bytes) => {
                let cfg: HostConfig = serde_json::from_slice(&bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("config decode: {e}"))
                })?;
                Ok(Some(cfg))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write atomically (temp file + rename), 0600 on Unix, mirroring
    /// [`crate::ipc::LockFile::write`].
    pub fn write(&self) -> io::Result<()> {
        let path = Self::path();
        let mut tmp = path.clone();
        tmp.set_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        #[cfg(not(unix))]
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn remove() {
        let _ = fs::remove_file(Self::path());
    }
}

// ----------------------------------------------------------------------------
// macOS keychain / Secure Enclave backend (vetted crate, no bespoke FFI)
// ----------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod sec {
    use core_foundation::base::{TCFType, ToVoid};
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

    use super::{der_to_raw_signature, EnclaveError, EnclavePublicKey, KEY_LABEL};

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
        let token = unsafe { CFString::wrap_under_get_rule(v.cast()) };
        let expected = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
        token == expected
    }

    /// Find the enrollment key by its stable label, failing closed unless it
    /// is unambiguous and Enclave-resident. Cross-process: the `pair` CLI
    /// mints it, the Chrome-spawned native host finds it here. Obtaining the
    /// reference does not trigger a presence prompt — only using the private
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
        match keys.len() {
            0 => Ok(None),
            1 => {
                let key = keys.pop().expect("len checked");
                if is_secure_enclave_key(&key) {
                    Ok(Some(key))
                } else {
                    Err(EnclaveError::KeyInvalid(
                        "the key under the enrollment label is not a Secure Enclave key",
                    ))
                }
            }
            _ => Err(EnclaveError::KeyInvalid(
                "multiple keys exist under the enrollment label",
            )),
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
}

// ----------------------------------------------------------------------------
// Cross-platform enrollment key handle
// ----------------------------------------------------------------------------

/// Handle to the (Enclave-resident) enrollment key. On macOS it wraps a
/// `SecKey`; on other platforms it cannot be constructed and every entry
/// point fails closed with [`EnclaveError::Unsupported`].
pub struct EnrollmentKey {
    #[cfg(target_os = "macos")]
    key: security_framework::key::SecKey,
}

impl EnrollmentKey {
    /// Look up the enrollment key minted by a previous `pair`.
    pub fn lookup() -> Result<Option<Self>, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            Ok(sec::lookup()?.map(|key| Self { key }))
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Mint a fresh enrollment key in the Secure Enclave.
    pub fn mint() -> Result<Self, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                key: sec::generate()?,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Delete the enrollment key wherever it is stored. Returns whether one
    /// existed.
    pub fn revoke() -> Result<bool, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            sec::delete()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    pub fn public_key(&self) -> Result<EnclavePublicKey, EnclaveError> {
        #[cfg(target_os = "macos")]
        {
            sec::public_key(&self.key)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(EnclaveError::Unsupported)
        }
    }

    /// Sign a challenge (raises the presence prompt) and return the raw
    /// 64-byte P1363 signature.
    pub fn sign_challenge(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<[u8; 64], EnclaveError> {
        let message = challenge_message(nonce, context)?;
        #[cfg(target_os = "macos")]
        {
            sec::sign(&self.key, &message)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = message;
            Err(EnclaveError::Unsupported)
        }
    }
}

// ----------------------------------------------------------------------------
// Native-host challenge handling
// ----------------------------------------------------------------------------

/// Answer an `enclave_challenge` control frame: look the key up, sign the
/// challenge (presence prompt), and build the proof — or a typed error frame.
/// Never panics and never leaks key material; detailed failure context goes to
/// stderr, the extension only sees the stable reason code.
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
    // Validate the challenge before touching the keychain, so malformed input
    // cannot trigger a presence prompt.
    challenge_message(nonce, context)?;
    let key = EnrollmentKey::lookup()?.ok_or(EnclaveError::NotEnrolled)?;
    let public = key.public_key()?;
    let sig = key.sign_challenge(nonce, context)?;
    Ok(EnclaveControl::EnclaveProof {
        sig: base64_encode(&sig),
        key_id: public.fingerprint_hex(),
        pubkey: public.to_base64(),
    })
}

// ----------------------------------------------------------------------------
// CLI: pair / revoke / enclave-status
// ----------------------------------------------------------------------------

/// `browser-bridge pair [--reset]`: the user-present half of the enrollment
/// ceremony. Mints the Enclave key (or reports the existing one), runs a
/// presence-gated self-test signature so the user proves Touch ID works right
/// now, and prints the public key + fingerprint for the user to compare
/// against the extension's enrollment UI.
pub fn run_pair(reset: bool) -> i32 {
    // A pre-existing key is never adopted, with or without a valid look: any
    // same-user process can plant a key under our label (even an Enclave key,
    // minted without a presence ACL), and public API cannot read the ACL back
    // to tell the difference. The only key `pair` can vouch for is one it
    // minted itself in this run, with the ACL it set itself. So the ceremony
    // completes exclusively with a fresh mint; anything already there means
    // stop (or, with --reset, delete it all and start clean).
    let existing = match EnrollmentKey::lookup() {
        Ok(k) => k.is_some(),
        Err(EnclaveError::Unsupported) => {
            println!("pair failed: {}", EnclaveError::Unsupported);
            return 1;
        }
        // KeyInvalid (planted software key, duplicate labels) and keychain
        // errors both mean "something is there that we did not just mint".
        Err(e) => {
            println!("note: the existing enrollment state is suspect: {e}");
            true
        }
    };

    if existing {
        if !reset {
            println!(
                "an enrollment key already exists on this machine; nothing was changed.\n\
                 pairing only completes with a freshly minted key, so to (re-)enroll run:\n\
                 \n    browser-bridge pair --reset\n\
                 \n\
                 to inspect the current key, run: browser-bridge enclave-status\n\
                 if you never enrolled this machine yourself, treat the existing key as\n\
                 untrusted and run the reset."
            );
            return 1;
        }
        match EnrollmentKey::revoke() {
            Ok(_) => {
                // The old key is gone, so any recorded enrollment is void.
                // Clear it now so a failure later in this run cannot leave a
                // config claiming enrolled=true with no key behind it.
                HostConfig::remove();
                println!("removed the previous enrollment key.");
            }
            Err(e) => {
                println!("pair --reset failed to remove the old key: {e}");
                return 1;
            }
        }
    }

    let key = match EnrollmentKey::mint() {
        Ok(k) => k,
        Err(e) => {
            println!("pair failed to mint the enrollment key: {e}");
            HostConfig::remove();
            return 1;
        }
    };
    let public = match key.public_key() {
        Ok(p) => p,
        Err(e) => {
            println!("pair failed to export the public key: {e}");
            let _ = EnrollmentKey::revoke();
            HostConfig::remove();
            return 1;
        }
    };

    // Presence self-test: one signature, which raises Touch ID. This is the
    // actual user-present step of the ceremony; declining it must leave the
    // machine unenrolled, so on failure the freshly minted key is deleted.
    println!("confirm with Touch ID (or your password) to finish pairing...");
    let selftest_nonce = match crate::ipc::generate_secret() {
        Ok(s) => format!("pair-selftest-{s}"),
        Err(e) => {
            println!("pair failed to generate a self-test nonce ({e}); rolling back.");
            let _ = EnrollmentKey::revoke();
            HostConfig::remove();
            return 1;
        }
    };
    if let Err(e) = key.sign_challenge(&selftest_nonce, None) {
        println!("pairing was not approved ({e}); rolling back.");
        let _ = EnrollmentKey::revoke();
        HostConfig::remove();
        return 1;
    }

    let cfg = HostConfig {
        enrolled: true,
        ..HostConfig::default()
    };
    if let Err(e) = cfg.write() {
        println!("pair failed to record the enrollment policy: {e}");
        let _ = EnrollmentKey::revoke();
        return 1;
    }

    println!("enrolled.");
    print_public_key(&public);
    println!(
        "\nnext: open the extension's enrollment screen and check it shows\n\
         EXACTLY this fingerprint before approving."
    );
    0
}

/// `browser-bridge revoke` (also `pair --reset` uses the same deletion):
/// delete the enrollment key and the recorded policy. Fail-closed by
/// construction — after this, proofs can no longer be produced, so a pinned
/// extension refuses the bridge until the user re-pairs.
pub fn run_revoke() -> i32 {
    match EnrollmentKey::revoke() {
        Ok(true) => {
            HostConfig::remove();
            println!("enrollment key revoked. re-run `browser-bridge pair` to re-enroll.");
            0
        }
        Ok(false) => {
            HostConfig::remove();
            println!("no enrollment key found; nothing to revoke.");
            0
        }
        Err(e) => {
            println!("revoke failed: {e}");
            1
        }
    }
}

/// `browser-bridge enclave-status`: read-only report on the enrollment state.
pub fn run_status() -> i32 {
    println!("browser-bridge enclave-status");
    if cfg!(target_os = "macos") {
        println!("platform:   macos (Secure Enclave supported)");
    } else {
        println!(
            "platform:   {} (Secure Enclave NOT supported)",
            std::env::consts::OS
        );
    }

    match EnrollmentKey::lookup() {
        Ok(Some(key)) => match key.public_key() {
            Ok(public) => {
                println!("key:        present ({KEY_LABEL})");
                print_public_key(&public);
            }
            Err(e) => println!("key:        present, but public key unreadable: {e}"),
        },
        Ok(None) => println!("key:        none (run `browser-bridge pair`)"),
        Err(EnclaveError::Unsupported) => println!("key:        n/a"),
        Err(e @ EnclaveError::KeyInvalid(_)) => println!(
            "key:        REJECTED — {e}\n            treat it as untrusted; \
             run `browser-bridge pair --reset` to replace it"
        ),
        Err(e) => println!("key:        lookup failed: {e}"),
    }

    match HostConfig::read() {
        Ok(Some(cfg)) => println!(
            "policy:     enrolled={} granularity={} ({})",
            cfg.enrolled,
            cfg.granularity,
            HostConfig::path().display()
        ),
        Ok(None) => println!("policy:     no config ({})", HostConfig::path().display()),
        Err(e) => println!("policy:     unreadable: {e}"),
    }
    0
}

fn print_public_key(public: &EnclavePublicKey) {
    println!("public key: {}", public.to_base64());
    println!("fingerprint (sha256):");
    println!("  {}", public.fingerprint_display());
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal strict-DER encoder for ECDSA-Sig-Value, used to build test
    /// vectors and roundtrip against the parser. Test-only on purpose: the
    /// production path never needs to *emit* DER.
    fn raw_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        fn integer(v: &[u8; 32]) -> Vec<u8> {
            let mut trimmed: &[u8] = v;
            while trimmed.len() > 1 && trimmed[0] == 0 {
                trimmed = &trimmed[1..];
            }
            let pad = trimmed[0] & 0x80 != 0;
            let mut out = vec![0x02, (trimmed.len() + usize::from(pad)) as u8];
            if pad {
                out.push(0x00);
            }
            out.extend_from_slice(trimmed);
            out
        }
        let body: Vec<u8> = [integer(r), integer(s)].concat();
        let mut out = vec![0x30];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x81);
            out.push(body.len() as u8);
        }
        out.extend(body);
        out
    }

    fn filled(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn der_roundtrip_plain_values() {
        // Top bits clear: 32-byte integers, no sign padding.
        let r = filled(0x11);
        let s = filled(0x7f);
        let der = raw_to_der(&r, &s);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_roundtrip_high_bit_needs_sign_padding() {
        // Top bit set: DER carries a 33-byte INTEGER with a 0x00 sign pad —
        // the most likely first bug in a naive converter.
        let r = filled(0x80);
        let s = filled(0xff);
        let der = raw_to_der(&r, &s);
        // Both integers must be 33 bytes on the wire.
        assert_eq!(der[3], 33);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_roundtrip_short_values_left_pad() {
        // Leading zero bytes are absent in DER; the converter must left-pad
        // back to 32 bytes.
        let mut r = [0u8; 32];
        r[31] = 0x01; // value 1 -> one-byte INTEGER
        let mut s = [0u8; 32];
        s[30] = 0x02;
        s[31] = 0x03; // two-byte INTEGER
        let der = raw_to_der(&r, &s);
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn der_zero_integer_is_wellformed() {
        // INTEGER 0 is valid DER (never a valid ECDSA scalar; the verifier
        // rejects the signature, not the parser).
        let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let raw = der_to_raw_signature(&der).unwrap();
        assert_eq!(raw, [0u8; 64]);
    }

    #[test]
    fn der_long_form_length_is_rejected() {
        // Two 33-byte integers make the maximum body: 70 bytes, still short
        // form. DER's minimal-length rule means a valid P-256 signature can
        // never use the long form, so a long-form length is corruption even
        // when its value is internally consistent.
        let r = filled(0xaa);
        let s = filled(0xbb);
        let der = raw_to_der(&r, &s);
        assert_eq!(der[1], 70); // the biggest possible body is still short form
        let mut long = vec![0x30, 0x81, 70];
        long.extend_from_slice(&der[2..]);
        assert!(der_to_raw_signature(&long).is_err());
    }

    #[test]
    fn der_rejects_malformed_inputs() {
        let ok = raw_to_der(&filled(0x22), &filled(0x33));

        // Empty / truncated.
        assert!(der_to_raw_signature(&[]).is_err());
        assert!(der_to_raw_signature(&ok[..ok.len() - 1]).is_err());
        // Wrong outer tag.
        let mut bad = ok.clone();
        bad[0] = 0x31;
        assert!(der_to_raw_signature(&bad).is_err());
        // Wrong inner tag.
        let mut bad = ok.clone();
        bad[2] = 0x03;
        assert!(der_to_raw_signature(&bad).is_err());
        // Trailing garbage.
        let mut bad = ok.clone();
        bad.push(0x00);
        assert!(der_to_raw_signature(&bad).is_err());
        // Sequence length that overshoots the body.
        let mut bad = ok.clone();
        bad[1] += 1;
        assert!(der_to_raw_signature(&bad).is_err());
        // Negative integer (top bit set, no sign pad).
        let neg = [0x30, 0x08, 0x02, 0x02, 0x80, 0x01, 0x02, 0x02, 0x00, 0x81];
        assert!(der_to_raw_signature(&neg).is_err());
        // Non-minimal encoding (0x00 pad over a low top bit).
        let nonmin = [0x30, 0x08, 0x02, 0x03, 0x00, 0x01, 0x02, 0x02, 0x01, 0x02];
        assert!(der_to_raw_signature(&nonmin).is_err());
        // Zero-length integer.
        let empty_int = [0x30, 0x04, 0x02, 0x00, 0x02, 0x00];
        assert!(der_to_raw_signature(&empty_int).is_err());
        // Oversize integer: 33 value bytes without a legal sign pad.
        let mut oversize = vec![0x30, 72, 0x02, 34, 0x00];
        oversize.extend_from_slice(&[0x01; 33]);
        oversize.extend_from_slice(&[0x02, 32]);
        oversize.extend_from_slice(&[0x01; 32]);
        assert!(der_to_raw_signature(&oversize).is_err());
        // Unsupported multi-byte long form (cannot occur for P-256).
        let multi = [0x30, 0x82, 0x00, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(der_to_raw_signature(&multi).is_err());
    }

    mod der_fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Roundtrip: any (r, s) pair survives encode -> parse.
            #[test]
            fn roundtrip(r in prop::array::uniform32(any::<u8>()),
                         s in prop::array::uniform32(any::<u8>())) {
                let der = raw_to_der(&r, &s);
                let raw = der_to_raw_signature(&der).unwrap();
                prop_assert_eq!(&raw[..32], &r[..]);
                prop_assert_eq!(&raw[32..], &s[..]);
            }

            /// The parser never panics on arbitrary bytes (it runs on frames
            /// that cross a process boundary).
            #[test]
            fn never_panics(data in prop::collection::vec(any::<u8>(), 0..128)) {
                let _ = der_to_raw_signature(&data);
            }
        }
    }

    #[test]
    fn challenge_message_is_domain_separated_and_injective() {
        let m = challenge_message("abc", Some("ctx")).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(CHALLENGE_DOMAIN.as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"abc");
        expected.push(0);
        expected.extend_from_slice(b"ctx");
        assert_eq!(m, expected);

        // No context serializes as an empty context, and cannot collide with
        // a nonce that happens to contain the other field's bytes.
        assert_eq!(
            challenge_message("abc", None).unwrap(),
            challenge_message("abc", Some("")).unwrap()
        );
        assert_ne!(
            challenge_message("ab", Some("c")).unwrap(),
            challenge_message("abc", None).unwrap()
        );
    }

    #[test]
    fn challenge_message_rejects_bad_fields() {
        assert!(matches!(
            challenge_message("", None),
            Err(EnclaveError::InvalidChallenge(_))
        ));
        assert!(challenge_message(&"x".repeat(MAX_NONCE_LEN + 1), None).is_err());
        assert!(challenge_message("a\0b", None).is_err());
        assert!(challenge_message("ok", Some("a\0b")).is_err());
        assert!(challenge_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN + 1))).is_err());
        // At the bounds is fine.
        assert!(challenge_message(&"x".repeat(MAX_NONCE_LEN), None).is_ok());
        assert!(challenge_message("ok", Some(&"x".repeat(MAX_CONTEXT_LEN))).is_ok());
    }

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn public_key_parse_validates_shape() {
        let mut good = vec![0x04];
        good.extend_from_slice(&[0xab; 64]);
        let pk = EnclavePublicKey::from_x963(good.clone()).unwrap();
        assert_eq!(pk.as_bytes(), &good[..]);
        assert_eq!(pk.fingerprint_hex().len(), 64);
        // Grouped display covers the same hex.
        assert_eq!(
            pk.fingerprint_display().replace(' ', ""),
            pk.fingerprint_hex()
        );

        // Wrong length.
        assert!(EnclavePublicKey::from_x963(vec![0x04; 64]).is_err());
        assert!(EnclavePublicKey::from_x963(vec![0x04; 66]).is_err());
        assert!(EnclavePublicKey::from_x963(Vec::new()).is_err());
        // Compressed-point prefix is rejected: the contract is uncompressed.
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0xab; 64]);
        assert!(EnclavePublicKey::from_x963(compressed).is_err());
    }

    #[test]
    fn host_config_serde_roundtrip_and_default() {
        let cfg = HostConfig::default();
        assert!(!cfg.enrolled);
        assert_eq!(cfg.granularity, "session");
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: HostConfig = serde_json::from_slice(&bytes).unwrap();
        assert!(!back.enrolled);
        assert_eq!(back.granularity, "session");
        assert_eq!(HostConfig::path().file_name().unwrap(), "config.json");
    }

    /// Sign/verify roundtrip against a real Security.framework signer, using a
    /// SOFTWARE P-256 key (no Enclave token, no presence ACL, not permanent),
    /// so nothing prompts and nothing is written to any keychain. This pins
    /// the DER conversion against genuine SecKeyCreateSignature output.
    #[cfg(target_os = "macos")]
    #[test]
    fn software_key_sign_convert_verify_roundtrip() {
        use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

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
    /// signature — guards against the converter accidentally producing
    /// something "verifiable" by construction.
    #[cfg(target_os = "macos")]
    #[test]
    fn software_key_rejects_wrong_message_and_tampered_sig() {
        use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

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
    #[cfg(target_os = "macos")]
    #[test]
    fn software_key_is_rejected_by_the_enclave_token_check() {
        use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};

        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software);
        let key = SecKey::new(&opts).expect("software P-256 keygen");
        assert!(!super::sec::is_secure_enclave_key(&key));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_fails_closed_with_unsupported() {
        assert!(matches!(
            EnrollmentKey::lookup(),
            Err(EnclaveError::Unsupported)
        ));
        assert!(matches!(
            EnrollmentKey::mint(),
            Err(EnclaveError::Unsupported)
        ));
        assert!(matches!(
            EnrollmentKey::revoke(),
            Err(EnclaveError::Unsupported)
        ));
        // And the challenge path reports the stable reason code.
        match respond_to_challenge("nonce", None) {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "unsupported_platform");
            }
            other => panic!("expected enclave_error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_challenge_yields_invalid_challenge_before_any_keychain_io() {
        // NUL in the nonce: rejected by validation, so the reply is
        // invalid_challenge on every platform (no keychain lookup happens).
        match respond_to_challenge("a\0b", None) {
            EnclaveControl::EnclaveError { reason } => {
                assert_eq!(reason, "invalid_challenge");
            }
            other => panic!("expected enclave_error, got {other:?}"),
        }
    }
}
