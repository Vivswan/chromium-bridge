//! The statement a WebAuthn signature covers, and the challenge derived from it. Same domain-separation
//! design as the enclave challenge: NUL-separated fields under a domain prefix, every field NUL-free, so
//! no two statements share bytes and a presence statement can never be replayed as an enrollment one.

use std::io;

use sha2::{Digest, Sha256};

use crate::ipc::BrowserLabel;

use super::base64url;

/// Domain prefix of a per-action presence statement (the tap that approves one capability-granting act).
pub const PRESENCE_DOMAIN: &str = "chromium-bridge-webauthn-presence-v1";

/// Domain prefix of an enrollment statement (the tap that registers a new credential).
pub const ENROLL_DOMAIN: &str = "chromium-bridge-webauthn-enroll-v1";

/// Bounds on the statement fields the extension echoes back; the host mints them, zero trust bounds them anyway.
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_ACTION_LEN: usize = 1024;

/// Which ceremony a statement belongs to; the two domains are distinct and neither is a prefix of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementDomain {
    Presence,
    Enrollment,
}

impl StatementDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            StatementDomain::Presence => PRESENCE_DOMAIN,
            StatementDomain::Enrollment => ENROLL_DOMAIN,
        }
    }
}

/// A single-use statement nonce: 1..=[`MAX_NONCE_LEN`] bytes, NUL-free. [`fresh`](Self::fresh) mints the one
/// the host uses (32 CSPRNG bytes, base64url); [`parse`](Self::parse) is the wire boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(String);

impl Nonce {
    pub fn parse(s: &str) -> Option<Self> {
        nul_free_bounded(s, MAX_NONCE_LEN).then(|| Nonce(s.to_string()))
    }

    pub fn fresh() -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        Ok(Nonce(base64url::encode(&bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the user is approving, as the host names it (the audit trail and the extension's prompt show it):
/// 1..=[`MAX_ACTION_LEN`] bytes, NUL-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action(String);

impl Action {
    // The host's own two acts: literals inside the bound, so neither can fail `parse`.
    pub fn enroll() -> Self {
        Action("enroll".to_string())
    }

    pub fn release_kill_switch() -> Self {
        Action("release the kill switch".to_string())
    }

    pub fn parse(s: &str) -> Option<Self> {
        nul_free_bounded(s, MAX_ACTION_LEN).then(|| Action(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn nul_free_bounded(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.contains('\0')
}

/// The statement one WebAuthn signature covers. Every field is a validated newtype, so a statement that
/// exists encodes injectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub domain: StatementDomain,
    pub browser_label: BrowserLabel,
    pub action: Action,
    pub nonce: Nonce,
}

impl Statement {
    /// `UTF8(domain) || 0x00 || UTF8(label) || 0x00 || UTF8(action) || 0x00 || UTF8(nonce)`.
    pub fn message(&self) -> Vec<u8> {
        let parts = [
            self.domain.as_str(),
            self.browser_label.as_str(),
            self.action.as_str(),
            self.nonce.as_str(),
        ];
        let mut msg = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                msg.push(0);
            }
            msg.extend_from_slice(part.as_bytes());
        }
        msg
    }

    /// The WebAuthn challenge: SHA-256 of [`message`](Self::message). The extension passes it to the
    /// authenticator verbatim, and the client echoes it as base64url in `clientDataJSON.challenge`.
    pub fn challenge(&self) -> Challenge {
        Challenge(Sha256::digest(self.message()).into())
    }
}

/// The 32-byte challenge an authenticator signs over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge([u8; 32]);

impl Challenge {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The spelling `clientDataJSON.challenge` must carry.
    pub fn to_base64url(&self) -> String {
        base64url::encode(&self.0)
    }
}
