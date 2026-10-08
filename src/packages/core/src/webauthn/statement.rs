//! The statement a WebAuthn signature covers, and the challenge derived from it. Same domain-separation
//! design as the enclave challenge: NUL-separated fields under a domain prefix, every field NUL-free, so
//! no two statements share bytes and a presence statement can never be replayed as an enrollment one.

use std::io;

use sha2::{Digest, Sha256};

use crate::ipc::BrowserLabel;
use crate::tools::ToolId;

use super::base64url;

pub const PRESENCE_DOMAIN: &str = "genkan-webauthn-presence-v1";

pub const ENROLL_DOMAIN: &str = "genkan-webauthn-enroll-v1";

/// The extension echoes these fields back; the host minted them, and zero trust bounds them anyway.
pub const MAX_NONCE_LEN: usize = 256;
pub const MAX_ACTION_LEN: usize = 1024;

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

/// [`parse`](Self::parse) is the wire boundary; [`fresh`](Self::fresh) mints the host's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(String);

impl Nonce {
    pub fn parse(s: &str) -> Option<Self> {
        bounded_nul_free(s, MAX_NONCE_LEN)
            .is_ok()
            .then(|| Nonce(s.to_string()))
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

/// What the user is approving, as the host names it: the audit trail and the extension's prompt show it.
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
        bounded_nul_free(s, MAX_ACTION_LEN)
            .is_ok()
            .then(|| Action(s.to_string()))
    }

    /// The action of a page operation's request: `<op> on <origin>`, so the signature covers the page the
    /// act lands on, and a tap minted for one origin cannot vouch for another. Always within bounds: the op
    /// is a fixed word and the origin is bounded by [`MAX_ORIGIN_LEN`].
    pub fn page_op(op: PageOp, origin: &Origin) -> Self {
        Action(format!("{} on {}", op.as_str(), origin.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The page operations whose confirmation the policy may route to the authenticator. The wire spelling is the
/// tool catalogue's, so a catalogue rename cannot drift from the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOp {
    PageEval,
    PageUpload,
}

impl PageOp {
    pub fn parse(s: &str) -> Option<Self> {
        [PageOp::PageEval, PageOp::PageUpload]
            .into_iter()
            .find(|op| op.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PageOp::PageEval => ToolId::PageEval.tool().name,
            PageOp::PageUpload => ToolId::PageUpload.tool().name,
        }
    }
}

/// Bound on an origin the extension names: a serialized origin is a scheme, a host of at most 253 bytes, and
/// a port, so 300 admits every real one.
pub const MAX_ORIGIN_LEN: usize = 300;

/// The web origin a page operation lands on. [`parse`](Self::parse) admits text only when the WHATWG parser's
/// own origin serialization reproduces it byte for byte, so no statement is minted for a page the user cannot
/// be shown.
///
/// ```text
/// `null`, a path, a query, userinfo, a default port, a rewritten host -> refused by the round trip
/// `;`, `=`, or a space anywhere                                       -> refused here: the audit trail
///                                                                        delimits its fields with them
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(String);

impl Origin {
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty()
            || s.len() > MAX_ORIGIN_LEN
            || s.bytes().any(|b| matches!(b, b';' | b'=' | b' '))
        {
            return None;
        }
        let url = url::Url::parse(s).ok()?;
        (url.origin().ascii_serialization() == s).then(|| Origin(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a bounded text field was refused; enclave/challenge.rs maps each to its refusal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldFault {
    Empty,
    TooLong,
    Nul,
}

/// The one rule for a field the extension echoes back: non-empty, at most `max` BYTES, and NUL-free, since
/// NUL is the separator of every signed statement.
pub(crate) fn bounded_nul_free(s: &str, max: usize) -> Result<(), FieldFault> {
    if s.is_empty() {
        return Err(FieldFault::Empty);
    }
    if s.len() > max {
        return Err(FieldFault::TooLong);
    }
    if s.contains('\0') {
        return Err(FieldFault::Nul);
    }
    Ok(())
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
