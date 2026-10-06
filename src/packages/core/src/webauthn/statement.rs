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

/// The page operations whose confirmation the policy may route to the authenticator, spelled as the tool
/// names the extension's gate knows them by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOp {
    PageEval,
    PageUpload,
}

impl PageOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "page_eval" => Some(PageOp::PageEval),
            "page_upload" => Some(PageOp::PageUpload),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            PageOp::PageEval => "page_eval",
            PageOp::PageUpload => "page_upload",
        }
    }
}

/// Bound on an origin the extension names. A serialized origin is a scheme, a host of at most 253 bytes, and a
/// port, so 300 admits every real one; the bound also keeps a presence record's act, origin, and auth path
/// together inside the audit field cap.
pub const MAX_ORIGIN_LEN: usize = 300;

/// The web origin a page operation lands on, as the extension's URL parser serializes it: `scheme://host[:port]`,
/// ASCII, with no path, query, fragment, or userinfo. [`parse`](Self::parse) is the wire boundary; an opaque
/// origin (`null`) or anything shaped differently is refused, so no statement is ever minted for a page the user
/// cannot be shown. The host rule is the URL Standard's own (no forbidden domain code point), not a guess at
/// what hostnames look like, so a host a browser serves a page from is never refused here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(String);

impl Origin {
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() || s.len() > MAX_ORIGIN_LEN || !s.is_ascii() {
            return None;
        }
        let (scheme, authority) = s.split_once("://")?;
        let mut scheme_bytes = scheme.bytes();
        let scheme_ok = scheme_bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            && scheme_bytes.all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
            });
        // A bracketed IPv6 literal keeps its colons; otherwise the first colon starts the port.
        let port = if let Some(literal) = authority.strip_prefix('[') {
            let (literal, rest) = literal.split_once(']')?;
            literal.parse::<std::net::Ipv6Addr>().ok()?;
            match rest.strip_prefix(':') {
                Some(port) => Some(port),
                None if rest.is_empty() => None,
                None => return None,
            }
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            if host.is_empty() || host.bytes().any(forbidden_domain_code_point) {
                return None;
            }
            port
        };
        // Digits first: u16's parser would also take a sign.
        let port_ok = port.is_none_or(|p| {
            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
        });
        (scheme_ok && port_ok).then(|| Origin(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn nul_free_bounded(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.contains('\0')
}

/// The URL Standard's forbidden domain code points, restricted to ASCII (the caller has refused the rest): a
/// C0 control, space, `#`, `%`, `/`, `:`, `<`, `>`, `?`, `@`, `[`, `\`, `]`, `^`, `|`, or DEL.
fn forbidden_domain_code_point(b: u8) -> bool {
    b.is_ascii_control()
        || matches!(
            b,
            b' ' | b'#'
                | b'%'
                | b'/'
                | b':'
                | b'<'
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b'\\'
                | b']'
                | b'^'
                | b'|'
        )
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
