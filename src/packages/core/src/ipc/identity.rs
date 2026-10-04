//! The kernel-attested client identity and the two typed values it is built from. Both newtypes are parsed ONCE
//! where a value enters the program (a measurement, a `clients.json` entry, a relayed attach frame, a CLI flag),
//! so every later holder compares trusted values and no compare site re-validates.
//!
//! ```text
//! HashDigest  -> non-empty lowercase hex, the form both platforms measure in
//! TeamId      -> non-empty: an unsigned or ad-hoc image measures NO team id, so an empty anchor could only ever be
//!                a permanent, silent Refuse (the hand-edited `{"kind":"team_id","value":""}` incident)
//! ```
//!
//! An on-disk value in the wrong form is deliberately NOT normalized (that would mask tampering): it fails the whole
//! decode, which every caller already fails closed on.

use serde::{Deserialize, Serialize};

/// A validated image digest (macOS `cdhash`, Linux `/proc/<pid>/exe` SHA256): non-empty lowercase ASCII hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct HashDigest(String);

impl HashDigest {
    /// The digest as its lowercase hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&[u8]> for HashDigest {
    type Error = String;

    /// The measurement boundary's constructor: lowercase hex by construction,
    /// so the one rule left to check is that the measurement had bytes at all.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            Err("digest must be non-empty".to_string())
        } else {
            Ok(HashDigest(hex::encode(bytes)))
        }
    }
}

impl TryFrom<String> for HashDigest {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let canonical = !value.is_empty()
            && value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if canonical {
            Ok(HashDigest(value))
        } else {
            Err("hash anchor must be non-empty lowercase hex".to_string())
        }
    }
}

impl TryFrom<&str> for HashDigest {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        HashDigest::try_from(value.to_string())
    }
}

impl From<HashDigest> for String {
    fn from(digest: HashDigest) -> String {
        digest.0
    }
}

impl std::fmt::Display for HashDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A macOS signing Team ID as measured from a Team-ID-signed image or pinned by
/// an allowlist entry. Non-empty by construction (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct TeamId(String);

impl TeamId {
    /// The Team ID as its string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TeamId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err("team id must be non-empty".to_string())
        } else {
            Ok(TeamId(value))
        }
    }
}

impl TryFrom<&str> for TeamId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        TeamId::try_from(value.to_string())
    }
}

impl From<TeamId> for String {
    fn from(team_id: TeamId) -> String {
        team_id.0
    }
}

impl std::fmt::Display for TeamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Schema-identical to a plain string on purpose: the canonical-form rules are enforced by the Rust parser at
/// the trust boundary, and the generated TS wire schema must stay exactly what it was when these fields were a
/// `String` (the extension only ever consumes them read-only in `client_list_result`).
#[cfg(feature = "envelope-schema")]
macro_rules! string_schema {
    ($t:ty) => {
        impl schemars::JsonSchema for $t {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                <String as schemars::JsonSchema>::schema_name()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                <String as schemars::JsonSchema>::schema_id()
            }

            fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                <String as schemars::JsonSchema>::json_schema(generator)
            }

            fn inline_schema() -> bool {
                <String as schemars::JsonSchema>::inline_schema()
            }
        }
    };
}
#[cfg(feature = "envelope-schema")]
string_schema!(HashDigest);
#[cfg(feature = "envelope-schema")]
string_schema!(TeamId);

/// A harness's kernel-attested code identity, the input to the trusted-client
/// allowlist decision ([`crate::allowlist`]). `team_id` is present only for a
/// Team-ID-signed image (always `None` on Linux and for ad-hoc / unsigned
/// builds). Nameable on every platform, including the Windows build where no
/// attestation exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub hash: HashDigest,
    pub team_id: Option<TeamId>,
}

impl From<&crate::protocol::HarnessId> for ClientIdentity {
    /// The allowlist-input projection of a relayed harness identity. Drops
    /// `name` deliberately: it is a self-asserted log label, never an
    /// authorization key.
    fn from(h: &crate::protocol::HarnessId) -> Self {
        ClientIdentity {
            hash: h.hash.clone(),
            team_id: h.team_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_digest_accepts_only_non_empty_lowercase_hex() {
        // The legitimate forms: lowercase hex of any (even) length, a 20-byte
        // macOS cdhash or a 32-byte Linux SHA256 both pass.
        assert!(HashDigest::try_from("deadbeef").is_ok());
        assert!(HashDigest::try_from("ab".repeat(32)).is_ok());
        assert!(HashDigest::try_from("0123456789abcdef").is_ok());
        // Everything that could never match a measured lowercase-hex identity
        // is refused at the parse boundary instead of becoming a permanent,
        // silent Refuse.
        for (bad, why) in [
            ("", "empty"),
            ("DEADBEEF", "uppercase"),
            ("aBc1", "mixed case"),
            ("zz", "non-hex"),
            ("dead beef", "whitespace"),
            ("dead-beef", "punctuation"),
        ] {
            assert!(HashDigest::try_from(bad).is_err(), "{why}");
        }
    }

    #[test]
    fn a_measured_digest_parses_back_equal_to_itself() {
        // The two constructors meet: what the measurement boundary produces
        // from bytes is exactly what the parse boundary accepts from text, so
        // a measured hash written to clients.json always reads back and
        // matches. Pins the encoder's lowercase output (an external fact of
        // the hex crate), which a parse of uppercase hex would silently reject.
        let measured = HashDigest::try_from(&[0x00u8, 0xab, 0xcd, 0xef, 0xff][..]).unwrap();
        assert_eq!(measured.as_str(), "00abcdefff");
        assert_eq!(HashDigest::try_from(measured.as_str()), Ok(measured));
    }
}
