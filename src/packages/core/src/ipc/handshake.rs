//! Everything the peer sends here arrives before it is trusted, so hex decoding and the label check fail
//! closed rather than sanitize.

use std::io::{self, BufRead, Write};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::lockfile::read_lock_or_err;
use super::rand::generate_secret;
use crate::protocol::{bridge_read, bridge_write, Handshake};

type HmacSha256 = Hmac<Sha256>;

fn compute_mac(key: &[u8], msg: &[u8]) -> io::Result<String> {
    // HMAC accepts a key of any length, so this cannot fail today; propagate
    // (failing the handshake) rather than panic if the Mac impl ever changes.
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unusable hmac key"))?;
    mac.update(msg);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// The label rides inside the MAC so the claim is authenticated, not adjacent to it. The forms cannot
/// collide: the nonce is hex (never NUL), so a message ends at the nonce or continues past exactly one NUL.
fn handshake_mac_message(nonce: &str, label: Option<&str>) -> Vec<u8> {
    let mut msg = nonce.as_bytes().to_vec();
    if let Some(label) = label {
        msg.push(0);
        msg.extend_from_slice(label.as_bytes());
    }
    msg
}

/// `verify_slice` compares without short-circuiting, so the tag cannot be recovered byte by byte through
/// timing.
fn verify_mac(key: &[u8], msg: &[u8], provided_hex: &str) -> io::Result<()> {
    let provided = hex::decode(provided_hex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mac is not valid hex"))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unusable hmac key"))?;
    mac.update(msg);
    mac.verify_slice(&provided)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "hmac mismatch"))
}

/// The slot a connection without a label lands in, so a one-browser install needs no configuration.
pub const DEFAULT_LABEL: &str = "default";

/// Proof that a label passed [`validate_label`]: constructible only through [`parse`](Self::parse) or
/// [`default_label`](Self::default_label), whose fixed value a test holds to the same rule. The
/// trusted-client name carries the same rule in its own newtype ([`crate::allowlist::ClientName`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BrowserLabel(String);

impl BrowserLabel {
    pub fn parse(s: &str) -> Option<Self> {
        validate_label(s).then(|| BrowserLabel(s.to_string()))
    }

    pub fn default_label() -> Self {
        BrowserLabel(DEFAULT_LABEL.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for BrowserLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lets the registry be probed by the tool call's unvalidated `browser` string. Sound only while `Hash`/`Eq`
/// stay derived, so they agree with `str`'s.
impl std::borrow::Borrow<str> for BrowserLabel {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// The label reaches log lines, audit records, and tool output, hence the bound and the tame charset; the
/// leading alphanumeric keeps it from ever reading as a command-line flag.
pub fn validate_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes.first().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Runs on the reader/writer the session keeps afterwards, so no byte past the handshake is consumed here.
pub fn server_handshake<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<Option<BrowserLabel>> {
    let secret = read_lock_or_err()?.secret;
    server_handshake_with_secret(reader, writer, &secret)
}

fn server_handshake_with_secret<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    secret: &str,
) -> io::Result<Option<BrowserLabel>> {
    let nonce = generate_secret()?;
    bridge_write(
        writer,
        &Handshake::Challenge {
            nonce: nonce.clone(),
        },
    )?;

    match bridge_read::<_, Handshake>(reader)? {
        Some(Handshake::Response { mac, label }) => {
            // Nothing the peer sent is trusted before the MAC verifies, the label included.
            verify_mac(
                secret.as_bytes(),
                &handshake_mac_message(&nonce, label.as_deref()),
                &mac,
            )?;
            match label {
                Some(l) => match BrowserLabel::parse(&l) {
                    Some(l) => Ok(Some(l)),
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid browser label in handshake (want 1-32 chars of [A-Za-z0-9._-])",
                    )),
                },
                None => Ok(None),
            }
        }
        Some(Handshake::Challenge { .. }) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake response, got challenge",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before handshake response",
        )),
    }
}

/// Runs on the pump's reader/writer, so no byte past the handshake leaks into forwarded frames.
pub fn client_handshake<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: Option<BrowserLabel>,
) -> io::Result<()> {
    let secret = read_lock_or_err()?.secret;
    client_handshake_with_secret(
        reader,
        writer,
        &secret,
        label.map(BrowserLabel::into_string),
    )
}

/// `label` is a raw `Option<String>` on purpose: the server must reject a malformed label whatever the peer
/// runs, and the tests exercise that with strings the public [`client_handshake`] cannot produce.
fn client_handshake_with_secret<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    secret: &str,
    label: Option<String>,
) -> io::Result<()> {
    match bridge_read::<_, Handshake>(reader)? {
        Some(Handshake::Challenge { nonce }) => {
            let mac = compute_mac(
                secret.as_bytes(),
                &handshake_mac_message(&nonce, label.as_deref()),
            )?;
            bridge_write(writer, &Handshake::Response { mac, label })
        }
        Some(Handshake::Response { .. }) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected handshake challenge, got response",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "connection closed before handshake challenge",
        )),
    }
}

/// The private internals, exposed under the `fuzzing` feature for the fuzz crate; off-feature the API is
/// unchanged.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    use std::io::{self, BufRead, Write};

    pub fn compute_mac(key: &[u8], msg: &[u8]) -> io::Result<String> {
        super::compute_mac(key, msg)
    }

    pub fn handshake_mac_message(nonce: &str, label: Option<&str>) -> Vec<u8> {
        super::handshake_mac_message(nonce, label)
    }

    pub fn verify_mac(key: &[u8], msg: &[u8], provided_hex: &str) -> io::Result<()> {
        super::verify_mac(key, msg, provided_hex)
    }

    pub fn server_handshake_with_secret<R: BufRead, W: Write>(
        reader: &mut R,
        writer: &mut W,
        secret: &str,
    ) -> io::Result<Option<super::BrowserLabel>> {
        super::server_handshake_with_secret(reader, writer, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_validation_bounds_length_and_charset() {
        for ok in ["default", "chrome", "Brave-2", "work_profile", "a", "x.y"] {
            assert!(validate_label(ok), "{ok:?} should validate");
        }
        // Rejected inputs name the hazards: log injection, path separators, flag-looking and dotfile-looking
        // names.
        for bad in [
            "",
            "a b",
            "a\nb",
            "a/b",
            "a\\b",
            "läbel",
            "-flag",
            "--native-host",
            ".hidden",
            "_x",
            &"x".repeat(33),
        ] {
            assert!(!validate_label(bad), "{bad:?} should be rejected");
        }
        assert!(validate_label(&"x".repeat(32)));
        // The fixed default bypasses parse, so it is held to the same rule here.
        assert!(validate_label(BrowserLabel::default_label().as_str()));
    }

    #[test]
    fn handshake_challenge_response_authenticates_over_a_pipe() {
        // The client must sign (nonce, label) and ship the label beside the MAC; this is the only client-half
        // pin that runs on Windows, where the socketpair round trip below does not.
        use std::io::Cursor;

        // A test fixture, not a credential.
        let secret = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4"; // nosemgrep: generic.secrets.security.detected-generic-secret.detected-generic-secret
        let nonce = "feedface";
        let expected = compute_mac(
            secret.as_bytes(),
            &handshake_mac_message(nonce, Some("chrome")),
        )
        .unwrap();

        let mut challenge = serde_json::to_vec(&Handshake::Challenge {
            nonce: nonce.into(),
        })
        .unwrap();
        challenge.push(b'\n');
        let mut client_in = Cursor::new(challenge);
        let mut client_out = Vec::new();
        client_handshake_with_secret(
            &mut client_in,
            &mut client_out,
            secret,
            Some("chrome".into()),
        )
        .unwrap();

        let sent: Handshake = serde_json::from_slice(&client_out[..client_out.len() - 1]).unwrap();
        let Handshake::Response { mac, label } = sent else {
            panic!("client should send a response, sent {sent:?}");
        };
        assert_eq!(mac, expected);
        assert_eq!(label.as_deref(), Some("chrome"));
    }

    #[test]
    fn handshake_round_trip_over_a_loopback_pair() {
        use std::io::{BufReader, BufWriter};

        use super::super::socket::loopback_pair;

        // A test fixture, not a credential.
        let secret = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"; // nosemgrep: generic.secrets.security.detected-generic-secret.detected-generic-secret

        // Matching secrets: the server returns the label the client signed.
        let (srv, cli) = loopback_pair();
        let cli_secret = secret.to_string();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, &cli_secret, Some("brave".into()))
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        let label = server_handshake_with_secret(&mut r, &mut w, secret).unwrap();
        assert_eq!(label, BrowserLabel::parse("brave"));
        assert!(client.join().unwrap().is_ok());

        // No label carried: None, still authenticated.
        let (srv, cli) = loopback_pair();
        let cli_secret = secret.to_string();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, &cli_secret, None)
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        assert_eq!(
            server_handshake_with_secret(&mut r, &mut w, secret).unwrap(),
            None
        );
        assert!(client.join().unwrap().is_ok());

        // A malformed label fails even with a valid MAC.
        let (srv, cli) = loopback_pair();
        let cli_secret = secret.to_string();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, &cli_secret, Some("bad label\n".into()))
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        let err = server_handshake_with_secret(&mut r, &mut w, secret).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = client.join();

        // A client that does not know the secret is rejected by the server.
        let (srv, cli) = loopback_pair();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, "the-wrong-secret", None)
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        let server_res = server_handshake_with_secret(&mut r, &mut w, secret);
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = client.join();
    }

    #[test]
    fn a_tampered_label_invalidates_the_mac() {
        // The label is an authenticated claim: every alteration of what was signed, the label included,
        // must fail, and only the genuine (key, nonce, label) triple passes.
        // A test fixture, not a credential.
        let secret = b"d00dd00dd00dd00dd00dd00dd00dd00d"; // nosemgrep: generic.secrets.security.detected-generic-secret.detected-generic-secret
        let nonce = "cafebabe";
        let signed_for_chrome =
            compute_mac(secret, &handshake_mac_message(nonce, Some("chrome"))).unwrap();
        struct Case {
            name: &'static str,
            key: &'static [u8],
            msg: Vec<u8>,
            mac: String,
            expected: Result<(), io::ErrorKind>,
        }
        let cases = [
            Case {
                name: "the genuine claim passes",
                key: secret,
                msg: handshake_mac_message(nonce, Some("chrome")),
                mac: signed_for_chrome.clone(),
                expected: Ok(()),
            },
            Case {
                name: "a different key (a peer without the secret)",
                key: b"wrong-secret",
                msg: handshake_mac_message(nonce, Some("chrome")),
                mac: signed_for_chrome.clone(),
                expected: Err(io::ErrorKind::PermissionDenied),
            },
            Case {
                name: "another nonce (a replay against a fresh challenge)",
                key: secret,
                msg: handshake_mac_message("deadbeef", Some("chrome")),
                mac: signed_for_chrome.clone(),
                expected: Err(io::ErrorKind::PermissionDenied),
            },
            Case {
                name: "a MAC that is not hex",
                key: secret,
                msg: handshake_mac_message(nonce, Some("chrome")),
                mac: "not-hex".to_string(),
                expected: Err(io::ErrorKind::InvalidData),
            },
            Case {
                name: "the label swapped after signing",
                key: secret,
                msg: handshake_mac_message(nonce, Some("brave")),
                mac: signed_for_chrome.clone(),
                expected: Err(io::ErrorKind::PermissionDenied),
            },
            Case {
                name: "the label stripped after signing",
                key: secret,
                msg: handshake_mac_message(nonce, None),
                mac: signed_for_chrome,
                expected: Err(io::ErrorKind::PermissionDenied),
            },
        ];
        for case in cases {
            let outcome = verify_mac(case.key, &case.msg, &case.mac).map_err(|e| e.kind());
            assert_eq!(outcome, case.expected, "{}", case.name);
        }
    }
}
