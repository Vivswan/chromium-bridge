//! The authenticated bridge handshake: an HMAC-SHA256 challenge-response
//! keyed on the per-run secret from the lock file, with an optional signed
//! browser label. Strict hex decoding and label validation both fail closed -
//! these fields arrive from the peer before it is trusted.

use std::io::{self, BufRead, Write};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::lockfile::read_lock_or_err;
use super::rand::{generate_secret, hex_encode};
use crate::protocol::{bridge_read, bridge_write, Handshake};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 of `msg` under `key`, hex-encoded. The key is the per-run
/// secret's bytes and the message is built by [`handshake_mac_message`].
fn compute_mac(key: &[u8], msg: &[u8]) -> io::Result<String> {
    // HMAC accepts a key of any length, so this cannot fail today; propagate
    // (failing the handshake) rather than panic if the Mac impl ever changes.
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unusable hmac key"))?;
    mac.update(msg);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

/// The exact bytes the handshake MAC covers: the server's nonce and, when the
/// client claims a browser label, a NUL separator plus that label. Covering
/// the label makes the claim authenticated rather than merely adjacent to the
/// MAC - a response whose label was altered in any way fails verification.
/// The two forms cannot collide: the nonce is fixed-width hex (never contains
/// NUL), so a message either ends at the nonce (no label) or continues past
/// exactly one NUL with the label bytes.
fn handshake_mac_message(nonce: &str, label: Option<&str>) -> Vec<u8> {
    let mut msg = nonce.as_bytes().to_vec();
    if let Some(label) = label {
        msg.push(0);
        msg.extend_from_slice(label.as_bytes());
    }
    msg
}

/// Constant-time verification that `provided_hex` is HMAC-SHA256(key, msg).
/// Uses `Mac::verify_slice`, whose comparison does not short-circuit, so a
/// caller cannot recover the expected tag byte-by-byte via timing.
fn verify_mac(key: &[u8], msg: &[u8], provided_hex: &str) -> io::Result<()> {
    let provided = hex_decode(provided_hex)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mac is not valid hex"))?;
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "unusable hmac key"))?;
    mac.update(msg);
    mac.verify_slice(&provided)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "hmac mismatch"))
}

/// Decode a hex string to bytes, or `None` on any odd length or non-hex
/// character. Operates on raw bytes via [`slice::chunks_exact`] rather than
/// `str` slicing: the input is an attacker-controlled handshake field, and
/// `&s[i..i + 2]` would panic when a multi-byte UTF-8 character straddles the
/// two-byte boundary. Under `panic = "abort"` that panic would take down the
/// whole MCP server, so this must reject bad input rather than trust it.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => Some(hex_nibble(*hi)? << 4 | hex_nibble(*lo)?),
            // chunks_exact(2) yields two-byte windows only.
            _ => None,
        })
        .collect()
}

/// Value of a single ASCII hex digit, or `None` for any other byte. Notably a
/// leading `+`, which `u8::from_str_radix` accepts (so the old decoder took
/// "+f" as 0x0f), is rejected here: the handshake MAC is strict two-digit hex.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Whether `label` is an acceptable browser label: 1-32 characters, starting
/// with an ASCII alphanumeric, the rest ASCII alphanumeric or `.`, `_`, `-`.
/// The label arrives in the (signed) handshake response and ends up in log
/// lines, audit records, and tool output, so it is bounded and restricted to
/// a tame charset; the leading-alphanumeric rule also keeps a label from ever
/// looking like a command-line flag. Anything else fails the handshake (fail
/// closed) rather than being sanitized.
pub fn validate_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes.first().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Server side: run the challenge-response over a freshly-accepted connection,
/// using the same buffered reader/writer the session will keep, so no bytes are
/// consumed past the handshake. On success returns the browser label the
/// client carried in its signed response (`None` when it sent none). The label
/// is read only AFTER the MAC verifies, and only a validated label is
/// returned; a malformed one fails the whole handshake.
pub fn server_handshake<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> io::Result<Option<String>> {
    let secret = read_lock_or_err()?.secret;
    server_handshake_with_secret(reader, writer, &secret)
}

fn server_handshake_with_secret<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    secret: &str,
) -> io::Result<Option<String>> {
    let nonce = generate_secret()?;
    bridge_write(
        writer,
        &Handshake::Challenge {
            nonce: nonce.clone(),
        },
    )?;

    match bridge_read::<_, Handshake>(reader)? {
        Some(Handshake::Response { mac, label }) => {
            // Authenticate FIRST; nothing the peer sent is trusted before
            // this. The MAC covers the nonce AND the claimed label
            // (handshake_mac_message), so a label that was altered after
            // signing fails here.
            verify_mac(
                secret.as_bytes(),
                &handshake_mac_message(&nonce, label.as_deref()),
                &mac,
            )?;
            if let Some(l) = &label {
                if !validate_label(l) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid browser label in handshake (want 1-32 chars of [A-Za-z0-9._-])",
                    ));
                }
            }
            Ok(label)
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

/// Client side: read the server's challenge and answer it with
/// HMAC(secret, nonce). `label` names the browser this host fronts; the server
/// keys its connection registry by it (missing label = the default slot).
/// Reuses the pump's buffered reader/writer so the handshake never leaks into
/// forwarded frames.
pub fn client_handshake<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: Option<String>,
) -> io::Result<()> {
    let secret = read_lock_or_err()?.secret;
    client_handshake_with_secret(reader, writer, &secret, label)
}

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

/// Fuzz-only wrappers over the private handshake internals, for the cargo-fuzz
/// workspace (see the `fuzzing` feature in Cargo.toml). Thin delegations only;
/// the real functions stay private and nothing here adds behavior.
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

    pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
        super::hex_decode(s)
    }

    pub fn server_handshake_with_secret<R: BufRead, W: Write>(
        reader: &mut R,
        writer: &mut W,
        secret: &str,
    ) -> io::Result<Option<String>> {
        super::server_handshake_with_secret(reader, writer, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_validation_bounds_length_and_charset() {
        // Accepted: browser-ish names within 32 chars of [A-Za-z0-9._-],
        // starting alphanumeric.
        for ok in ["default", "chrome", "Brave-2", "work_profile", "a", "x.y"] {
            assert!(validate_label(ok), "{ok:?} should validate");
        }
        // Rejected: empty, overlong, spaces/newlines (log injection), path
        // separators, non-ASCII, and anything starting like a flag or a
        // dotfile (first char must be alphanumeric).
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
        // The 32-char boundary itself is accepted.
        assert!(validate_label(&"x".repeat(32)));
    }

    #[test]
    fn hex_decode_roundtrips_and_rejects_bad_input() {
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        // Odd length and non-hex digits are rejected, not silently truncated.
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
        // A signed nibble is not hex: `u8::from_str_radix` would have accepted
        // "+f" as 0x0f, but the handshake MAC is strict two-digit hex only.
        assert_eq!(hex_decode("+f"), None);
        // A multi-byte UTF-8 character makes the byte length even while landing
        // a chunk boundary mid-codepoint. The old `&s[i..i + 2]` slicing
        // panicked here (aborting the server under panic=abort); now it is a
        // clean rejection. "é" is two UTF-8 bytes, so "aé" has byte length 3
        // (odd) and "ééf" (5 bytes) is odd too; use a 4-byte even case.
        assert_eq!(hex_decode("éé"), None); // 4 bytes, none of them ASCII hex
        assert_eq!(hex_decode("aé"), None); // 3 bytes: odd length
        assert_eq!(hex_decode("a\u{00e9}b"), None); // 4 bytes, non-hex middle
                                                    // A 4-byte emoji is even-length but not hex.
        assert_eq!(hex_decode("😀"), None);
    }

    /// Fuzz the handshake MAC decoder. It runs on an attacker-controlled field
    /// in the accept path, so it must reject or decode every input without
    /// panicking -- including multi-byte UTF-8 that lands mid-codepoint on a
    /// two-byte chunk boundary, the abort-the-server bug this guards against.
    /// Arbitrary strings are built from `any::<char>()` to avoid pulling in
    /// proptest's `regex-syntax` feature (see `protocol.rs` proptests).
    mod hex_fuzz {
        use super::super::hex_decode;
        use crate::ipc::hex_encode;
        use proptest::prelude::*;

        fn arb_string() -> impl Strategy<Value = String> {
            prop::collection::vec(any::<char>(), 0..16).prop_map(|cs| cs.into_iter().collect())
        }

        proptest! {
            #[test]
            fn never_panics(s in arb_string()) {
                let _ = hex_decode(&s);
            }

            #[test]
            fn encode_decode_roundtrips(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
                prop_assert_eq!(hex_decode(&hex_encode(&bytes)), Some(bytes));
            }
        }
    }

    #[test]
    fn verify_mac_accepts_correct_and_rejects_wrong() {
        let key = b"per-run-secret";
        let nonce = b"challenge-nonce";
        let mac = compute_mac(key, nonce).unwrap();
        // The MAC the client would send verifies.
        assert!(verify_mac(key, nonce, &mac).is_ok());
        // A different key (attacker who doesn't know the secret) is rejected.
        assert!(verify_mac(b"wrong-secret", nonce, &mac).is_err());
        // A different nonce (replay against a fresh challenge) is rejected.
        assert!(verify_mac(key, b"other-nonce", &mac).is_err());
        // Non-hex garbage is rejected before any comparison.
        assert!(verify_mac(key, nonce, "not-hex").is_err());
    }

    #[test]
    fn handshake_challenge_response_authenticates_over_a_pipe() {
        // Drive the client half against a known challenge and confirm it emits
        // the exact HMAC response (including the carried label) the server will
        // verify. The server's own accept path is exercised end-to-end in the
        // socketpair test below and in tests/protocol/e2e.py.
        use std::io::Cursor;

        let secret = "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4";
        let nonce = "feedface";
        // The MAC covers nonce AND label (handshake_mac_message), so the
        // label claim is authenticated, not merely adjacent to the MAC.
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
        match sent {
            Handshake::Response { mac, label } => {
                assert_eq!(mac, expected);
                assert_eq!(label.as_deref(), Some("chrome"));
            }
            _ => panic!("client should send a response"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn handshake_round_trip_over_socketpair() {
        use std::io::{BufReader, BufWriter};
        use std::os::unix::net::UnixStream;

        let secret = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";

        // Matching secrets on both ends: the server accepts and returns the
        // label the client carried in its signed response.
        let (srv, cli) = UnixStream::pair().unwrap();
        let cli_secret = secret.to_string();
        let client = std::thread::spawn(move || {
            let mut r = BufReader::new(cli.try_clone().unwrap());
            let mut w = BufWriter::new(cli);
            client_handshake_with_secret(&mut r, &mut w, &cli_secret, Some("brave".into()))
        });
        let mut r = BufReader::new(srv.try_clone().unwrap());
        let mut w = BufWriter::new(srv);
        let label = server_handshake_with_secret(&mut r, &mut w, secret).unwrap();
        assert_eq!(label.as_deref(), Some("brave"));
        assert!(client.join().unwrap().is_ok());

        // No label carried: the server reports None (the caller applies the
        // default), still authenticated.
        let (srv, cli) = UnixStream::pair().unwrap();
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

        // A malformed label fails the handshake even with a valid MAC: the
        // label feeds registry keys and log lines, so it is validated (fail
        // closed) right after authentication.
        let (srv, cli) = UnixStream::pair().unwrap();
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
        let (srv, cli) = UnixStream::pair().unwrap();
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
        // A response whose label was altered after signing must fail
        // verification: the MAC covers (nonce, label), so swapping the label
        // while keeping the MAC is detected. This is what makes the label an
        // authenticated claim rather than a free-rider next to the MAC.
        let secret = "d00dd00dd00dd00dd00dd00dd00dd00d";
        let nonce = "cafebabe";
        let signed_for_chrome = compute_mac(
            secret.as_bytes(),
            &handshake_mac_message(nonce, Some("chrome")),
        )
        .unwrap();
        // Genuine claim verifies.
        assert!(verify_mac(
            secret.as_bytes(),
            &handshake_mac_message(nonce, Some("chrome")),
            &signed_for_chrome,
        )
        .is_ok());
        // The same MAC presented with a different label is rejected.
        assert!(verify_mac(
            secret.as_bytes(),
            &handshake_mac_message(nonce, Some("brave")),
            &signed_for_chrome,
        )
        .is_err());
        // ...and with the label stripped entirely.
        assert!(verify_mac(
            secret.as_bytes(),
            &handshake_mac_message(nonce, None),
            &signed_for_chrome,
        )
        .is_err());
    }
}
