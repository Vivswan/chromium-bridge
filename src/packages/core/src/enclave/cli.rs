//! CLI runners: `pair` / `revoke` / `enclave-status`.

use super::config::HostConfig;
use super::key::EnrollmentKey;
use super::pubkey::EnclavePublicKey;
use super::{EnclaveError, KEY_LABEL};

/// `chromium-bridge pair [--reset]`: the user-present half of the enrollment
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
                 \n    chromium-bridge pair --reset\n\
                 \n\
                 to inspect the current key, run: chromium-bridge enclave-status\n\
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
                bump_host_key_epoch();
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

/// `chromium-bridge revoke` (also `pair --reset` uses the same deletion):
/// delete the enrollment key and the recorded policy, and bump the revocation
/// epoch's host-key marker (ADR-0025) so a live native host notices and
/// pushes the `enclave_revoked` frame to the extension -- the pinned
/// extension flips to its fail-closed state without waiting for an opt-in
/// reverify. Fail-closed by construction - after this, proofs can no longer
/// be produced, so a pinned extension refuses the bridge until the user
/// re-pairs.
pub fn run_revoke() -> i32 {
    match EnrollmentKey::revoke() {
        Ok(true) => {
            HostConfig::remove();
            bump_host_key_epoch();
            println!("enrollment key revoked. re-run `chromium-bridge pair` to re-enroll.");
            println!(
                "a connected extension is notified and fails closed; \
                 otherwise it notices on its next connect."
            );
            0
        }
        Ok(false) => {
            HostConfig::remove();
            bump_host_key_epoch();
            println!("no enrollment key found; nothing to revoke.");
            0
        }
        Err(e) => {
            println!("revoke failed: {e}");
            1
        }
    }
}

/// Bump the revocation epoch's host-key marker after a key deletion, and
/// record the revocation in the audit trail (ADR-0030, log-after-decide: the
/// keychain deletion has already happened). The deletion itself is the
/// authoritative act (the keychain is the ground truth); a failed bump only
/// loses the proactive push a connected host would otherwise send, so it is
/// reported, not fatal. A pinned extension still fails closed on its next key
/// verification (its stored pin outlives the key, and the missing key can no
/// longer answer a challenge).
fn bump_host_key_epoch() {
    if let Err(e) = crate::revocation::bump(crate::revocation::Scope::HostKey) {
        eprintln!(
            "warning: the enrollment key is gone, but the revocation epoch could not be \
             bumped ({e}); a connected extension will not get a proactive notice and will \
             instead notice at its next pinned-key verification"
        );
    }
    crate::audit::record(
        crate::audit::AuditRecord::new(crate::audit::AuditKind::HostKeyRevoke)
            .surface(crate::audit::Surface::Cli)
            .outcome("ok"),
    );
}

/// `chromium-bridge enclave-status`: read-only report on the enrollment state.
pub fn run_status() -> i32 {
    println!("chromium-bridge enclave-status");
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
        Ok(None) => println!("key:        none (run `chromium-bridge pair`)"),
        Err(EnclaveError::Unsupported) => println!("key:        n/a"),
        Err(e @ EnclaveError::KeyInvalid(_)) => println!(
            "key:        REJECTED - {e}\n            treat it as untrusted; \
             run `chromium-bridge pair --reset` to replace it"
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

/// `chromium-bridge presence-selftest`: raise ONE per-action user-presence
/// prompt (ADR-0031) and report the outcome. It signs a throwaway challenge
/// over the presence domain with the enrollment key - exactly the Enclave
/// operation the `page_eval`/`page_upload` gate performs when the extension
/// sends a `presence_challenge` - so the user can see that Touch ID prompt
/// without a browser. Read-only: nothing is stored, and the signature is
/// discarded. Returns a process exit code.
pub fn run_presence_selftest() -> i32 {
    println!("chromium-bridge presence-selftest");
    let key = match EnrollmentKey::lookup() {
        Ok(Some(key)) => key,
        Ok(None) => {
            eprintln!(
                "no enrollment key on this machine; run `chromium-bridge pair` first. \
                 Without a key the per-action Touch ID gate is unavailable and \
                 page_eval/page_upload confirmations use the extension window instead."
            );
            return 1;
        }
        Err(e) => {
            eprintln!("could not look up the enrollment key: {e}");
            return 1;
        }
    };
    println!("raising a user-presence prompt (Touch ID or your login password)...");
    // A fresh nonce + a self-test context; the signature is discarded. The
    // point is that this Enclave op cannot complete without a live tap.
    let nonce = format!(
        "selftest-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    match key.sign_presence(&nonce, Some("presence-selftest")) {
        Ok(_sig) => {
            println!("OK: user presence verified (the Enclave signed under Touch ID).");
            println!(
                "this is the exact prompt page_eval / page_upload raise on an enrolled \
                 Mac when touchIdConfirm is on."
            );
            0
        }
        Err(e) => {
            eprintln!("presence NOT verified: {e}");
            eprintln!("(a cancelled prompt or a failed scan reads as a refusal, fail closed)");
            1
        }
    }
}

/// `chromium-bridge enclave-status --json`: the machine-readable form of
/// [`run_status`], for co-equal surfaces that drive this binary as a
/// subprocess (the desktop app, ADR-0029) instead of scraping the human
/// report. One JSON object on stdout; the shape is versioned (`v`) so a
/// consumer can refuse a report it does not understand instead of guessing.
pub fn run_status_json() -> i32 {
    let key = match EnrollmentKey::lookup() {
        Ok(Some(key)) => match key.public_key() {
            Ok(public) => KeyReport::Present(public),
            Err(e) => KeyReport::Error(format!("public key unreadable: {e}")),
        },
        Ok(None) => KeyReport::None,
        Err(EnclaveError::Unsupported) => KeyReport::Unsupported,
        Err(e @ EnclaveError::KeyInvalid(_)) => KeyReport::Invalid(e.to_string()),
        Err(e) => KeyReport::Error(e.to_string()),
    };
    let policy = HostConfig::read().map_err(|e| e.to_string());
    println!("{}", render_status_json(&key, &policy));
    0
}

/// What the keychain lookup found, reduced to the states the JSON report
/// names. Factored from [`run_status_json`] so the rendering is pure and
/// unit-testable without a keychain.
enum KeyReport {
    Present(EnclavePublicKey),
    None,
    Invalid(String),
    Unsupported,
    Error(String),
}

/// Render the JSON status object. `key: "present" | "none" | "invalid" |
/// "unsupported" | "error"`; `invalid` means a key exists under our label but
/// must be treated as untrusted (planted or malformed), which a consumer must
/// surface as loudly as the human report does.
fn render_status_json(
    key: &KeyReport,
    policy: &Result<Option<HostConfig>, String>,
) -> serde_json::Value {
    let mut out = serde_json::json!({
        "v": 1,
        "supported": cfg!(target_os = "macos"),
        "key_label": KEY_LABEL,
    });
    // The json! literal above always builds an object; guard anyway so this
    // renderer can never panic on the impossible.
    let Some(obj) = out.as_object_mut() else {
        return serde_json::json!({ "v": 1, "key": "error", "detail": "internal render error" });
    };
    match key {
        KeyReport::Present(public) => {
            obj.insert("key".into(), "present".into());
            obj.insert("public_key_b64".into(), public.to_base64().into());
            obj.insert("fingerprint".into(), public.fingerprint_display().into());
        }
        KeyReport::None => {
            obj.insert("key".into(), "none".into());
        }
        KeyReport::Invalid(detail) => {
            obj.insert("key".into(), "invalid".into());
            obj.insert("detail".into(), detail.as_str().into());
        }
        KeyReport::Unsupported => {
            obj.insert("key".into(), "unsupported".into());
        }
        KeyReport::Error(detail) => {
            obj.insert("key".into(), "error".into());
            obj.insert("detail".into(), detail.as_str().into());
        }
    }
    match policy {
        Ok(Some(cfg)) => {
            obj.insert(
                "policy".into(),
                serde_json::json!({ "enrolled": cfg.enrolled, "granularity": cfg.granularity }),
            );
        }
        Ok(None) => {
            obj.insert("policy".into(), serde_json::Value::Null);
        }
        Err(e) => {
            obj.insert("policy".into(), serde_json::Value::Null);
            obj.insert("policy_error".into(), e.as_str().into());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn present_key() -> EnclavePublicKey {
        // A syntactically valid uncompressed P-256 point (0x04 + 64 bytes).
        let mut bytes = vec![0x04u8];
        bytes.extend(std::iter::repeat_n(0xabu8, 64));
        match EnclavePublicKey::from_x963(bytes) {
            Ok(k) => k,
            Err(e) => panic!("fixture key must parse: {e}"),
        }
    }

    #[test]
    fn json_report_carries_the_fingerprint_for_a_present_key() {
        let public = present_key();
        let (b64, fingerprint) = (public.to_base64(), public.fingerprint_display());
        let v = render_status_json(
            &KeyReport::Present(public),
            &Ok(Some(HostConfig {
                enrolled: true,
                ..HostConfig::default()
            })),
        );
        assert_eq!(v["v"], 1);
        assert_eq!(v["key"], "present");
        assert_eq!(v["key_label"], KEY_LABEL);
        assert_eq!(v["public_key_b64"], b64);
        assert_eq!(v["fingerprint"], fingerprint);
        assert_eq!(v["policy"]["enrolled"], true);
    }

    #[test]
    fn json_report_states_map_one_to_one() {
        let none = render_status_json(&KeyReport::None, &Ok(None));
        assert_eq!(none["key"], "none");
        assert!(none["policy"].is_null());
        assert!(none.get("fingerprint").is_none());

        let invalid = render_status_json(
            &KeyReport::Invalid("planted software key".into()),
            &Ok(None),
        );
        assert_eq!(invalid["key"], "invalid");
        assert_eq!(invalid["detail"], "planted software key");

        let unsupported = render_status_json(&KeyReport::Unsupported, &Ok(None));
        assert_eq!(unsupported["key"], "unsupported");

        let err = render_status_json(&KeyReport::Error("keychain: -25300".into()), &Ok(None));
        assert_eq!(err["key"], "error");
        assert_eq!(err["detail"], "keychain: -25300");
    }

    #[test]
    fn json_report_surfaces_an_unreadable_policy() {
        let v = render_status_json(&KeyReport::None, &Err("config decode: bad".into()));
        assert!(v["policy"].is_null());
        assert_eq!(v["policy_error"], "config decode: bad");
    }
}
