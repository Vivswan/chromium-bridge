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
/// delete the enrollment key and the recorded policy. Fail-closed by
/// construction — after this, proofs can no longer be produced, so a pinned
/// extension refuses the bridge until the user re-pairs.
pub fn run_revoke() -> i32 {
    match EnrollmentKey::revoke() {
        Ok(true) => {
            HostConfig::remove();
            println!("enrollment key revoked. re-run `chromium-bridge pair` to re-enroll.");
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
            "key:        REJECTED — {e}\n            treat it as untrusted; \
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
