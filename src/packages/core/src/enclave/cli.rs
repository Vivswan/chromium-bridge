//! CLI runners: `pair` / `revoke` / `enclave-status`.

use serde::{Deserialize, Serialize};

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
    let report = build_status_report(&key, &policy);
    // Serialize through `Value` so the object keys stay sorted (serde_json's
    // default `Map` ordering), byte-for-byte as the previous ad-hoc `json!`
    // rendering emitted them: this JSON is a frozen wire contract the desktop
    // app parses, and routing through `to_value` keeps the emitted bytes
    // identical regardless of the struct's field declaration order.
    match serde_json::to_value(&report) {
        Ok(value) => {
            println!("{value}");
            0
        }
        // A struct of plain scalars cannot fail to serialize; refuse loudly on
        // the impossible rather than print a half-formed object on stdout.
        Err(e) => {
            eprintln!("enclave-status --json failed to serialize the report: {e}");
            1
        }
    }
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

/// The versioned, machine-readable enclave status: the exact object
/// `chromium-bridge enclave-status --json` prints (ADR-0029). It is a typed
/// mirror of what used to be an ad-hoc `serde_json::json!`, so the host that
/// emits it and the desktop app that parses it back (`src/apps/desktop`) share
/// one Rust definition instead of two hand-kept shapes.
///
/// The wire form is frozen: a consumer refuses an unrecognized `v` BEFORE it
/// trusts any other field, so field names and `v` must not change without a
/// version bump. `deny_unknown_fields` makes an unexpected shape a loud
/// refusal on the parsing side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct EnclaveStatusReport {
    /// Schema version. `1` today; a newer value must be refused before any
    /// field below is read (fail closed).
    pub v: u32,
    /// Whether this platform has a Secure Enclave (macOS today).
    pub supported: bool,
    /// The keychain label the enrollment key lives under.
    pub key_label: String,
    /// The keychain lookup outcome.
    pub key: EnclaveKeyState,
    /// Base64 X9.63 public key; present only when `key == present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub public_key_b64: Option<String>,
    /// The public key's SHA-256 fingerprint; present only when `key == present`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub fingerprint: Option<String>,
    /// Human detail for a `key == invalid` or `key == error` state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub detail: Option<String>,
    /// The recorded enrollment policy, or `null` when there is no readable
    /// config. Always present on the wire (as `null`), never omitted.
    pub policy: Option<EnclavePolicyReport>,
    /// Set only when the policy read itself failed; `policy` is then `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub policy_error: Option<String>,
}

/// The keychain lookup outcome, lowercased on the wire. `invalid` means a key
/// exists under our label but must be treated as untrusted (planted or
/// malformed), which a consumer surfaces as loudly as the human report does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum EnclaveKeyState {
    /// A key is present and its public half is readable.
    Present,
    /// No key on this machine.
    None,
    /// A key exists under our label but is untrusted (planted or malformed).
    Invalid,
    /// This platform has no Secure Enclave.
    Unsupported,
    /// The lookup itself failed (keychain error, unreadable key).
    Error,
}

/// The enrollment policy carried in the report, mirrored from [`HostConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct EnclavePolicyReport {
    pub enrolled: bool,
    pub granularity: String,
}

/// Build the typed status report. Pure (no keychain access): the caller
/// resolves the key state and policy, this maps them onto the wire struct.
fn build_status_report(
    key: &KeyReport,
    policy: &Result<Option<HostConfig>, String>,
) -> EnclaveStatusReport {
    let mut report = EnclaveStatusReport {
        v: 1,
        supported: cfg!(target_os = "macos"),
        key_label: KEY_LABEL.to_string(),
        key: EnclaveKeyState::None,
        public_key_b64: None,
        fingerprint: None,
        detail: None,
        policy: None,
        policy_error: None,
    };
    match key {
        KeyReport::Present(public) => {
            report.key = EnclaveKeyState::Present;
            report.public_key_b64 = Some(public.to_base64());
            report.fingerprint = Some(public.fingerprint_display());
        }
        KeyReport::None => report.key = EnclaveKeyState::None,
        KeyReport::Invalid(detail) => {
            report.key = EnclaveKeyState::Invalid;
            report.detail = Some(detail.clone());
        }
        KeyReport::Unsupported => report.key = EnclaveKeyState::Unsupported,
        KeyReport::Error(detail) => {
            report.key = EnclaveKeyState::Error;
            report.detail = Some(detail.clone());
        }
    }
    match policy {
        Ok(Some(cfg)) => {
            report.policy = Some(EnclavePolicyReport {
                enrolled: cfg.enrolled,
                granularity: cfg.granularity.clone(),
            });
        }
        Ok(None) => report.policy = None,
        Err(e) => {
            report.policy = None;
            report.policy_error = Some(e.clone());
        }
    }
    report
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

    /// The wire bytes `enclave-status --json` emits: the typed struct serialized
    /// through `Value` exactly as `run_status_json` does. A helper so the tests
    /// assert against the real emitted form.
    fn wire(key: &KeyReport, policy: &Result<Option<HostConfig>, String>) -> serde_json::Value {
        serde_json::to_value(build_status_report(key, policy)).expect("report serializes")
    }

    /// The pre-refactor ad-hoc `json!` rendering, kept ONLY here as the golden
    /// reference: the typed struct must serialize to byte-identical JSON.
    fn legacy_render(
        key: &KeyReport,
        policy: &Result<Option<HostConfig>, String>,
    ) -> serde_json::Value {
        let mut out = serde_json::json!({
            "v": 1,
            "supported": cfg!(target_os = "macos"),
            "key_label": KEY_LABEL,
        });
        let obj = out.as_object_mut().expect("json! literal is an object");
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

    #[test]
    fn json_report_carries_the_fingerprint_for_a_present_key() {
        let public = present_key();
        let (b64, fingerprint) = (public.to_base64(), public.fingerprint_display());
        let v = wire(
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
        let none = wire(&KeyReport::None, &Ok(None));
        assert_eq!(none["key"], "none");
        assert!(none["policy"].is_null());
        assert!(none.get("fingerprint").is_none());

        let invalid = wire(
            &KeyReport::Invalid("planted software key".into()),
            &Ok(None),
        );
        assert_eq!(invalid["key"], "invalid");
        assert_eq!(invalid["detail"], "planted software key");

        let unsupported = wire(&KeyReport::Unsupported, &Ok(None));
        assert_eq!(unsupported["key"], "unsupported");

        let err = wire(&KeyReport::Error("keychain: -25300".into()), &Ok(None));
        assert_eq!(err["key"], "error");
        assert_eq!(err["detail"], "keychain: -25300");
    }

    #[test]
    fn json_report_surfaces_an_unreadable_policy() {
        let v = wire(&KeyReport::None, &Err("config decode: bad".into()));
        assert!(v["policy"].is_null());
        assert_eq!(v["policy_error"], "config decode: bad");
    }

    /// Byte-for-byte wire compatibility: the typed struct must serialize to
    /// exactly the JSON string the old ad-hoc `json!` renderer produced, for
    /// every key/policy combination. This is the contract the desktop app and
    /// any older host binary depend on.
    #[test]
    fn typed_report_is_byte_identical_to_the_legacy_json() {
        let enrolled = Ok(Some(HostConfig {
            enrolled: true,
            ..HostConfig::default()
        }));
        let no_config: Result<Option<HostConfig>, String> = Ok(None);
        let unreadable: Result<Option<HostConfig>, String> = Err("config decode: bad".into());
        let cases: Vec<(KeyReport, &Result<Option<HostConfig>, String>)> = vec![
            (KeyReport::Present(present_key()), &enrolled),
            (KeyReport::None, &no_config),
            (
                KeyReport::Invalid("planted software key".into()),
                &no_config,
            ),
            (KeyReport::Unsupported, &no_config),
            (KeyReport::Error("keychain: -25300".into()), &no_config),
            (KeyReport::None, &unreadable),
        ];
        for (key, policy) in &cases {
            let typed = serde_json::to_string(&build_status_report(key, policy))
                .expect("report serializes");
            // The emitted form: routed through `Value` so keys stay sorted.
            let emitted = serde_json::to_value(build_status_report(key, policy))
                .expect("report serializes")
                .to_string();
            let legacy = legacy_render(key, policy).to_string();
            assert_eq!(
                emitted, legacy,
                "emitted wire JSON drifted from the legacy form"
            );
            // A struct serialized directly is NOT sorted; it must still round-trip
            // to the same value, proving no field was dropped or renamed.
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&typed).unwrap(),
                legacy_render(key, policy),
            );
        }
    }

    /// A literal byte-golden for the common `key=none`, enrolled case: the
    /// exact string `enclave-status --json` prints today. Unlike the
    /// legacy-comparison test (both sides share the serializer), this pins the
    /// concrete bytes, so a serializer-config change (e.g. enabling
    /// `preserve_order`) that silently altered the wire form would fail here.
    #[test]
    fn emitted_wire_bytes_match_the_frozen_golden() {
        let report = build_status_report(
            &KeyReport::None,
            &Ok(Some(HostConfig {
                enrolled: true,
                ..HostConfig::default()
            })),
        );
        let emitted = serde_json::to_value(&report)
            .expect("report serializes")
            .to_string();
        // Keys sorted (serde_json default Map ordering), `key_label` is KEY_LABEL.
        let golden = format!(
            "{{\"key\":\"none\",\"key_label\":\"{KEY_LABEL}\",\
             \"policy\":{{\"enrolled\":true,\"granularity\":\"session\"}},\
             \"supported\":{},\"v\":1}}",
            cfg!(target_os = "macos"),
        );
        assert_eq!(
            emitted, golden,
            "the enclave-status --json wire bytes drifted"
        );
    }

    /// The typed report round-trips through serde: what the host emits, the
    /// desktop app deserializes back into the same struct (its parse path).
    #[test]
    fn typed_report_round_trips_through_serde() {
        let report = build_status_report(
            &KeyReport::Present(present_key()),
            &Ok(Some(HostConfig {
                enrolled: true,
                ..HostConfig::default()
            })),
        );
        let json = serde_json::to_string(&report).expect("serializes");
        let back: EnclaveStatusReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(report, back);
    }

    /// The parse side rejects an unexpected field rather than silently
    /// coercing it: `deny_unknown_fields` is the fail-closed guard the desktop
    /// app relies on when a host emits a shape it does not understand.
    #[test]
    fn typed_report_rejects_unknown_fields() {
        let with_extra =
            r#"{"v":1,"supported":true,"key_label":"x","key":"none","policy":null,"surprise":1}"#;
        let parsed: Result<EnclaveStatusReport, _> = serde_json::from_str(with_extra);
        assert!(
            parsed.is_err(),
            "an unknown field must be refused, not ignored"
        );
    }
}
