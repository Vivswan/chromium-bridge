//! The exchange driven end to end with a software authenticator built to the WebAuthn layouts (nothing
//! captured from a real one): enrollment on a fresh machine, the kill release behind an assertion, and every
//! refusal the host owes a replayed, misdirected, or unenrolled answer.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::*;
use crate::audit::AuditRecord;
use crate::protocol::control::{AdminControl, WebAuthnControl};
use crate::runtime_record::RuntimeRecord;
use crate::test_support::scratch_runtime_dir;
use crate::webauthn::{encode, Assertion};

const UP_UV: u8 = encode::flags::UP | encode::flags::UV;

fn label(s: &str) -> BrowserLabel {
    BrowserLabel::parse(s).unwrap()
}

/// One authenticator: a key, a credential id, and a counter it advances per assertion.
struct Authenticator {
    key: SigningKey,
    id: Vec<u8>,
    count: u32,
}

impl Authenticator {
    fn new(seed: u8) -> Self {
        Authenticator {
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
            id: vec![seed; 32],
            count: 0,
        }
    }

    fn id_b64(&self) -> String {
        webauthn::base64url_encode(&self.id)
    }

    /// The spelling the audit trail carries for this credential.
    fn audit_label(&self) -> String {
        format!("webauthn:{}", hex::encode(Sha256::digest(&self.id)))
    }

    fn client_data(kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": challenge,
            "origin": RpId::pinned().origin(),
        }))
        .unwrap()
    }

    /// The `navigator.credentials.create` response: attestation `none` over an attested ES256 credential.
    fn register(&self, challenge: &str) -> Registration {
        let cose = encode::cose_ec2_key(&self.key.verifying_key().to_sec1_bytes(), encode::ES256);
        let auth = encode::authenticator_data(
            &RpId::pinned().hash(),
            UP_UV | encode::flags::AT,
            0,
            Some((&self.id, &cose)),
        );
        let object = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("none".into()),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(Vec::new()),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(auth),
            ),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::into_writer(&object, &mut attestation_object).unwrap();
        Registration {
            attestation_object,
            client_data_json: Self::client_data("webauthn.create", challenge),
        }
    }

    /// The `navigator.credentials.get` response for `challenge`, the counter advanced by one.
    fn assert(&mut self, challenge: &str) -> Assertion {
        self.count += 1;
        self.assert_with_count(challenge, self.count)
    }

    fn assert_with_count(&self, challenge: &str, count: u32) -> Assertion {
        let authenticator_data =
            encode::authenticator_data(&RpId::pinned().hash(), UP_UV, count, None);
        let client_data_json = Self::client_data("webauthn.get", challenge);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig: Signature = self.key.sign(&signed);
        Assertion {
            authenticator_data,
            client_data_json,
            signature: sig.to_der().to_bytes().into_vec(),
        }
    }
}

fn unwrap_webauthn(reply: &HostReply) -> &WebAuthnControl {
    match reply {
        HostReply::WebAuthn(frame) => frame,
        HostReply::Enclave(_) | HostReply::Admin(_) | HostReply::Policy(_) => {
            panic!("expected a WebAuthn frame, got {reply:?}")
        }
    }
}

fn enroll_options(reply: &HostReply) -> (String, String) {
    let WebAuthnControl::EnrollOptions {
        challenge, nonce, ..
    } = unwrap_webauthn(reply)
    else {
        panic!("expected enroll_options, got {reply:?}")
    };
    (challenge.clone(), nonce.clone())
}

fn presence_request(reply: &HostReply) -> (String, Vec<String>) {
    let WebAuthnControl::PresenceRequest {
        challenge,
        allowed_credential_ids,
        ..
    } = unwrap_webauthn(reply)
    else {
        panic!("expected presence_request, got {reply:?}")
    };
    (challenge.clone(), allowed_credential_ids.clone())
}

fn presence_nonce(reply: &HostReply) -> String {
    let WebAuthnControl::PresenceRequest { nonce, .. } = unwrap_webauthn(reply) else {
        panic!("expected presence_request, got {reply:?}")
    };
    nonce.clone()
}

fn presence_reason(reply: &HostReply) -> Option<String> {
    let WebAuthnControl::PresenceResult { ok: false, reason } = unwrap_webauthn(reply) else {
        panic!("expected a refused presence_result, got {reply:?}")
    };
    reason.clone()
}

fn enroll_reason(reply: &HostReply) -> Option<String> {
    let WebAuthnControl::EnrollResult {
        ok: false, reason, ..
    } = unwrap_webauthn(reply)
    else {
        panic!("expected a refused enroll_result, got {reply:?}")
    };
    reason.clone()
}

/// Open a later enrollment: `enroll_begin` is answered `presence_required` beside the pushed request, `approver`
/// answers it, and the second `enroll_begin` consumes the approval. Returns the enroll_options challenge.
fn approve_enrollment(exchange: &mut Exchange, approver: &mut Authenticator) -> String {
    let replies = exchange.enroll_begin();
    assert_eq!(replies.len(), 2, "{replies:?}");
    let (challenge, _) = presence_request(&replies[0]);
    assert_eq!(
        enroll_reason(&replies[1]).as_deref(),
        Some("presence_required")
    );
    let replies = exchange.presence_assert(&approver.id_b64(), Ok(approver.assert(&challenge)));
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_approved(&replies[0]);
    let replies = exchange.enroll_begin();
    assert_eq!(replies.len(), 1, "{replies:?}");
    enroll_options(&replies[0]).0
}

/// Enroll `authenticator` for `exchange`'s browser on a machine with no enrollment (trust on first use).
fn enroll_tofu(exchange: &mut Exchange, authenticator: &Authenticator) {
    let replies = exchange.enroll_begin();
    assert_eq!(replies.len(), 1, "{replies:?}");
    let (challenge, _) = enroll_options(&replies[0]);
    let replies = exchange.enroll_finish(Ok(authenticator.register(&challenge)));
    assert_enrolled(&replies[0], authenticator);
}

fn assert_enrolled(reply: &HostReply, authenticator: &Authenticator) {
    let WebAuthnControl::EnrollResult {
        ok: true,
        credential_id: Some(id),
        reason: None,
    } = unwrap_webauthn(reply)
    else {
        panic!("expected enroll_result ok, got {reply:?}")
    };
    assert_eq!(*id, authenticator.id_b64(), "the registered credential");
}

fn assert_approved(reply: &HostReply) {
    let WebAuthnControl::PresenceResult {
        ok: true,
        reason: None,
    } = unwrap_webauthn(reply)
    else {
        panic!("expected presence_result ok, got {reply:?}")
    };
}

fn audit_text() -> String {
    std::fs::read_to_string(crate::audit::audit_path().unwrap()).unwrap()
}

/// Every record of `kind` in the trail, parsed; a line that does not parse is a failure, not a skipped row.
fn audit_records(kind: AuditKind) -> Vec<AuditRecord> {
    audit_text()
        .lines()
        .map(|line| serde_json::from_str::<AuditRecord>(line).unwrap())
        .filter(|r| r.event_kind == kind)
        .collect()
}

/// The first enrollment on a fresh machine is trust on first use and lands in trust.json under the browser's
/// label; the enroll_options the host emitted carry the challenge of the statement it later verified.
#[test]
fn a_fresh_machine_enrolls_on_first_use_and_records_the_credential() {
    let _dir = scratch_runtime_dir();
    let mut exchange = Exchange::new(label("brave"));
    let authenticator = Authenticator::new(0x11);
    let replies = exchange.enroll_begin();
    let (challenge, nonce) = enroll_options(&replies[0]);
    let statement = Statement {
        domain: StatementDomain::Enrollment,
        browser_label: label("brave"),
        action: Action::parse("enroll").unwrap(),
        nonce: Nonce::parse(&nonce).unwrap(),
    };
    assert_eq!(challenge, statement.challenge().to_base64url());
    let replies = exchange.enroll_finish(Ok(authenticator.register(&challenge)));
    assert_enrolled(&replies[0], &authenticator);
    let enrolled = TrustState::current().unwrap().enrollments().to_vec();
    assert_eq!(enrolled.len(), 1);
    assert_eq!(enrolled[0].label, label("brave"));
    assert_eq!(enrolled[0].credential.id.as_bytes(), &authenticator.id[..]);
    assert_eq!(enrolled[0].credential.sign_count, 0);
    let enrolls = audit_records(AuditKind::Enroll);
    assert_eq!(enrolls.len(), 1, "{enrolls:?}");
    assert_eq!(enrolls[0].outcome.as_deref(), Some("ok"));
    assert_eq!(enrolls[0].surface, Some(Surface::Extension));
    assert_eq!(
        enrolls[0].detail.as_deref(),
        Some(
            format!(
                "browser=brave; credential={}; authorized_by=first_use",
                authenticator.audit_label()
            )
            .as_str()
        ),
        "the trail names the browser, the credential, and first use"
    );
    // A second enroll_finish answers nothing outstanding: the statement was consumed.
    let replies = exchange.enroll_finish(Ok(authenticator.register(&challenge)));
    assert_eq!(
        enroll_reason(&replies[0]).as_deref(),
        Some("no_enrollment_outstanding")
    );
}

/// The kill release from the extension: presence_request names exactly this browser's credential, an
/// assertion over its challenge releases the switch, the counter is persisted, and the trail names the path.
#[test]
fn kill_release_needs_an_assertion_from_this_browsers_credential_and_persists_the_counter() {
    let _dir = scratch_runtime_dir();
    let mut exchange = Exchange::new(label("brave"));
    let mut authenticator = Authenticator::new(0x11);
    enroll_tofu(&mut exchange, &authenticator);
    crate::kill::engage(Surface::Cli).unwrap();

    let replies = exchange.kill_release();
    let (challenge, allowed) = presence_request(&replies[0]);
    assert_eq!(allowed, vec![authenticator.id_b64()]);
    let replies = exchange.presence_assert(
        &authenticator.id_b64(),
        Ok(authenticator.assert(&challenge)),
    );
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_approved(&replies[0]);
    assert!(
        matches!(
            &replies[1],
            HostReply::Admin(AdminControl::KillStatusResult {
                ok: true,
                killed: Some(false),
                error: None,
            })
        ),
        "{replies:?}"
    );
    assert!(!crate::kill::is_killed().unwrap());
    assert_eq!(
        TrustState::current().unwrap().enrollments()[0]
            .credential
            .sign_count,
        1,
        "the accepted assertion's counter is persisted"
    );
    let releases = audit_records(AuditKind::KillRelease);
    assert_eq!(releases.len(), 1, "{releases:?}");
    assert_eq!(releases[0].outcome.as_deref(), Some("ok"));
    assert_eq!(releases[0].surface, Some(Surface::Extension));
    assert_eq!(
        releases[0].detail.as_deref(),
        Some(format!("auth={}", authenticator.audit_label()).as_str())
    );
}

/// Every refusal the host owes an answer that is not a fresh assertion from this browser's own credential:
/// each row names the input and the one code it produces, and the switch stays engaged through all of them.
#[test]
fn replayed_misdirected_and_unenrolled_answers_are_refused_and_the_switch_stays_engaged() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    // A credential enrolled under another browser's label, on the same machine.
    let mut chrome = Exchange::new(label("chrome"));
    let other_browser = Authenticator::new(0x22);
    {
        let (_, allowed) = presence_request(&chrome.enroll_begin()[0]);
        assert_eq!(
            allowed,
            vec![own.id_b64()],
            "any enrolled credential approves"
        );
        let challenge = approve_enrollment(&mut chrome, &mut own);
        chrome.enroll_finish(Ok(other_browser.register(&challenge)));
    }
    let unenrolled = Authenticator::new(0x33);
    crate::kill::engage(Surface::Cli).unwrap();

    // A request, answered correctly once; its assertion is the replay candidate below.
    let replies = brave.kill_release();
    let (first_challenge, _) = presence_request(&replies[0]);
    let accepted = own.assert(&first_challenge);
    let replies = brave.presence_assert(&own.id_b64(), Ok(accepted.clone()));
    assert_approved(&replies[0]);
    crate::kill::engage(Surface::Cli).unwrap();

    // The verifier reads the counter before the clientData, so a byte-identical replay is caught as a
    // stalled counter; a fresh assertion over the superseded challenge is the challenge mismatch.
    type Answer = Box<dyn Fn(&str, &mut Authenticator) -> (String, Assertion)>;
    let cases: Vec<(&str, Answer, &str)> = vec![
        (
            "the accepted assertion replayed against a new request",
            Box::new(move |_, _| (own_id(0x11), accepted.clone())),
            "sign_count_not_increased",
        ),
        (
            "a fresh assertion over the earlier, superseded challenge",
            Box::new(move |_, own| (own.id_b64(), own.assert(&first_challenge))),
            "challenge_mismatch",
        ),
        (
            "a credential enrolled under another browser's label",
            Box::new(move |challenge, _| {
                (
                    other_browser.id_b64(),
                    other_browser.assert_with_count(challenge, 1),
                )
            }),
            "wrong_browser_label",
        ),
        (
            "a credential enrolled nowhere",
            Box::new(move |challenge, _| {
                (
                    unenrolled.id_b64(),
                    unenrolled.assert_with_count(challenge, 1),
                )
            }),
            "credential_not_enrolled",
        ),
    ];
    for (case, answer, want) in cases {
        let replies = brave.kill_release();
        let (challenge, _) = presence_request(&replies[0]);
        let (id, assertion) = answer(&challenge, &mut own);
        let replies = brave.presence_assert(&id, Ok(assertion));
        assert_eq!(replies.len(), 1, "{case}: {replies:?}");
        assert_eq!(
            presence_reason(&replies[0]).as_deref(),
            Some(want),
            "{case}"
        );
        assert!(
            crate::kill::is_killed().unwrap(),
            "{case}: the switch stays engaged"
        );
    }
    // Nothing outstanding after a refusal: the request was consumed by the attempt.
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert("AAAA")));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding")
    );
    let trail = audit_text();
    assert!(trail.contains("\"outcome\":\"refused\""), "{trail}");
    assert!(
        trail.contains("wrong_browser_label") || trail.contains("not this one"),
        "{trail}"
    );
}

fn own_id(seed: u8) -> String {
    webauthn::base64url_encode(&[seed; 32])
}

/// A second enrollment on an enrolled machine needs presence first, and a presence answer over a stale
/// challenge (a superseded request) is refused as a challenge mismatch.
#[test]
fn a_later_enrollment_needs_presence_and_a_superseded_request_cannot_be_answered() {
    let _dir = scratch_runtime_dir();
    let mut exchange = Exchange::new(label("brave"));
    let mut first = Authenticator::new(0x11);
    enroll_tofu(&mut exchange, &first);

    let replies = exchange.enroll_begin();
    let (stale_challenge, _) = presence_request(&replies[0]);
    // A second enroll_begin supersedes the first request; an answer to the stale one no longer matches.
    let replies = exchange.enroll_begin();
    presence_request(&replies[0]);
    let replies = exchange.presence_assert(&first.id_b64(), Ok(first.assert(&stale_challenge)));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("challenge_mismatch")
    );
    // The refusal consumed the request; a fresh one is answered, and the approval is held for the next
    // enroll_begin only: a kill_release in between supersedes it, so the enrollment needs presence again.
    let (challenge, _) = presence_request(&exchange.enroll_begin()[0]);
    let replies = exchange.presence_assert(&first.id_b64(), Ok(first.assert(&challenge)));
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_approved(&replies[0]);
    presence_request(&exchange.kill_release()[0]);
    let replies = exchange.enroll_begin();
    assert_eq!(
        enroll_reason(&replies[1]).as_deref(),
        Some("presence_required"),
        "the superseded approval does not open the enrollment"
    );
    let enroll_challenge = approve_enrollment(&mut exchange, &mut first);
    let second = Authenticator::new(0x22);
    let replies = exchange.enroll_finish(Ok(second.register(&enroll_challenge)));
    assert_enrolled(&replies[0], &second);
    assert_eq!(TrustState::current().unwrap().enrollments().len(), 2);
}

/// A registration answering another statement's challenge is refused with the verifier's code and nothing is
/// stored.
#[test]
fn a_registration_over_another_challenge_is_refused_and_nothing_is_stored() {
    let _dir = scratch_runtime_dir();
    let mut exchange = Exchange::new(label("brave"));
    let authenticator = Authenticator::new(0x11);
    let replies = exchange.enroll_begin();
    enroll_options(&replies[0]);
    let other = Statement {
        domain: StatementDomain::Enrollment,
        browser_label: label("brave"),
        action: Action::parse("enroll").unwrap(),
        nonce: Nonce::parse("some-other-nonce").unwrap(),
    }
    .challenge()
    .to_base64url();
    let replies = exchange.enroll_finish(Ok(authenticator.register(&other)));
    assert_eq!(
        enroll_reason(&replies[0]).as_deref(),
        Some("challenge_mismatch")
    );
    assert!(TrustState::current().unwrap().enrollments().is_empty());
    let enrolls = audit_records(AuditKind::Enroll);
    assert_eq!(enrolls.len(), 1, "{enrolls:?}");
    assert_eq!(enrolls[0].outcome.as_deref(), Some("refused"));
    assert!(
        enrolls[0]
            .detail
            .as_deref()
            .is_some_and(|d| d.starts_with("browser=brave; ")),
        "the refusal names the browser: {enrolls:?}"
    );
}

/// Two hosts open first-use enrollments on an empty machine; after the first lands, the second's write runs
/// under the first-use rule against a store that is no longer empty and is refused, so an unapproved
/// enrollment cannot ride a stale trust-on-first-use decision.
#[test]
fn a_first_use_enrollment_is_refused_once_another_credential_landed_first() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut chrome = Exchange::new(label("chrome"));
    let (brave_challenge, _) = enroll_options(&brave.enroll_begin()[0]);
    let (chrome_challenge, _) = enroll_options(&chrome.enroll_begin()[0]);
    let first = Authenticator::new(0x11);
    let second = Authenticator::new(0x22);
    assert_enrolled(
        &brave.enroll_finish(Ok(first.register(&brave_challenge)))[0],
        &first,
    );
    let replies = chrome.enroll_finish(Ok(second.register(&chrome_challenge)));
    assert_eq!(
        enroll_reason(&replies[0]).as_deref(),
        Some("machine_already_enrolled")
    );
    let enrolled = TrustState::current().unwrap().enrollments().to_vec();
    assert_eq!(enrolled.len(), 1);
    assert_eq!(enrolled[0].label, label("brave"));
}

/// A credential re-enrolled under another browser between a request and its answer no longer answers the
/// first browser's request: the rule is judged against the enrollment as it stands, not the minted hint.
#[test]
fn a_credential_moved_to_another_browser_cannot_answer_the_first_browsers_request() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut shared = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &shared);
    crate::kill::engage(Surface::Cli).unwrap();
    let replies = brave.kill_release();
    let (challenge, hint) = presence_request(&replies[0]);
    assert_eq!(hint, vec![shared.id_b64()]);

    // Chrome enrolls the same credential (a synced passkey) with Brave's approval, which moves it.
    let mut chrome = Exchange::new(label("chrome"));
    let enroll_challenge = approve_enrollment(&mut chrome, &mut shared);
    assert_enrolled(
        &chrome.enroll_finish(Ok(shared.register(&enroll_challenge)))[0],
        &shared,
    );

    let replies = brave.presence_assert(&shared.id_b64(), Ok(shared.assert(&challenge)));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("wrong_browser_label")
    );
    assert!(crate::kill::is_killed().unwrap());
}

/// The counter write is decided against the stored counter under the lock, not the caller's snapshot: a
/// value another host already moved past is refused as stale, a forward value lands, and a credential that
/// was never enrolled is named as such. A refusal writes nothing: the record's bytes and its epoch are as
/// they were, so a replayed assertion does not stamp the trail every watcher re-reads on.
#[test]
fn the_counter_write_refuses_a_stale_value_under_the_lock_and_writes_nothing() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    let id = CredentialId::parse(own.id.clone()).unwrap();
    webauthn::advance_sign_count(&id, 5).unwrap();
    let record = || {
        (
            std::fs::read(crate::trust::Trust::path().unwrap()).unwrap(),
            TrustState::current().unwrap().epoch(),
        )
    };
    let before = record();
    assert!(matches!(
        webauthn::advance_sign_count(&id, 3),
        Err(webauthn::CounterError::Stale { stored: 5 })
    ));
    assert!(matches!(
        webauthn::advance_sign_count(&id, 5),
        Err(webauthn::CounterError::Stale { stored: 5 })
    ));
    assert_eq!(
        record(),
        before,
        "a stale value leaves the record untouched"
    );
    webauthn::advance_sign_count(&id, 6).unwrap();
    assert_eq!(
        TrustState::current().unwrap().enrollments()[0]
            .credential
            .sign_count,
        6
    );
    let before = record();
    let stranger = CredentialId::parse(vec![0x33; 32]).unwrap();
    assert!(matches!(
        webauthn::advance_sign_count(&stranger, 1),
        Err(webauthn::CounterError::NotEnrolled)
    ));
    assert_eq!(
        record(),
        before,
        "an unenrolled credential leaves the record untouched"
    );
}

/// A browser with no credential of its own answers with the window, even on a machine where another browser
/// is enrolled: the rule is per browser label, the release lands, and the trail names the software path.
#[test]
fn a_browser_with_no_credential_releases_by_window_and_the_trail_names_the_software_path() {
    let _dir = scratch_runtime_dir();
    let mut chrome = Exchange::new(label("chrome"));
    enroll_tofu(&mut chrome, &Authenticator::new(0x22));
    let mut brave = Exchange::new(label("brave"));
    crate::kill::engage(Surface::Cli).unwrap();

    let replies = brave.kill_release();
    let (_, allowed) = presence_request(&replies[0]);
    assert!(
        allowed.is_empty(),
        "brave has no credential to hint: {allowed:?}"
    );
    let nonce = presence_nonce(&replies[0]);
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_approved(&replies[0]);
    assert!(
        matches!(
            &replies[1],
            HostReply::Admin(AdminControl::KillStatusResult {
                ok: true,
                killed: Some(false),
                error: None,
            })
        ),
        "{replies:?}"
    );
    assert!(!crate::kill::is_killed().unwrap());
    let releases = audit_records(AuditKind::KillRelease);
    assert_eq!(releases.len(), 1, "{releases:?}");
    assert_eq!(releases[0].outcome.as_deref(), Some("ok"));
    assert_eq!(releases[0].detail.as_deref(), Some("auth=confirm_window"));
}

/// An enrolled browser's window answer is the downgrade the ladder forbids: refused by code, the switch stays
/// engaged, and the refusal is in the trail. An answer to nothing and a superseded request's nonce are the
/// other two refusals a confirmation can earn.
#[test]
fn an_enrolled_browsers_window_answer_is_refused_and_the_switch_stays_engaged() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    enroll_tofu(&mut brave, &Authenticator::new(0x11));
    crate::kill::engage(Surface::Cli).unwrap();

    let replies = brave.kill_release();
    let nonce = presence_nonce(&replies[0]);
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("software_confirmation_not_allowed")
    );
    assert!(crate::kill::is_killed().unwrap());
    let releases = audit_records(AuditKind::KillRelease);
    assert_eq!(releases.len(), 1, "{releases:?}");
    assert_eq!(releases[0].outcome.as_deref(), Some("refused"));

    // The refusal consumed the request: nothing is outstanding.
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding")
    );

    // A confirmation naming a superseded request's nonce does not ride the newer request.
    let stale = nonce;
    let replies = brave.kill_release();
    assert_ne!(stale, presence_nonce(&replies[0]));
    let replies = brave.presence_confirm(&stale);
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("request_mismatch")
    );
    assert!(crate::kill::is_killed().unwrap());
}

/// An approval is for the ceremony it was given for: it expires after APPROVAL_TTL, and it does not survive a
/// trust reset, where the first-use rule (re-checked under the lock) governs again: the registration opened
/// under a stale approval is refused once another credential landed first.
#[test]
fn an_enrollment_approval_expires_and_does_not_outlive_the_enrollments_it_presupposed() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut first = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &first);

    // Expired: the next enroll_begin asks for presence again.
    let (challenge, _) = presence_request(&brave.enroll_begin()[0]);
    assert_approved(&brave.presence_assert(&first.id_b64(), Ok(first.assert(&challenge)))[0]);
    brave.expire_approval_for_tests();
    let replies = brave.enroll_begin();
    assert_eq!(
        enroll_reason(&replies[1]).as_deref(),
        Some("presence_required"),
        "an expired approval opens nothing"
    );

    // Approved again, then the trust record is reset: the store is empty, so the enroll_begin is first use,
    // and a concurrent first-use enrollment landing first makes this one's write refuse.
    let (challenge, _) = presence_request(&replies[0]);
    assert_approved(&brave.presence_assert(&first.id_b64(), Ok(first.assert(&challenge)))[0]);
    std::fs::remove_file(crate::trust::Trust::path().unwrap()).unwrap();
    let replies = brave.enroll_begin();
    assert_eq!(replies.len(), 1, "{replies:?}");
    let (challenge, _) = enroll_options(&replies[0]);
    let mut chrome = Exchange::new(label("chrome"));
    enroll_tofu(&mut chrome, &Authenticator::new(0x22));
    let replies = brave.enroll_finish(Ok(Authenticator::new(0x33).register(&challenge)));
    assert_eq!(
        enroll_reason(&replies[0]).as_deref(),
        Some("machine_already_enrolled")
    );
    assert_eq!(TrustState::current().unwrap().enrollments().len(), 1);
}
