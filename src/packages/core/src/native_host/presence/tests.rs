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

/// A browser forgets itself through its own host and only itself: the other browser's enrollment stays, the
/// trail names the forgotten credential under the extension surface, and a second forget is refused.
#[test]
fn a_browser_forgets_itself_and_only_itself() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut brave_auth = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &brave_auth);
    let mut chrome = Exchange::new(label("chrome"));
    let chrome_auth = Authenticator::new(0x22);
    let challenge = approve_enrollment(&mut chrome, &mut brave_auth);
    let replies = chrome.enroll_finish(Ok(chrome_auth.register(&challenge)));
    assert_enrolled(&replies[0], &chrome_auth);

    let replies = brave.browser_revoke();
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert!(
        matches!(
            unwrap_webauthn(&replies[0]),
            WebAuthnControl::BrowserRevokeResult {
                ok: true,
                reason: None
            }
        ),
        "{replies:?}"
    );
    let remaining: Vec<(String, String)> = TrustState::current()
        .unwrap()
        .enrollments()
        .iter()
        .map(|e| (e.label.as_str().to_string(), e.credential.id.to_base64url()))
        .collect();
    assert_eq!(
        remaining,
        vec![("chrome".to_string(), chrome_auth.id_b64())]
    );
    let records = audit_records(AuditKind::RevokeBrowser);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (
            records[0].surface,
            records[0].name.as_deref(),
            records[0].detail.as_deref()
        ),
        (
            Some(Surface::Extension),
            Some("brave"),
            Some(format!("credential={}", brave_auth.audit_label()).as_str())
        )
    );

    let replies = brave.browser_revoke();
    let WebAuthnControl::BrowserRevokeResult { ok: false, reason } = unwrap_webauthn(&replies[0])
    else {
        panic!("expected a refused browser_revoke_result, got {replies:?}")
    };
    assert_eq!(reason.as_deref(), Some("not_enrolled"));
}

/// A refused forget leaves the outstanding request in place, whether the store held nothing for the browser
/// (its window may still answer its own request) or could not be read: the worker still holds that request,
/// so its answer must find it rather than `no_request_outstanding`.
#[test]
fn a_refused_forget_keeps_the_outstanding_request() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    enroll_tofu(&mut brave, &Authenticator::new(0x11));
    crate::kill::engage(Surface::Cli).unwrap();
    let request_kept = |exchange: &mut Exchange, expected_reason: &str| {
        let replies = exchange.browser_revoke();
        let WebAuthnControl::BrowserRevokeResult { ok: false, reason } =
            unwrap_webauthn(&replies[0])
        else {
            panic!("expected a refused browser_revoke_result, got {replies:?}")
        };
        assert!(
            reason.as_deref().unwrap_or("").starts_with(expected_reason),
            "{reason:?}"
        );
        let replies = exchange.presence_confirm("not-the-outstanding-nonce");
        assert_eq!(
            presence_reason(&replies[0]).as_deref(),
            Some("request_mismatch"),
            "the request is still outstanding"
        );
    };

    let mut chrome = Exchange::new(label("chrome"));
    presence_request(&chrome.kill_release()[0]);
    request_kept(&mut chrome, "not_enrolled");

    presence_request(&brave.kill_release()[0]);
    std::fs::write(crate::trust::Trust::path().unwrap(), b"{ not a record").unwrap();
    request_kept(&mut brave, "store_error: ");
}

/// The page-op action the extension's `presence_begin` carries, as the pushed request spells it.
fn presence_action(reply: &HostReply) -> String {
    let WebAuthnControl::PresenceRequest { action, .. } = unwrap_webauthn(reply) else {
        panic!("expected presence_request, got {reply:?}")
    };
    action.clone()
}

/// A page operation's request: the statement names the op and the page's origin, only this browser's
/// credential is hinted, an assertion over its challenge is the whole answer (no second frame: the extension
/// runs the op), the request is consumed, and the trail names the op, the origin, and the credential.
#[test]
fn a_page_op_request_binds_the_origin_and_is_answered_by_this_browsers_credential() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);

    let replies = brave.presence_begin("page_eval", "https://example.com");
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(
        presence_action(&replies[0]),
        "page_eval on https://example.com"
    );
    let (challenge, allowed) = presence_request(&replies[0]);
    assert_eq!(allowed, vec![own.id_b64()]);
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert(&challenge)));
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_approved(&replies[0]);
    let replies = brave.presence_confirm("anything");
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding"),
        "the answer consumed the request"
    );
    let records = audit_records(AuditKind::PresenceAssert);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome.as_deref(), Some("ok"));
    assert_eq!(records[0].surface, Some(Surface::Extension));
    assert_eq!(
        records[0].detail.as_deref(),
        Some(
            format!(
                "act=page_eval; origin=https://example.com; auth={}",
                own.audit_label()
            )
            .as_str()
        )
    );
}

/// Every answer a page-op request refuses, each named by its code: the window on an enrolled browser, a
/// credential enrolled under another browser, one the host never saw, an assertion over a superseded
/// request's challenge, and a confirmation naming a superseded nonce. Each refusal consumes the request it
/// answered, so none of them leaves anything the next answer could ride.
#[test]
fn a_page_op_request_refuses_the_window_and_every_misdirected_or_stale_answer() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    let mut chrome = Exchange::new(label("chrome"));
    let mut other_browser = Authenticator::new(0x22);
    {
        let challenge = approve_enrollment(&mut chrome, &mut own);
        chrome.enroll_finish(Ok(other_browser.register(&challenge)));
    }
    let mut unenrolled = Authenticator::new(0x33);
    let begin = |brave: &mut Exchange| {
        let replies = brave.presence_begin("page_upload", "https://files.example.com:8443");
        (presence_request(&replies[0]).0, presence_nonce(&replies[0]))
    };

    let (_, nonce) = begin(&mut brave);
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("software_confirmation_not_allowed")
    );

    let (challenge, _) = begin(&mut brave);
    let replies = brave.presence_assert(
        &other_browser.id_b64(),
        Ok(other_browser.assert(&challenge)),
    );
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("wrong_browser_label")
    );

    let (challenge, _) = begin(&mut brave);
    let replies = brave.presence_assert(&unenrolled.id_b64(), Ok(unenrolled.assert(&challenge)));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("credential_not_enrolled")
    );

    // A newer request supersedes the older: the older's challenge and nonce answer nothing.
    let (stale_challenge, stale_nonce) = begin(&mut brave);
    let (challenge, nonce) = begin(&mut brave);
    assert_ne!(stale_challenge, challenge);
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert(&stale_challenge)));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("challenge_mismatch")
    );
    let (_, nonce_after) = begin(&mut brave);
    assert_ne!(nonce, nonce_after);
    let replies = brave.presence_confirm(&stale_nonce);
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("request_mismatch")
    );

    let refusals: Vec<String> = audit_records(AuditKind::PresenceAssert)
        .into_iter()
        .filter(|r| r.outcome.as_deref() == Some("refused"))
        .map(|r| r.detail.unwrap())
        .collect();
    assert_eq!(refusals.len(), 5, "{refusals:?}");
    assert!(
        refusals
            .iter()
            .all(|d| d.starts_with("act=page_upload; origin=https://files.example.com:8443; ")),
        "{refusals:?}"
    );
}

/// A browser with no credential of its own answers a page-op request with the window, the trail names the
/// software path beside the op and origin, and the request is consumed.
#[test]
fn a_bare_browser_answers_a_page_op_request_by_window_and_the_trail_names_the_software_path() {
    let _dir = scratch_runtime_dir();
    let mut chrome = Exchange::new(label("chrome"));
    enroll_tofu(&mut chrome, &Authenticator::new(0x22));
    let mut brave = Exchange::new(label("brave"));

    let replies = brave.presence_begin("page_eval", "http://localhost:3000");
    let (_, allowed) = presence_request(&replies[0]);
    assert!(allowed.is_empty(), "{allowed:?}");
    let nonce = presence_nonce(&replies[0]);
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_approved(&replies[0]);
    let records = audit_records(AuditKind::PresenceAssert);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        records[0].detail.as_deref(),
        Some("act=page_eval; origin=http://localhost:3000; auth=confirm_window")
    );
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding")
    );
}

/// A `presence_begin` naming an unknown action or a malformed origin is refused before anything is pending:
/// the outstanding request stays answerable exactly as it was, and the trail names each reason.
#[test]
fn a_refused_presence_begin_leaves_the_outstanding_request_as_it_was() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));

    let replies = brave.presence_begin("page_eval", "https://example.com");
    let nonce = presence_nonce(&replies[0]);
    for (action, origin, reason) in [
        ("page_click", "https://example.com", "invalid_action"),
        (
            "release the kill switch",
            "https://example.com",
            "invalid_action",
        ),
        ("page_eval", "null", "invalid_origin"),
        ("page_eval", "", "invalid_origin"),
        ("page_upload", "https://example.com/path", "invalid_origin"),
    ] {
        let replies = brave.presence_begin(action, origin);
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(
            presence_reason(&replies[0]).as_deref(),
            Some(reason),
            "{action:?} on {origin:?}"
        );
    }
    // The outstanding request survived every refusal.
    assert_approved(&brave.presence_confirm(&nonce)[0]);
    let refusals: Vec<String> = audit_records(AuditKind::PresenceAssert)
        .into_iter()
        .filter(|r| r.outcome.as_deref() == Some("refused"))
        .map(|r| r.detail.unwrap())
        .collect();
    assert_eq!(
        refusals,
        [
            "act=presence_begin; invalid_action",
            "act=presence_begin; invalid_action",
            "act=presence_begin; invalid_origin",
            "act=presence_begin; invalid_origin",
            "act=presence_begin; invalid_origin",
        ]
    );
}

/// An enrollment store that cannot be read refuses the request before anything is pending, with the store's
/// error named, and the trail carries it: a page op never runs on a guess about who is enrolled.
#[test]
fn a_presence_begin_over_an_unreadable_trust_record_is_refused_as_a_store_error() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    enroll_tofu(&mut brave, &Authenticator::new(0x11));
    std::fs::write(crate::trust::Trust::path().unwrap(), b"{ not the record").unwrap();

    let replies = brave.presence_begin("page_eval", "https://example.com");
    assert_eq!(replies.len(), 1, "{replies:?}");
    let reason = presence_reason(&replies[0]).unwrap();
    assert!(reason.starts_with("store_error: "), "{reason}");
    let replies = brave.presence_confirm("anything");
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding")
    );
    let refusals: Vec<String> = audit_records(AuditKind::PresenceAssert)
        .into_iter()
        .filter(|r| r.outcome.as_deref() == Some("refused"))
        .map(|r| r.detail.unwrap())
        .collect();
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(
        refusals[0].starts_with("act=presence_begin; store_error: "),
        "{refusals:?}"
    );
}

// ---- the grant lane and client pairing from the page --------------------------------------------------------

use crate::allowlist::{Anchor, ClientName};
use crate::ipc::SignerId;
use crate::policy::{HistoryEntryRef, PolicyField, PolicyOverlay, PolicyStore, PolicyValues};
use crate::protocol::control::PolicyControl;
use crate::trust::Clients;

/// The host key a grant signs with, minted into the scratch dir's file record; the test attestation stands in
/// for `pair`'s typed phrase.
fn mint_host_key() {
    crate::ipc::with_runtime_lock(|lock| {
        Ok(crate::enclave::EnrollmentKey::mint(
            lock,
            crate::enclave::KeyStore::File,
            PresenceAttestation::assume_for_tests(PresencePath::Tty),
        ))
    })
    .unwrap()
    .unwrap();
}

/// A signed baseline over `values` touching `touched`, written as the CLI writes one.
fn sign_baseline(values: PolicyValues, touched: Vec<PolicyField>) {
    crate::policy::set_signed(values, touched, Surface::Core, || {
        Ok(PresenceAttestation::assume_for_tests(PresencePath::Tty))
    })
    .unwrap();
}

fn effective() -> PolicyValues {
    PolicyStore::load().unwrap().unwrap().effective().unwrap()
}

fn revision() -> u64 {
    PolicyStore::load()
        .unwrap()
        .unwrap()
        .baseline_doc()
        .unwrap()
        .revision
}

/// `(ok, error)` of a write verdict frame, whichever lane answered.
fn write_verdict(reply: &HostReply) -> (bool, Option<String>) {
    match reply {
        HostReply::Policy(PolicyControl::PolicySetResult { ok, error })
        | HostReply::Policy(PolicyControl::PolicyRollbackResult { ok, error })
        | HostReply::Admin(AdminControl::ClientPairResult { ok, error }) => (*ok, error.clone()),
        other @ (HostReply::Enclave(_)
        | HostReply::Admin(_)
        | HostReply::Policy(_)
        | HostReply::WebAuthn(_)) => panic!("expected a write verdict, got {other:?}"),
    }
}

fn is_policy_current(reply: &HostReply) -> bool {
    matches!(
        reply,
        HostReply::Policy(PolicyControl::PolicyCurrent { ok: true, .. })
    )
}

fn page_eval_grant() -> PolicyOverlay {
    PolicyOverlay {
        page_eval_enabled: Some(true),
        ..PolicyOverlay::default()
    }
}

/// The CLI's up-front rule holds on the page too: with no host key the grant is refused in the CLI's words,
/// no presence request is minted (an assertion finds nothing outstanding), the store stays empty, and the
/// trail carries the same refused record the CLI leaves.
#[test]
fn a_policy_grant_from_the_page_is_refused_before_any_request_on_a_keyless_host() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);

    let replies = brave.policy_set(page_eval_grant());
    assert_eq!(replies.len(), 1, "{replies:?}");
    let (ok, error) = write_verdict(&replies[0]);
    assert!(!ok);
    assert_eq!(
        error.as_deref(),
        Some(
            "no host key on this machine; a policy grant is a signed baseline and refuses without \
             one (pair first)"
        )
    );
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert("unused")));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("no_request_outstanding"),
        "a keyless refusal mints no request"
    );
    assert!(PolicyStore::load().unwrap().is_none());
    let writes = audit_records(AuditKind::PolicyWrite);
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0].surface, Some(Surface::Extension));
    assert_eq!(writes[0].outcome.as_deref(), Some("refused"));
    assert_eq!(
        writes[0].detail.as_deref(),
        Some("no signing key; touched=pageEvalEnabled")
    );
}

/// The store the tap was shown is the store the write lands over: a restriction landing while the request is
/// outstanding refuses the grant as the conflict `policy set` would report, the restriction stands, and no
/// request is left behind. An invalid request (nothing touched) is refused before any request exists.
#[test]
fn a_store_that_moves_while_the_tap_is_awaited_refuses_the_grant_as_a_conflict() {
    let _dir = scratch_runtime_dir();
    mint_host_key();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    sign_baseline(
        PolicyValues {
            page_eval_enabled: true,
            ..PolicyValues::default()
        },
        vec![PolicyField::PageEvalEnabled],
    );

    let replies = brave.policy_set(PolicyOverlay {
        cdp_mode: Some(true),
        ..PolicyOverlay::default()
    });
    let (challenge, _) = presence_request(&replies[0]);
    crate::policy::restrict(
        PolicyOverlay {
            page_eval_enabled: Some(false),
            ..PolicyOverlay::default()
        },
        Surface::Cli,
    )
    .unwrap();
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert(&challenge)));
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_approved(&replies[0]);
    let (ok, error) = write_verdict(&replies[1]);
    assert!(!ok);
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("changed while this write was pending")),
        "{error:?}"
    );
    let written = effective();
    assert!(!written.page_eval_enabled, "the restriction stands");
    assert!(!written.cdp_mode, "the grant did not land");
    assert_eq!(revision(), 1);

    let replies = brave.policy_set(PolicyOverlay::default());
    assert_eq!(replies.len(), 1, "{replies:?}");
    let (ok, error) = write_verdict(&replies[0]);
    assert!(!ok);
    assert_eq!(
        error.as_deref(),
        Some("invalid policy write: the touched set is empty (a write must name the fields it edits)")
    );
}

/// A prompt shows the whole change it approves: a summary past the action bound is refused before any
/// request exists rather than shown truncated, on both lanes that embed caller-sized text (a long tool list,
/// an unbounded signer id), in each lane's own refusal words. A NUL byte in that text is the field's own
/// grammar refusal, never the bound's: the statement parser refuses both with one answer. The host here is
/// keyless: the bound is decided before the key lookup, so these refusals stay promptless and unaudited.
#[test]
fn a_summary_past_the_prompt_bound_is_refused_before_any_request() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    enroll_tofu(&mut brave, &Authenticator::new(0x11));
    let overlay = PolicyOverlay {
        disabled_tools: Some((0..40).map(|i| format!("tool_{i:0>60}")).collect()),
        ..PolicyOverlay::default()
    };
    let long_signer = Anchor::Signer(SignerId::try_from("A".repeat(MAX_ACTION_LEN)).unwrap());
    let cases = [
        (
            brave.policy_set(overlay),
            format!(
                "invalid policy write: the change summary exceeds the {MAX_ACTION_LEN}-byte bound a \
                 presence prompt can show"
            ),
        ),
        (
            brave.client_pair(ClientName::try_from("codex").unwrap(), long_signer),
            format!(
                "invalid pairing request: the pairing summary exceeds the {MAX_ACTION_LEN}-byte bound a \
                 presence prompt can show"
            ),
        ),
    ];
    for (replies, want) in cases {
        assert_eq!(replies.len(), 1, "{replies:?}");
        assert_eq!(write_verdict(&replies[0]), (false, Some(want)));
    }
    let replies = brave.policy_set(PolicyOverlay {
        disabled_tools: Some(vec!["a\0b".into()]),
        ..PolicyOverlay::default()
    });
    assert_eq!(
        write_verdict(&replies[0]),
        (
            false,
            Some("invalid policy write: a disabledTools entry contains a NUL byte".into())
        )
    );
    assert_eq!(
        SignerId::try_from("a\0b").unwrap_err(),
        "signer anchor must not contain a NUL byte"
    );
    assert_eq!(
        presence_reason(&brave.presence_confirm("unused")[0]).as_deref(),
        Some("no_request_outstanding"),
        "neither refusal minted a request"
    );
    assert!(PolicyStore::load().unwrap().is_none());
    assert!(audit_records(AuditKind::PolicyWrite).is_empty());
    assert!(audit_records(AuditKind::PairClient).is_empty());
}

/// The grant lane from the page: the request names this browser's credential and the change in the words the
/// tap approves (each touched field with its value, in the CLI's spellings), the answer signs the baseline
/// through the CLI's own seam, the written state is pushed, and the trail names the credential. A replayed
/// assertion then cannot sign a second grant, and the refused tap leaves the grant lane's own refused record
/// beside the presence one.
#[test]
fn a_policy_grant_from_the_page_signs_the_baseline_behind_this_browsers_tap() {
    let _dir = scratch_runtime_dir();
    mint_host_key();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);

    let replies = brave.policy_set(PolicyOverlay {
        page_eval_enabled: Some(true),
        confirm_grace_ms: Some(crate::policy::Ms::from(30_000u32)),
        disabled_tools: Some(vec!["page_upload".into(), "tab_close".into()]),
        ..PolicyOverlay::default()
    });
    assert_eq!(replies.len(), 1, "{replies:?}");
    let (challenge, allowed) = presence_request(&replies[0]);
    assert_eq!(allowed, vec![own.id_b64()]);
    assert_eq!(
        presence_action(&replies[0]),
        "set policy: pageEvalEnabled=on,confirmGraceMs=30000,disabledTools=[page_upload,tab_close]"
    );
    let assertion = own.assert(&challenge);
    let replies = brave.presence_assert(&own.id_b64(), Ok(assertion.clone()));
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_approved(&replies[0]);
    assert_eq!(write_verdict(&replies[1]), (true, None));
    assert!(is_policy_current(&replies[2]), "{replies:?}");
    let written = effective();
    assert!(written.page_eval_enabled);
    assert_eq!(written.confirm_grace_ms, crate::policy::Ms::from(30_000u32));
    assert_eq!(written.disabled_tools, vec!["page_upload", "tab_close"]);
    assert_eq!(revision(), 1);
    let writes = audit_records(AuditKind::PolicyWrite);
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0].surface, Some(Surface::Extension));
    assert_eq!(writes[0].outcome.as_deref(), Some("ok"));
    assert_eq!(
        writes[0].detail.as_deref(),
        Some(
            format!(
                "auth={}; touched=pageEvalEnabled,confirmGraceMs,disabledTools",
                own.audit_label()
            )
            .as_str()
        )
    );

    // The replay: the counter already moved past this assertion.
    let replies = brave.policy_set(PolicyOverlay {
        confirm_page_eval: Some(false),
        ..PolicyOverlay::default()
    });
    assert_eq!(
        presence_action(&replies[0]),
        "set policy: confirmPageEval=off"
    );
    let replies = brave.presence_assert(&own.id_b64(), Ok(assertion));
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("sign_count_not_increased")
    );
    assert_eq!(revision(), 1, "nothing was signed");
    assert!(effective().confirm_page_eval);
    let writes = audit_records(AuditKind::PolicyWrite);
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert_eq!(writes[1].outcome.as_deref(), Some("refused"));
    assert!(
        writes[1]
            .detail
            .as_deref()
            .is_some_and(|d| d.starts_with("presence: assertion refused: signCount")
                && d.ends_with("; touched=confirmPageEval")),
        "{:?}",
        writes[1].detail
    );
}

/// A browser with no enrolled credential signs a grant through the window, and the trail says so.
#[test]
fn a_bare_browser_signs_a_grant_by_window_and_the_trail_names_the_software_path() {
    let _dir = scratch_runtime_dir();
    mint_host_key();
    let mut chrome = Exchange::new(label("chrome"));
    enroll_tofu(&mut chrome, &Authenticator::new(0x22));
    let mut brave = Exchange::new(label("brave"));

    let replies = brave.policy_set(page_eval_grant());
    let (_, allowed) = presence_request(&replies[0]);
    assert!(allowed.is_empty(), "{allowed:?}");
    let nonce = presence_nonce(&replies[0]);
    let replies = brave.presence_confirm(&nonce);
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_approved(&replies[0]);
    assert_eq!(write_verdict(&replies[1]), (true, None));
    assert!(effective().page_eval_enabled);
    let writes = audit_records(AuditKind::PolicyWrite);
    assert_eq!(
        writes[0].detail.as_deref(),
        Some("auth=confirm_window; touched=pageEvalEnabled")
    );
}

/// A rollback from the page takes the lane the plan decides, as `policy rollback` does: a tightening rides the
/// free lane with no request, a relaxation opens a request naming the revision and the change, a no-op answers
/// at once, and an unknown or ambiguous revision is refused in the CLI's words.
#[test]
fn a_rollback_from_the_page_takes_the_lane_the_plan_decides() {
    let _dir = scratch_runtime_dir();
    mint_host_key();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    let reverify = PolicyValues {
        host_reverify_ms: crate::policy::Ms::from(1000u32),
        ..PolicyValues::default()
    };
    sign_baseline(reverify.clone(), vec![PolicyField::HostReverifyMs]);
    sign_baseline(
        PolicyValues {
            page_eval_enabled: true,
            ..reverify
        },
        vec![PolicyField::PageEvalEnabled],
    );
    assert_eq!(revision(), 2);

    // Revision 1 is tighter than the current state: free, no request, the written state pushed.
    let replies = brave.policy_rollback(1, None);
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_eq!(write_verdict(&replies[0]), (true, None));
    assert!(is_policy_current(&replies[1]), "{replies:?}");
    assert!(!effective().page_eval_enabled);
    assert_eq!(revision(), 2, "a tightening leaves the baseline alone");

    // Already there: nothing to do, nothing pushed.
    let replies = brave.policy_rollback(1, None);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(write_verdict(&replies[0]), (true, None));

    // Revision 2 relaxes the current state: a request, then a fresh signed revision.
    let replies = brave.policy_rollback(2, None);
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(
        presence_action(&replies[0]),
        "roll policy back to revision 2: pageEvalEnabled=on"
    );
    let (challenge, _) = presence_request(&replies[0]);
    let replies = brave.presence_assert(&own.id_b64(), Ok(own.assert(&challenge)));
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_approved(&replies[0]);
    assert_eq!(write_verdict(&replies[1]), (true, None));
    assert!(effective().page_eval_enabled);
    assert_eq!(
        revision(),
        3,
        "a relaxation is a fresh revision, never the old artifact"
    );

    // Revision 2 now names two superseded states (before and after its restriction); revision 9 none.
    for (revision, needle) in [(2, "ambiguous"), (9, "no history entry at revision 9")] {
        let replies = brave.policy_rollback(revision, None);
        assert_eq!(replies.len(), 1, "{replies:?}");
        let (ok, error) = write_verdict(&replies[0]);
        assert!(!ok);
        assert!(
            error.as_deref().is_some_and(|e| e.contains(needle)),
            "{error:?}"
        );
    }
    let acts: Vec<String> = audit_records(AuditKind::PresenceAssert)
        .iter()
        .filter_map(|r| r.detail.clone())
        .collect();
    assert!(
        acts.iter()
            .any(|d| d.starts_with("act=policy_rollback; auth=")),
        "{acts:?}"
    );
    // A surface names the row it listed, so a revision the ring holds twice is no obstacle to it: the later
    // row (revision 2 under its restriction) tightens for free, the earlier (unrestricted) relaxes behind a
    // request, and a record the ring no longer holds is refused rather than guessed.
    let report = crate::policy::gather_history_report().unwrap();
    let rows: Vec<HistoryEntryRef> = report
        .entries
        .iter()
        .filter(|e| e.held.as_ref().is_some_and(|held| held.revision == 2))
        .map(|e| HistoryEntryRef { id: e.id.clone() })
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let replies = brave.policy_rollback(2, Some(rows[1].clone()));
    assert_eq!(write_verdict(&replies[0]), (true, None));
    assert!(!effective().page_eval_enabled);
    let replies = brave.policy_rollback(2, Some(rows[0].clone()));
    assert_eq!(
        presence_action(&replies[0]),
        "roll policy back to revision 2: pageEvalEnabled=on"
    );
    let gone = HistoryEntryRef { id: "0".repeat(64) };
    let replies = brave.policy_rollback(2, Some(gone));
    assert_eq!(
        write_verdict(&replies[0]),
        (
            false,
            Some(
                "the policy history no longer holds that record; refresh it and choose again"
                    .into()
            )
        )
    );
}

/// The request's own validity and the prompt's bound are decided before the first store read: with the store
/// unreadable, a tool name the grammar refuses and a change past the bound get their own sentences, and only a
/// request that passes both reaches the store's refusal.
#[test]
fn validity_and_the_bound_are_decided_before_the_first_store_read() {
    let _dir = scratch_runtime_dir();
    let path = PolicyStore::path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"{").unwrap();
    let mut brave = Exchange::new(label("brave"));
    enroll_tofu(&mut brave, &Authenticator::new(0x11));
    let tools = |tools: Vec<String>| PolicyOverlay {
        disabled_tools: Some(tools),
        ..PolicyOverlay::default()
    };
    let cases = [
        (
            tools(vec!["bad,tool".into()]),
            "invalid policy write: a disabledTools entry contains a comma, which the comma-joined CLI \
             transport cannot round-trip"
                .to_string(),
        ),
        (
            tools((0..40).map(|i| format!("tool_{i:0>60}")).collect()),
            format!(
                "invalid policy write: the change summary exceeds the {MAX_ACTION_LEN}-byte bound a \
                 presence prompt can show"
            ),
        ),
    ];
    for (overlay, want) in cases {
        let replies = brave.policy_set(overlay);
        assert_eq!(write_verdict(&replies[0]), (false, Some(want)));
    }
    let replies = brave.policy_set(page_eval_grant());
    let (ok, error) = write_verdict(&replies[0]);
    assert!(!ok);
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.starts_with("the policy store is unreadable (")),
        "the control: a valid request reaches the store and is refused there: {error:?}"
    );
    assert!(audit_records(AuditKind::PolicyWrite).is_empty());
}

/// Pairing a trusted client from the page runs the CLI's own seam behind this browser's tap: the request names
/// the client and its anchor, the answer lands the entry, and the trail names the credential. A refused tap
/// leaves the pairing lane's own refused record and no entry.
#[test]
fn a_client_pairing_from_the_page_lands_behind_this_browsers_tap() {
    let _dir = scratch_runtime_dir();
    let mut brave = Exchange::new(label("brave"));
    let mut own = Authenticator::new(0x11);
    enroll_tofu(&mut brave, &own);
    let name = ClientName::try_from("codex").unwrap();
    let anchor = Anchor::Signer(SignerId::try_from("TEAMID").unwrap());

    let replies = brave.client_pair(name.clone(), anchor.clone());
    assert_eq!(replies.len(), 1, "{replies:?}");
    assert_eq!(
        presence_action(&replies[0]),
        "pair trusted client 'codex' on signer TEAMID"
    );
    let (challenge, allowed) = presence_request(&replies[0]);
    assert_eq!(allowed, vec![own.id_b64()]);
    let assertion = own.assert(&challenge);
    let replies = brave.presence_assert(&own.id_b64(), Ok(assertion.clone()));
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_approved(&replies[0]);
    assert_eq!(write_verdict(&replies[1]), (true, None));
    let trust = TrustState::current().unwrap();
    let Clients::Paired(clients) = trust.clients() else {
        panic!("the allowlist exists after a pairing: {trust:?}");
    };
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].name, name);
    assert_eq!(clients[0].anchor, anchor);
    let pairs = audit_records(AuditKind::PairClient);
    assert_eq!(pairs.len(), 1, "{pairs:?}");
    assert_eq!(pairs[0].surface, Some(Surface::Extension));
    assert_eq!(pairs[0].outcome.as_deref(), Some("ok"));
    assert_eq!(pairs[0].name.as_deref(), Some("codex"));
    assert_eq!(
        pairs[0].detail.as_deref(),
        Some("signer TEAMID; auth=webauthn")
    );

    // The replay cannot pair a second client.
    let other = ClientName::try_from("claude").unwrap();
    let replies = brave.client_pair(other, anchor);
    assert_eq!(replies.len(), 1, "{replies:?}");
    let replies = brave.presence_assert(&own.id_b64(), Ok(assertion));
    assert_eq!(
        presence_reason(&replies[0]).as_deref(),
        Some("sign_count_not_increased")
    );
    let trust = TrustState::current().unwrap();
    let Clients::Paired(clients) = trust.clients() else {
        panic!("{trust:?}");
    };
    assert_eq!(clients.len(), 1, "nothing was paired");
    let pairs = audit_records(AuditKind::PairClient);
    assert_eq!(pairs.len(), 2, "{pairs:?}");
    assert_eq!(pairs[1].outcome.as_deref(), Some("refused"));
    assert_eq!(pairs[1].name.as_deref(), Some("claude"));
    assert!(
        pairs[1]
            .detail
            .as_deref()
            .is_some_and(|d| d.starts_with("presence: assertion refused: signCount")),
        "{:?}",
        pairs[1].detail
    );
}
