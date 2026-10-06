//! The enrollment store: which credential each browser enrolled, kept in the trust record so every
//! enforcement point reads enrollments from the same snapshot as the kill latch and the client allowlist.
//! The two writers decide under the runtime lock, against the record as it stands then, never against the
//! caller's snapshot.

use std::io;

use itertools::Itertools as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::audit::{self, AuditKind, AuditRecord, Surface};
use crate::ipc::{self, BrowserLabel};
use crate::presence::{PresenceAttestation, PresencePath};
use crate::trust::{CounterAdvance, Scope, Trust, TrustState};

use super::credential::{Credential, CredentialId};

/// One enrolled credential and the browser it belongs to. A presence act accepts only credentials under its
/// own browser's label ([`crate::presence::request::PresenceRequest::for_browser`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub label: BrowserLabel,
    pub credential: Credential,
}

/// The record spelling; the label is validated back into a [`BrowserLabel`] on read, so a record carrying a
/// label the handshake would refuse is refused here too.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentWire {
    label: String,
    credential: Credential,
}

impl Serialize for Enrollment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EnrollmentWire {
            label: self.label.as_str().to_string(),
            credential: self.credential.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Enrollment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EnrollmentWire::deserialize(deserializer)?;
        let label = BrowserLabel::parse(&wire.label).ok_or_else(|| {
            serde::de::Error::custom(format!("{:?} is not a browser label", wire.label))
        })?;
        Ok(Enrollment {
            label,
            credential: wire.credential,
        })
    }
}

/// What authorizes a credential to be recorded. Carried from `enroll_begin` to `enroll_finish`, so the write
/// knows which rule it is under instead of inferring it from the store.
#[derive(Debug)]
pub enum EnrollmentAuthority {
    /// The machine had no enrollment when the ceremony began; the write re-checks that under the lock, so two
    /// first-use ceremonies cannot both land.
    FirstUse,
    /// An enrolled authenticator approved this enrollment; the attestation is consumed by the write.
    Approved(PresenceAttestation),
}

/// Record a credential an accepted registration produced, replacing an earlier enrollment of the same
/// credential id. Returns the snapshot after the write.
pub fn record(
    label: &BrowserLabel,
    credential: Credential,
    authority: EnrollmentAuthority,
) -> io::Result<TrustState> {
    let enrollment = Enrollment {
        label: label.clone(),
        credential,
    };
    ipc::with_runtime_lock(|lock| {
        match authority {
            EnrollmentAuthority::FirstUse => {
                if !TrustState::current()?.enrollments().is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "another credential was enrolled first; this enrollment needs an approval",
                    ));
                }
            }
            EnrollmentAuthority::Approved(attestation) => drop(attestation),
        }
        Trust::mutate_locked(lock, Scope::Enrollments, |t| t.enroll(enrollment))
    })
}

/// What `revoke <browser>` did.
#[derive(Debug)]
pub struct BrowserRevoked {
    /// The credentials that went, in record order.
    pub forgotten: Vec<Enrollment>,
    /// The record after the write.
    pub trust: TrustState,
}

/// Why a browser was not forgotten. Either way nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum RevokeBrowserError {
    /// No enrollment carries the label; `enrolled` names the labels that are present, in record order, so
    /// the user sees which browser the record knows (a shared manifest's browsers all enroll as `default`).
    #[error("no browser is enrolled under that label")]
    NotEnrolled { enrolled: Vec<BrowserLabel> },
    #[error("trust record: {0}")]
    Io(#[from] io::Error),
}

/// Forget every enrollment under `label`. Not presence-gated: forgetting an authenticator only removes
/// capability, and the browser enrolls again from its options page (first use when it was the last one).
/// Audited HERE, log-after-decide, so no surface can forget an enrollment without a trail entry.
pub fn revoke_browser(
    label: &BrowserLabel,
    surface: Surface,
) -> Result<BrowserRevoked, RevokeBrowserError> {
    let revoked = ipc::with_runtime_lock(|lock| {
        let current = TrustState::current()?;
        if !current.enrollments().iter().any(|e| &e.label == label) {
            let enrolled = current
                .enrollments()
                .iter()
                .map(|e| e.label.clone())
                .unique()
                .collect();
            return Ok(Err(RevokeBrowserError::NotEnrolled { enrolled }));
        }
        let (trust, forgotten) =
            Trust::mutate_locked_with(lock, Scope::Enrollments, |t| t.revoke_browser(label))?;
        Ok(Ok(BrowserRevoked { forgotten, trust }))
    })??;
    audit_browsers_revoked(surface, &revoked.forgotten);
    Ok(revoked)
}

/// One [`AuditKind::RevokeBrowser`] record per forgotten credential: under the per-field bound however many a
/// browser held, and the shape an enrollment's own record has. Call it after the write, outside the lock.
pub(crate) fn audit_browsers_revoked(surface: Surface, forgotten: &[Enrollment]) {
    for e in forgotten {
        audit::record(
            AuditRecord::new(AuditKind::RevokeBrowser)
                .surface(surface)
                .name(e.label.as_str())
                .outcome("ok")
                .detail(&format!(
                    "credential={}",
                    PresencePath::WebAuthn(e.credential.id.clone()).audit_label()
                )),
        );
    }
}

/// Why the sign counter did not advance.
#[derive(Debug)]
pub enum CounterError {
    /// The credential is no longer enrolled.
    NotEnrolled,
    /// The stored counter already reached `stored`: another host accepted a later assertion between this
    /// one's verification and its write, or this assertion is the replay.
    Stale {
        stored: u32,
    },
    Io(io::Error),
}

/// Whether `received` moves the counter forward: a zero on both sides is an authenticator that does not
/// count; once either side counts, the value must advance on every assertion. The verifier applies the same
/// rule to its snapshot; this is the authoritative application, under the lock.
pub fn counter_advances(stored: u32, received: u32) -> bool {
    (stored == 0 && received == 0) || received > stored
}

/// Persist the sign counter an accepted assertion carried, so the next assertion from `id` must exceed it.
/// Decided against the stored counter under the lock, so a write never moves a counter backwards, and a
/// refusal writes nothing: a stale or unenrolled assertion moves neither the record's bytes nor its epoch.
pub fn advance_sign_count(id: &CredentialId, sign_count: u32) -> Result<(), CounterError> {
    let outcome = ipc::with_runtime_lock(|lock| {
        let verdict = TrustState::current()?.counter_advance(id, sign_count);
        if matches!(verdict, CounterAdvance::Advanced) {
            Trust::mutate_locked(lock, Scope::Enrollments, |t| {
                t.set_sign_count(id, sign_count)
            })?;
        }
        Ok(verdict)
    })
    .map_err(CounterError::Io)?;
    match outcome {
        CounterAdvance::Advanced => Ok(()),
        CounterAdvance::Stale { stored } => Err(CounterError::Stale { stored }),
        CounterAdvance::NotEnrolled => Err(CounterError::NotEnrolled),
    }
}
