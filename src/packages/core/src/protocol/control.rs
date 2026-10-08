//! Host-handled control frames on the native-messaging channel: the host-key ceremony, client-allowlist
//! admin, kill switch and audit, policy and shared language, WebAuthn enrollment and presence. [`classify_nm_frame`] routes each inbound frame; [`FrameDisposition`] states what reaches the
//! MCP server.

use std::fmt;

use itertools::Itertools as _;
use serde::de::value::StrDeserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Host-key ceremony frames, answered by the native host itself: the stdin->socket pump signs a challenge
/// with the host key and never forwards these frames to the MCP server. The host keeps no replay state and
/// signs any valid challenge, so freshness is the extension's job: a fresh single-use CSPRNG nonce per
/// challenge, a proof accepted only for the outstanding nonce and verified against its PINNED key, never the
/// `pubkey` field (trustworthy only during the user-verified pairing, when the user compares fingerprints).
/// Every error is a denial the extension fails closed on; user presence is [`WebAuthnControl`]'s business.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnclaveControl {
    /// Extension -> host: sign this challenge. The bytes signed and both fields' bounds (NUL-free; the nonce
    /// non-empty and at most `MAX_NONCE_LEN`; the context at most `MAX_CONTEXT_LEN`, absent and `""` signing
    /// identically) are [`crate::enclave::challenge_message`]'s.
    EnclaveChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    /// Host -> extension: the proof. `sig` is base64 of the raw IEEE P1363 `r || s` ECDSA P-256/SHA-256
    /// signature ([`crate::enclave::SIG_LEN`] bytes); `key_id` is the key's lowercase-hex fingerprint
    /// ([`crate::enclave::EnclavePublicKey::fingerprint_hex`]) and `pubkey` the base64 of its X9.63 bytes.
    EnclaveProof {
        sig: String,
        key_id: String,
        pubkey: String,
    },
    /// Host -> extension: a denial; `reason` is one of [`crate::enclave::REASON_CODES`].
    EnclaveError { reason: String },
    /// Extension -> host: delete the host key. Not presence-gated, since it only reduces capability; what the
    /// deletion clears with it, and when `enclave_revoked` still answers, is `revoke_host_key`'s
    /// (`native_host.rs`).
    EnclaveRevoke {},
    /// Host -> extension: the host key is gone. The ack to `enclave_revoke`, and PUSHED unprompted when the
    /// host sees the key revoked out-of-band (`genkan revoke`, `pair --reset`), so a pinned extension flips
    /// to its fail-closed compromised state without waiting for a reverify; without a pin it is a no-op.
    EnclaveRevoked {},
}

/// Host-admin frames, answered by the native host itself exactly like [`EnclaveControl`]: never forwarded
/// to the MCP server, and dropped if the server leg tries to inject one. They arrive only from the extension
/// Chrome connected to this host (`allowed_origins`). A frame that only reduces capability (list, revoke,
/// `kill_engage`) is acted on at once; the two that would RESTORE or GRANT it (`kill_release`, `client_pair`)
/// are answered with a presence request instead, and `native_host/presence.rs` decides the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminControl {
    /// Extension -> host: report the trusted-client allowlist.
    ClientList {},
    /// Host -> extension: the allowlist. A load failure (the tamper case included) is `ok: false` with the
    /// error text; the UI shows it and guesses nothing.
    ClientListResult {
        ok: bool,
        /// Whether admission is enforced (an allowlist exists). `false` with
        /// `ok: true` is the unenrolled bootstrap posture.
        enrolled: bool,
        clients: Vec<crate::allowlist::ClientEntry>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: revoke one trusted client by name.
    ClientRevoke { name: String },
    /// Host -> extension: the revocation outcome.
    ClientRevokeResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: trust an MCP client under `name`, keyed on `anchor`; the page names an explicit anchor
    /// only, since a browser has no parent process to measure (`--this-parent` is the CLI's). Presence-gated:
    /// the host answers with a `presence_request`, and an approved tap adds `client_pair_result` to its
    /// `presence_result`; a refusal before any request exists answers `client_pair_result { ok: false, error }`
    /// alone.
    ClientPair {
        name: crate::allowlist::ClientName,
        anchor: crate::allowlist::Anchor,
    },
    /// Host -> extension: the pairing verdict. `error` travels exactly when not `ok`
    /// ([`WriteVerdict::into_frame`]).
    ClientPairResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: report the kill-switch state.
    KillStatus {},
    /// Extension -> host: engage the global kill switch.
    KillEngage {},
    /// Extension -> host: release the global kill switch. Presence-gated like `client_pair`: an approved tap
    /// adds `kill_status_result` to its `presence_result`, a refused one answers `presence_result` alone, and
    /// a failure before any request exists answers `kill_status_result { ok: false }` alone.
    KillRelease {},
    /// Host -> extension: the kill-switch state. The reply to `kill_status` and `kill_engage`, pushed
    /// unsolicited on observed transitions (`native_host.rs` push_kill_status says when), and part of an
    /// approved `kill_release` answer. `killed` is absent when `ok` is false (the state could not be read; the
    /// extension fails closed on unknown).
    KillStatusResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        killed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: one extension-side decision for the audit trail. Fire-and-forget; no reply frame. The
    /// host accepts only the extension-owned kinds (`crate::audit::extension_kind`) and stamps the surface
    /// itself, so the frame cannot forge host-side events like admissions or kills.
    AuditEvent {
        kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// Per-confirmation correlation id, joining a `confirm_shown` to its verdict ([`crate::audit::AuditRecord::cid`]).
        #[serde(skip_serializing_if = "Option::is_none")]
        cid: Option<String>,
    },
    /// Extension -> host: the health report plain `doctor` prints, and the host key's state.
    DoctorReport {},
    /// Host -> extension: the report. `report` travels exactly when `ok`, `error` exactly when not
    /// ([`DoctorOutcome::into_frame`]).
    DoctorReportResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        report: Option<HealthReport>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: read the newest records of the host's audit trail, the page `genkan audit --limit <n>`
    /// prints; an absent `limit` is the CLI's default.
    AuditRead {
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<AuditReadLimit>,
    },
    /// Host -> extension: the trail page. `entries`, `older`, and `path` travel exactly when `ok`, `error`
    /// exactly when not ([`AuditReport::into_frame`]).
    AuditReadResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        entries: Option<Vec<AuditTrailEntry>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        older: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: report every known browser's native-messaging registration.
    RegistrationStatus {},
    /// Extension -> host: re-register the detected browsers, or exactly the named ones (what `doctor --fix`
    /// and `--browser` do), then report. A repair that failed on any target answers `ok: false`, and the
    /// extension re-asks for the rows.
    RegistrationRepair {
        #[serde(skip_serializing_if = "Option::is_none")]
        browsers: Option<RepairBrowsers>,
    },
    /// Host -> extension: the registration rows (the reply to both registration frames). `browsers`
    /// travels exactly when `ok`, `error` exactly when not ([`RegistrationReport::into_frame`]).
    RegistrationStatusResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        browsers: Option<Vec<RegistrationRow>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

/// The health report as the options page shows it: each row's words are the ones `doctor` prints after its
/// label (`doctor.rs` spells them once for both), and `host_key` is the `key:` line of `enclave-status`. The
/// page localizes the labels and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HealthReport {
    pub version: String,
    /// `os/arch`, as the `platform:` row prints it.
    pub platform: String,
    pub lock_file: DoctorRow,
    pub mcp_server: DoctorRow,
    pub kill_switch: DoctorRow,
    pub policy_baseline: DoctorRow,
    pub host_key: String,
    /// The one-line verdict `doctor` ends with; `healthy` is its exit code 0.
    pub summary: String,
    pub healthy: bool,
}

/// One `doctor` row: the text after its label, then the indented lines under it (the lock file's endpoint
/// and pid, an active policy overlay), empty for most rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DoctorRow {
    pub value: String,
    pub details: Vec<String>,
}

impl DoctorRow {
    pub fn new(value: impl Into<String>) -> Self {
        DoctorRow {
            value: value.into(),
            details: Vec::new(),
        }
    }

    pub fn detail(mut self, line: impl Into<String>) -> Self {
        self.details.push(line.into());
        self
    }
}

/// The report as the host answers it, the [`KillStatus`] discipline applied: gathering never fails, so the
/// refused arm exists for a malformed frame alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorOutcome {
    Report(Box<HealthReport>),
    Unavailable { error: String },
}

impl DoctorOutcome {
    pub fn into_frame(self) -> AdminControl {
        match self {
            DoctorOutcome::Report(report) => AdminControl::DoctorReportResult {
                ok: true,
                report: Some(*report),
                error: None,
            },
            DoctorOutcome::Unavailable { error } => AdminControl::DoctorReportResult {
                ok: false,
                report: None,
                error: Some(error),
            },
        }
    }
}

/// One line of the host's audit trail as the options page shows it: the three parts of the line
/// `genkan audit` prints, spelled by `audit.rs` alone (the kind's wire name and the `key=value`
/// fields), with the timestamp left raw for the page to localize. An unparsable line keeps its position and
/// carries the CLI's stand-in text; so does a record whose timestamp lies past the JS-safe bound the page's
/// parser enforces, so one such line cannot sink the whole reply. The timestamp keeps both of the record's
/// bounds: non-negative, as its `u64` source is, and JS-safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "entry", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditTrailEntry {
    Record {
        ts_ms: crate::tools::args::JsUint,
        kind: String,
        fields: String,
    },
    Unrecognized {
        text: String,
    },
}

impl From<&crate::audit::AuditEntry> for AuditTrailEntry {
    fn from(entry: &crate::audit::AuditEntry) -> Self {
        let unrecognized = AuditTrailEntry::Unrecognized {
            text: crate::audit::UNRECOGNIZED_RECORD.into(),
        };
        match entry {
            crate::audit::AuditEntry::Record(rec) => {
                match crate::tools::args::JsUint::try_from(rec.ts_ms).ok() {
                    Some(ts_ms) => AuditTrailEntry::Record {
                        ts_ms,
                        kind: rec.kind_name(),
                        fields: rec.fields_display(),
                    },
                    None => unrecognized,
                }
            }
            crate::audit::AuditEntry::Unrecognized => unrecognized,
        }
    }
}

/// The trail page as the host reports it, the [`KillStatus`] discipline applied: the page travels exactly
/// when the trail was readable, an error exactly when not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditReport {
    Page {
        /// Newest first, as `audit.rs` reads them.
        entries: Vec<AuditTrailEntry>,
        /// Lines older than the page, left out of it.
        older: usize,
        /// The live file, for the same empty state the CLI prints.
        path: String,
    },
    Unavailable {
        error: String,
    },
}

impl From<crate::audit::AuditPage> for AuditReport {
    fn from(page: crate::audit::AuditPage) -> Self {
        AuditReport::Page {
            entries: page.entries.iter().map(AuditTrailEntry::from).collect(),
            older: page.older,
            path: page.path.to_string_lossy().into_owned(),
        }
    }
}

impl AuditReport {
    pub fn into_frame(self) -> AdminControl {
        match self {
            AuditReport::Page {
                entries,
                older,
                path,
            } => AdminControl::AuditReadResult {
                ok: true,
                entries: Some(entries),
                older: Some(older),
                path: Some(path),
                error: None,
            },
            AuditReport::Unavailable { error } => AdminControl::AuditReadResult {
                ok: false,
                entries: None,
                older: None,
                path: None,
                error: Some(error),
            },
        }
    }
}

/// The browsers a `registration_repair` names, parsed once at the frame boundary the way `--browser` is at
/// argv: known keys only, a repeat folded in first-seen order as `--browser chrome,brave,chrome` is, never
/// empty. Travels as the list of keys, and its schema carries the same key enum and the non-empty floor, so
/// the generated contract states them beside the host's parse (the writer schema types the extension's
/// frames; the parse here is what refuses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairBrowsers(Vec<crate::browsers::Browser>);

#[cfg(feature = "envelope-schema")]
impl schemars::JsonSchema for RepairBrowsers {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RepairBrowsers".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let keys: Vec<&str> = crate::browsers::Browser::ALL
            .iter()
            .map(|b| b.key())
            .collect();
        schemars::json_schema!({
            "type": "array",
            "items": { "type": "string", "enum": keys },
            "minItems": 1
        })
    }
}

impl RepairBrowsers {
    pub fn into_targets(self) -> crate::cli::FixTargets {
        crate::cli::FixTargets::Browsers(self.0)
    }
}

impl Serialize for RepairBrowsers {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|browser| browser.key()))
    }
}

impl<'de> Deserialize<'de> for RepairBrowsers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use crate::browsers::Browser;
        let keys = Vec::<String>::deserialize(deserializer)?;
        if keys.is_empty() {
            return Err(serde::de::Error::custom(
                "registration_repair names no browser; omit the list for the detected ones",
            ));
        }
        let browsers = keys
            .iter()
            .map(|key| {
                Browser::from_key(key).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "unknown browser key {key:?}; known: {}",
                        crate::registration::known_keys()
                    ))
                })
            })
            .collect::<Result<Vec<Browser>, D::Error>>()?;
        Ok(RepairBrowsers(browsers.into_iter().unique().collect()))
    }
}

/// The most records one `audit_read` may ask for. The page shows a list, not the whole trail; the whole
/// trail is `genkan audit --limit <n>`.
pub const MAX_AUDIT_READ_LIMIT: usize = 1000;

/// An `audit_read` limit, parsed once at the frame boundary into `1..=MAX_AUDIT_READ_LIMIT`: a zero or
/// over-cap limit fails the frame parse, so the handler never sees one. Travels as the plain integer, and
/// its schema carries the same bounds, so the generated contract states them beside the host's parse (the
/// writer schema types the extension's frames; the parse here is what refuses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AuditReadLimit(usize);

#[cfg(feature = "envelope-schema")]
impl schemars::JsonSchema for AuditReadLimit {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AuditReadLimit".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "integer", "minimum": 1, "maximum": MAX_AUDIT_READ_LIMIT })
    }
}

impl AuditReadLimit {
    pub fn get(self) -> usize {
        self.0
    }
}

impl<'de> Deserialize<'de> for AuditReadLimit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let limit = usize::deserialize(deserializer)?;
        if (1..=MAX_AUDIT_READ_LIMIT).contains(&limit) {
            Ok(AuditReadLimit(limit))
        } else {
            Err(serde::de::Error::custom(format!(
                "audit_read limit {limit} is outside 1..={MAX_AUDIT_READ_LIMIT}"
            )))
        }
    }
}

/// One browser's registration as the options page shows it: the browser key, whether this user has the
/// browser, the manifest state, and where the registration lives. The wire projection of
/// `doctor::ManifestStatus`, whose `RegState` serializes externally tagged (a shape the generated
/// validators do not model), so the state travels as the internally tagged [`RegistrationState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RegistrationRow {
    pub browser: String,
    pub detected: bool,
    pub state: RegistrationState,
    pub location: String,
}

/// A registration's diagnosed state on the wire, one variant per [`crate::registration::RegState`]
/// variant; `detail` is that state's reason text and travels exactly on the states that carry one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistrationState {
    Missing {},
    Ok {},
    Stale { detail: String },
    Foreign { detail: String },
    Unreadable { detail: String },
}

impl From<&crate::registration::RegState> for RegistrationState {
    fn from(state: &crate::registration::RegState) -> Self {
        use crate::registration::RegState;
        match state {
            RegState::Missing => RegistrationState::Missing {},
            RegState::Ok => RegistrationState::Ok {},
            RegState::Stale(detail) => RegistrationState::Stale {
                detail: detail.clone(),
            },
            RegState::Foreign(detail) => RegistrationState::Foreign {
                detail: detail.clone(),
            },
            RegState::Unreadable(detail) => RegistrationState::Unreadable {
                detail: detail.clone(),
            },
        }
    }
}

/// The registration rows as the host reports them, the [`KillStatus`] discipline applied: rows travel
/// exactly when the resolver could run, an error exactly when not, so an `ok: false` carrying rows or an
/// `ok: true` with an error is unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationReport {
    Rows(Vec<RegistrationRow>),
    /// The environment could not name the browser roots (no HOME), or the repair failed on a target: no
    /// rows travel, the extension shows the error and asks again.
    Unavailable {
        error: String,
    },
}

impl RegistrationReport {
    pub fn into_frame(self) -> AdminControl {
        match self {
            RegistrationReport::Rows(browsers) => AdminControl::RegistrationStatusResult {
                ok: true,
                browsers: Some(browsers),
                error: None,
            },
            RegistrationReport::Unavailable { error } => AdminControl::RegistrationStatusResult {
                ok: false,
                browsers: None,
                error: Some(error),
            },
        }
    }
}

/// The kill-switch state as the host reports it: exactly readable-with-verdict or unreadable-with-error.
/// Every producer builds one of these and lets [`into_frame`](KillStatus::into_frame) flatten it onto the
/// wire triple, so the mixtures the extension must never see (`ok: true` with no `killed` claim,
/// `ok: false` asserting one) are unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillStatus {
    /// The revocation record was readable; `killed` is the definite verdict.
    Read { killed: bool },
    /// The state could not be read (or the transition was refused): no
    /// `killed` claim travels at all, so the extension fails closed on
    /// unknown rather than trusting a boolean nobody could vouch for.
    Unreadable { error: String },
}

impl KillStatus {
    /// The pinned `kill_status_result` wire frame for this state: `killed`
    /// is present exactly when `ok`, `error` exactly when not.
    pub fn into_frame(self) -> AdminControl {
        match self {
            KillStatus::Read { killed } => AdminControl::KillStatusResult {
                ok: true,
                killed: Some(killed),
                error: None,
            },
            KillStatus::Unreadable { error } => AdminControl::KillStatusResult {
                ok: false,
                killed: None,
                error: Some(error),
            },
        }
    }
}

/// The policy state the host reports, the [`KillStatus`] discipline applied to the policy push: every
/// producer builds one of these and lets [`into_frame`](PolicyStatus::into_frame) flatten it onto the wire
/// frame, so an `ok: false` carrying a baseline, a `sig` with no baseline, or an `ok: true` with an error
/// is unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyStatus {
    /// The store was readable: the EXACT signed baseline bytes (base64), the
    /// optional signature (`None` is an unsigned baseline), and the
    /// optional restriction overlay. A signature can never travel without the
    /// baseline it covers, because both live inside this one variant.
    Present {
        baseline_b64: String,
        sig_b64: Option<String>,
        overlay: Option<crate::policy::PolicyOverlay>,
    },
    /// No usable policy: `ok: false` with an error and NO baseline claim, so the extension keeps its deny
    /// baseline rather than trusting bytes nobody vouched for.
    Unavailable { error: String },
}

impl PolicyStatus {
    /// The pinned `policy_current` wire frame for this state: `baseline` is present exactly when the store
    /// was readable, `error` exactly when not, and a `sig` never appears without its `baseline`.
    pub fn into_frame(self) -> PolicyControl {
        match self {
            PolicyStatus::Present {
                baseline_b64,
                sig_b64,
                overlay,
            } => PolicyControl::PolicyCurrent {
                ok: true,
                baseline: Some(baseline_b64),
                sig: sig_b64,
                overlay,
                error: None,
            },
            PolicyStatus::Unavailable { error } => PolicyControl::PolicyCurrent {
                ok: false,
                baseline: None,
                sig: None,
                overlay: None,
                error: Some(error),
            },
        }
    }
}

/// Policy and language frames, host-handled exactly like [`EnclaveControl`] and [`AdminControl`]: never
/// forwarded to the MCP server, dropped when the server leg tries to inject one. The host pushes
/// `policy_current` and `lang_current` unsolicited, at every connect and on every observed change, which is
/// why those two are not requests: one arriving inbound is an injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyControl {
    /// Extension -> host: request the current policy. Sent only on a connection where the host has already
    /// pushed a policy frame (never speak first): a host that does not know the frame would forward it, and
    /// the MCP server's strict `BridgeResp` parse would tear the browser leg down.
    PolicyGet {},
    /// Host -> extension: the policy state (connect/change push, and the
    /// reply to `policy_get`).
    PolicyCurrent {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        baseline: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
        /// The unsigned restriction overlay, strict-parsed at the frame
        /// boundary: an overlay carrying a field this catalogue does not own
        /// fails the whole frame parse, fail closed.
        #[serde(skip_serializing_if = "Option::is_none")]
        overlay: Option<crate::policy::PolicyOverlay>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: tighten the effective policy by this overlay (merged entry-wise over the stored one),
    /// the unsigned restriction lane (`crate::policy::restrict`). Answered with `policy_restrict_result`, then
    /// `policy_current` when the restriction applied (`native_host.rs` restrict_replies says why the push is
    /// not left to the watch).
    PolicyRestrict {
        overlay: crate::policy::PolicyOverlay,
    },
    /// Host -> extension: the restriction verdict. `error` travels exactly when not `ok`
    /// ([`WriteVerdict::into_frame`]).
    PolicyRestrictResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: mint a fresh signed baseline carrying this overlay over the current one, the GRANT
    /// lane behind a `presence_request`. An approved tap adds `policy_set_result` to its `presence_result`, and
    /// `policy_current` once the write committed; a refusal before any request exists (a keyless host, an
    /// invalid overlay) answers `policy_set_result { ok: false, error }` alone.
    PolicySet {
        overlay: crate::policy::PolicyOverlay,
    },
    /// Host -> extension: the grant verdict ([`WriteVerdict::into_frame`]).
    PolicySetResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: report the superseded-revision ring.
    PolicyHistory {},
    /// Host -> extension: the ring, oldest first. `entries` travels exactly when `ok`, `error` exactly when not
    /// ([`HistoryReport::into_frame`]).
    PolicyHistoryResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        entries: Option<Vec<PolicyHistoryRow>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: re-derive `revision`'s effective policy as a fresh write; `entry` names the listed
    /// record where `revision` alone is ambiguous (`policy/plan.rs` find_history_effective says when). A
    /// tightening rolls back free, a relaxation opens a `presence_request` like `policy_set`.
    PolicyRollback {
        revision: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        entry: Option<crate::policy::HistoryEntryRef>,
    },
    /// Host -> extension: the rollback verdict ([`WriteVerdict::into_frame`]).
    PolicyRollbackResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: request the current shared language.
    LangGet {},
    /// Extension -> host: a user-gesture language change.
    LangSet { value: String },
    /// Host -> extension: the shared language and its echo-suppression
    /// sequence (the reply to both `lang_*` requests, and pushed on change).
    LangCurrent { value: String, seq: u64 },
}

/// A write verdict as the host decides it, the [`PresenceOutcome`] discipline applied: one typed value per
/// producer, flattened by [`into_frame`](Self::into_frame) onto the result frame of the lane that produced it,
/// so an `ok: true` carrying an error or a refusal without one is unconstructible. `error` is the sentence the
/// CLI prints for the same refusal: one owner for every user-facing word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteVerdict {
    Applied,
    Refused { error: String },
}

/// The host-answered writes that share the [`WriteVerdict`] shape, each with its own result frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteLane {
    PolicyRestrict,
    PolicySet,
    PolicyRollback,
    ClientPair,
}

impl WriteVerdict {
    pub fn into_frame(self, lane: WriteLane) -> HostReply {
        let (ok, error) = match self {
            WriteVerdict::Applied => (true, None),
            WriteVerdict::Refused { error } => (false, Some(error)),
        };
        match lane {
            WriteLane::PolicyRestrict => PolicyControl::PolicyRestrictResult { ok, error }.into(),
            WriteLane::PolicySet => PolicyControl::PolicySetResult { ok, error }.into(),
            WriteLane::PolicyRollback => PolicyControl::PolicyRollbackResult { ok, error }.into(),
            WriteLane::ClientPair => AdminControl::ClientPairResult { ok, error }.into(),
        }
    }
}

/// One superseded policy record as the options page lists it: the wire projection of
/// [`crate::policy::PolicyHistoryEntryReport`]. A damaged record travels with `held` omitted (the report's
/// `null`; the readers refuse `null` at every optional field), and so does one whose timestamp is past the
/// JS-safe bound the readers enforce, its timestamp omitted too: one unreadable row, never a frame refused whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PolicyHistoryRow {
    /// The record's content identity, what a rollback names so the record restored is the one listed.
    pub id: String,
    pub signed: bool,
    pub overlay_active: bool,
    /// Unix seconds when the record stopped being the current store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_unix: Option<crate::tools::args::JsUint>,
    /// The record's revision with the policy it held, what a rollback to it re-derives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held: Option<crate::policy::HeldPolicy>,
}

impl From<&crate::policy::PolicyHistoryEntryReport> for PolicyHistoryRow {
    fn from(entry: &crate::policy::PolicyHistoryEntryReport) -> Self {
        let (superseded_unix, held) =
            match crate::tools::args::JsUint::try_from(entry.superseded_unix) {
                Ok(at) => (Some(at), entry.held.clone()),
                Err(_) => (None, None),
            };
        PolicyHistoryRow {
            id: entry.id.clone(),
            signed: entry.signed,
            overlay_active: entry.overlay_active,
            superseded_unix,
            held,
        }
    }
}

/// The history ring as the host reports it, the [`RegistrationReport`] discipline applied: rows travel
/// exactly when the ring could be read, an error exactly when not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryReport {
    Entries(Vec<PolicyHistoryRow>),
    Unavailable { error: String },
}

impl HistoryReport {
    pub fn into_frame(self) -> PolicyControl {
        match self {
            HistoryReport::Entries(entries) => PolicyControl::PolicyHistoryResult {
                ok: true,
                entries: Some(entries),
                error: None,
            },
            HistoryReport::Unavailable { error } => PolicyControl::PolicyHistoryResult {
                ok: false,
                entries: None,
                error: Some(error),
            },
        }
    }
}

/// WebAuthn enrollment and presence frames, host-handled exactly like the three enums above. The host is
/// the relying party ([`crate::webauthn`]): it mints the statement and verifies the assertion; the extension
/// is the WebAuthn client, running `navigator.credentials.create` / `.get` with RP ID = the extension id.
/// Byte fields travel base64url, unpadded, as `PublicKeyCredential.toJSON()` spells them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebAuthnControl {
    /// Extension -> host: start enrolling a credential for this browser. The host binds the connection's
    /// browser label into the statement, so the frame carries none; answered with `enroll_options`, or with
    /// `enroll_result { ok: false }` when refused.
    EnrollBegin {},
    /// Host -> extension: the `PublicKeyCredentialCreationOptions` the host decides.
    EnrollOptions {
        challenge: String,
        nonce: String,
        user_id: String,
        user_name: String,
        exclude_credential_ids: Vec<String>,
    },
    /// Extension -> host: the `navigator.credentials.create` response; attestation `none` and ES256 only
    /// ([`crate::webauthn::parse_registration`]).
    EnrollFinish {
        attestation_object: String,
        client_data_json: String,
    },
    /// Host -> extension: the enrollment verdict. `credential_id` travels exactly when `ok`, `reason`
    /// exactly when not ([`EnrollOutcome::into_frame`]).
    EnrollResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Extension -> host: a page operation whose confirmation the policy routes to the authenticator asks
    /// for its request. `action` is the tool name (`page_eval`, `page_upload`); `origin` is the page's web
    /// origin. The host answers with a `presence_request`, or `presence_result { ok: false }` when either
    /// field is not one it mints statements for.
    PresenceBegin { action: String, origin: String },
    /// Host -> extension: one capability-granting act awaits a tap. `challenge` is base64url(sha256(statement)),
    /// `action` the act the user approves, and `allowed_credential_ids` the allowCredentials list, scoped as
    /// [`crate::presence::request`] decides (this browser's credentials for an act, any enrolled one for an
    /// enrollment).
    PresenceRequest {
        challenge: String,
        nonce: String,
        action: String,
        allowed_credential_ids: Vec<String>,
    },
    /// Extension -> host: the `navigator.credentials.get` response.
    PresenceAssert {
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    /// Extension -> host: the confirmation window answered the outstanding request, named by its nonce. The
    /// software confirmation: the host accepts it only when no enrolled credential could have answered.
    PresenceConfirm { nonce: String },
    /// Host -> extension: the presence verdict. `reason` travels exactly when not `ok`
    /// ([`PresenceOutcome::into_frame`]): a [`crate::webauthn::Reason`] for a verdict the exchange decided,
    /// the host's malformed-frame sentence for a frame that never reached it.
    PresenceResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Extension -> host: forget every authenticator enrolled from this browser. The host binds its own label,
    /// so the frame carries none. Not presence-gated: forgetting only removes capability.
    BrowserRevoke {},
    /// Host -> extension: the forgetting verdict. `reason` travels exactly when not `ok`
    /// ([`RevokeOutcome::into_frame`]).
    BrowserRevokeResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// The enrollment verdict as the host decides it, the [`KillStatus`] discipline applied: one typed value
/// per producer, flattened onto the wire triple by [`into_frame`](Self::into_frame), so an `ok: true` with
/// no credential or an `ok: false` naming one is unconstructible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    Enrolled { credential_id: String },
    Refused { reason: String },
}

impl EnrollOutcome {
    pub fn into_frame(self) -> WebAuthnControl {
        match self {
            EnrollOutcome::Enrolled { credential_id } => WebAuthnControl::EnrollResult {
                ok: true,
                credential_id: Some(credential_id),
                reason: None,
            },
            EnrollOutcome::Refused { reason } => WebAuthnControl::EnrollResult {
                ok: false,
                credential_id: None,
                reason: Some(reason),
            },
        }
    }
}

/// The presence verdict as the host decides it; same discipline as [`EnrollOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceOutcome {
    Approved,
    Refused { reason: String },
}

impl PresenceOutcome {
    pub fn into_frame(self) -> WebAuthnControl {
        match self {
            PresenceOutcome::Approved => WebAuthnControl::PresenceResult {
                ok: true,
                reason: None,
            },
            PresenceOutcome::Refused { reason } => WebAuthnControl::PresenceResult {
                ok: false,
                reason: Some(reason),
            },
        }
    }
}

/// The browser-forgetting verdict as the host decides it; same discipline as [`EnrollOutcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOutcome {
    Forgotten,
    Refused { reason: String },
}

impl RevokeOutcome {
    pub fn into_frame(self) -> WebAuthnControl {
        match self {
            RevokeOutcome::Forgotten => WebAuthnControl::BrowserRevokeResult {
                ok: true,
                reason: None,
            },
            RevokeOutcome::Refused { reason } => WebAuthnControl::BrowserRevokeResult {
                ok: false,
                reason: Some(reason),
            },
        }
    }
}

/// The wire `type` tag of every host-handled control frame: the variants of [`EnclaveControl`],
/// [`AdminControl`], [`PolicyControl`], and [`WebAuthnControl`], spelled by serde. Both pumps key on this
/// one set ([`FrameDisposition`], [`host_control_type`]); the `host_control_tags_mirror_the_wire_enums`
/// test holds this list to those four enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HostControlTag {
    EnclaveChallenge,
    EnclaveProof,
    EnclaveError,
    EnclaveRevoke,
    EnclaveRevoked,
    ClientList,
    ClientListResult,
    ClientRevoke,
    ClientRevokeResult,
    ClientPair,
    ClientPairResult,
    KillStatus,
    KillEngage,
    KillRelease,
    KillStatusResult,
    AuditEvent,
    DoctorReport,
    DoctorReportResult,
    AuditRead,
    AuditReadResult,
    RegistrationStatus,
    RegistrationRepair,
    RegistrationStatusResult,
    PolicyGet,
    PolicyCurrent,
    PolicyRestrict,
    PolicyRestrictResult,
    PolicySet,
    PolicySetResult,
    PolicyHistory,
    PolicyHistoryResult,
    PolicyRollback,
    PolicyRollbackResult,
    LangGet,
    LangSet,
    LangCurrent,
    EnrollBegin,
    EnrollOptions,
    EnrollFinish,
    EnrollResult,
    PresenceBegin,
    PresenceRequest,
    PresenceAssert,
    PresenceConfirm,
    PresenceResult,
    BrowserRevoke,
    BrowserRevokeResult,
}

/// Which way a control frame travels. The browser->host set is the [`HostRequest`] roster: the
/// `host_request_variants_match_their_wire_enum_variants` test holds the two equal, and the envelope
/// schema emitter carries this table to the TS generator, which holds its writer plan to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    BrowserToHost,
    HostToBrowser,
}

impl HostControlTag {
    /// Which way a frame wearing this tag travels. Exhaustive on purpose: a new tag must say.
    pub fn direction(self) -> Direction {
        match self {
            HostControlTag::EnclaveChallenge
            | HostControlTag::EnclaveRevoke
            | HostControlTag::ClientList
            | HostControlTag::ClientRevoke
            | HostControlTag::ClientPair
            | HostControlTag::KillStatus
            | HostControlTag::KillEngage
            | HostControlTag::KillRelease
            | HostControlTag::AuditEvent
            | HostControlTag::DoctorReport
            | HostControlTag::AuditRead
            | HostControlTag::RegistrationStatus
            | HostControlTag::RegistrationRepair
            | HostControlTag::PolicyGet
            | HostControlTag::PolicyRestrict
            | HostControlTag::PolicySet
            | HostControlTag::PolicyHistory
            | HostControlTag::PolicyRollback
            | HostControlTag::LangGet
            | HostControlTag::LangSet
            | HostControlTag::EnrollBegin
            | HostControlTag::EnrollFinish
            | HostControlTag::PresenceBegin
            | HostControlTag::PresenceAssert
            | HostControlTag::PresenceConfirm
            | HostControlTag::BrowserRevoke => Direction::BrowserToHost,
            HostControlTag::EnclaveProof
            | HostControlTag::EnclaveError
            | HostControlTag::EnclaveRevoked
            | HostControlTag::ClientListResult
            | HostControlTag::ClientRevokeResult
            | HostControlTag::ClientPairResult
            | HostControlTag::KillStatusResult
            | HostControlTag::DoctorReportResult
            | HostControlTag::AuditReadResult
            | HostControlTag::RegistrationStatusResult
            | HostControlTag::PolicyCurrent
            | HostControlTag::PolicyRestrictResult
            | HostControlTag::PolicySetResult
            | HostControlTag::PolicyHistoryResult
            | HostControlTag::PolicyRollbackResult
            | HostControlTag::LangCurrent
            | HostControlTag::EnrollOptions
            | HostControlTag::EnrollResult
            | HostControlTag::PresenceRequest
            | HostControlTag::PresenceResult
            | HostControlTag::BrowserRevokeResult => Direction::HostToBrowser,
        }
    }

    /// What the host owes a browser frame wearing this tag that does not parse as its [`HostRequest`]: the
    /// matching result frame with `ok: false` (or an `invalid_challenge` error) where a reply contract
    /// exists, so the extension's pending request resolves instead of timing out. Exhaustive on purpose: a
    /// new tag does not compile until it says what it owes.
    pub fn malformed_reply(self) -> MalformedReply {
        match self {
            HostControlTag::EnclaveChallenge => MalformedReply::Send(Box::new(
                EnclaveControl::EnclaveError {
                    reason: "invalid_challenge".into(),
                }
                .into(),
            )),
            HostControlTag::ClientList => MalformedReply::Send(Box::new(
                AdminControl::ClientListResult {
                    ok: false,
                    enrolled: false,
                    clients: Vec::new(),
                    error: Some("malformed client_list frame".into()),
                }
                .into(),
            )),
            HostControlTag::ClientRevoke => MalformedReply::Send(Box::new(
                AdminControl::ClientRevokeResult {
                    ok: false,
                    error: Some("malformed client_revoke frame".into()),
                }
                .into(),
            )),
            HostControlTag::KillStatus
            | HostControlTag::KillEngage
            | HostControlTag::KillRelease => MalformedReply::Send(Box::new(
                KillStatus::Unreadable {
                    error: format!("malformed {self} frame"),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::PolicyGet => MalformedReply::Send(Box::new(
                PolicyStatus::Unavailable {
                    error: "malformed policy_get frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::RegistrationStatus | HostControlTag::RegistrationRepair => {
                MalformedReply::Send(Box::new(
                    RegistrationReport::Unavailable {
                        error: format!("malformed {self} frame"),
                    }
                    .into_frame()
                    .into(),
                ))
            }
            HostControlTag::DoctorReport => MalformedReply::Send(Box::new(
                DoctorOutcome::Unavailable {
                    error: "malformed doctor_report frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::AuditRead => MalformedReply::Send(Box::new(
                AuditReport::Unavailable {
                    error: "malformed audit_read frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::PolicyRestrict => self.malformed_write(WriteLane::PolicyRestrict),
            HostControlTag::PolicySet => self.malformed_write(WriteLane::PolicySet),
            HostControlTag::PolicyRollback => self.malformed_write(WriteLane::PolicyRollback),
            HostControlTag::ClientPair => self.malformed_write(WriteLane::ClientPair),
            HostControlTag::PolicyHistory => MalformedReply::Send(Box::new(
                HistoryReport::Unavailable {
                    error: "malformed policy_history frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::LangGet | HostControlTag::LangSet => MalformedReply::LangCurrent,
            HostControlTag::EnrollBegin | HostControlTag::EnrollFinish => {
                MalformedReply::Send(Box::new(
                    EnrollOutcome::Refused {
                        reason: format!("malformed {self} frame"),
                    }
                    .into_frame()
                    .into(),
                ))
            }
            HostControlTag::PresenceBegin => MalformedReply::Send(Box::new(
                PresenceOutcome::Refused {
                    reason: "malformed presence_begin frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::PresenceAssert => MalformedReply::Send(Box::new(
                PresenceOutcome::Refused {
                    reason: "malformed presence_assert frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::BrowserRevoke => MalformedReply::Send(Box::new(
                RevokeOutcome::Refused {
                    reason: "malformed browser_revoke frame".into(),
                }
                .into_frame()
                .into(),
            )),
            HostControlTag::PresenceConfirm => MalformedReply::Send(Box::new(
                PresenceOutcome::Refused {
                    reason: "malformed presence_confirm frame".into(),
                }
                .into_frame()
                .into(),
            )),
            // No error-reply contract: the genuine extension sends the exact empty revoke shape, and an audit
            // event is fire-and-forget. Dropping fails closed without inventing a misleading reason code.
            HostControlTag::EnclaveRevoke | HostControlTag::AuditEvent => MalformedReply::Drop,
            // Host->extension frames: the browser leg never legitimately originates one.
            HostControlTag::EnclaveProof
            | HostControlTag::EnclaveError
            | HostControlTag::EnclaveRevoked
            | HostControlTag::ClientListResult
            | HostControlTag::ClientRevokeResult
            | HostControlTag::ClientPairResult
            | HostControlTag::KillStatusResult
            | HostControlTag::DoctorReportResult
            | HostControlTag::AuditReadResult
            | HostControlTag::RegistrationStatusResult
            | HostControlTag::PolicyCurrent
            | HostControlTag::PolicyRestrictResult
            | HostControlTag::PolicySetResult
            | HostControlTag::PolicyHistoryResult
            | HostControlTag::PolicyRollbackResult
            | HostControlTag::LangCurrent
            | HostControlTag::EnrollOptions
            | HostControlTag::EnrollResult
            | HostControlTag::PresenceRequest
            | HostControlTag::PresenceResult
            | HostControlTag::BrowserRevokeResult => MalformedReply::Drop,
        }
    }
}

impl HostControlTag {
    fn malformed_write(self, lane: WriteLane) -> MalformedReply {
        MalformedReply::Send(Box::new(
            WriteVerdict::Refused {
                error: format!("malformed {self} frame"),
            }
            .into_frame(lane),
        ))
    }
}

impl fmt::Display for HostControlTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(Value::String(tag)) = serde_json::to_value(self) {
            f.write_str(&tag)
        } else {
            f.write_str("?")
        }
    }
}

/// The host's answer to a frame that wears a control tag but does not parse as its request.
#[derive(Debug)]
pub enum MalformedReply {
    /// No reply contract: dropped and logged, never forwarded.
    Drop,
    /// The matching error or `ok: false` result frame.
    Send(Box<HostReply>),
    /// `lang_current` with the UNCHANGED value and sequence (a malformed `lang_set` changes nothing), which
    /// only the host's language store can supply.
    LangCurrent,
}

/// A host->extension control frame of any of the four wire enums, serialized as that frame.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HostReply {
    Enclave(EnclaveControl),
    Admin(AdminControl),
    Policy(PolicyControl),
    WebAuthn(WebAuthnControl),
}

impl From<EnclaveControl> for HostReply {
    fn from(frame: EnclaveControl) -> Self {
        HostReply::Enclave(frame)
    }
}

impl From<AdminControl> for HostReply {
    fn from(frame: AdminControl) -> Self {
        HostReply::Admin(frame)
    }
}

impl From<PolicyControl> for HostReply {
    fn from(frame: PolicyControl) -> Self {
        HostReply::Policy(frame)
    }
}

impl From<WebAuthnControl> for HostReply {
    fn from(frame: WebAuthnControl) -> Self {
        HostReply::WebAuthn(frame)
    }
}

/// An audit kind the browser leg may record, parsed through [`crate::audit::extension_kind`]: a frame
/// claiming a host-owned kind (an admission, a kill) fails the `audit_event` parse and is dropped, so
/// nothing downstream can record it. The parse is the only constructor; travels as the kind's wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ExtensionAuditKind(crate::audit::AuditKind);

impl From<ExtensionAuditKind> for crate::audit::AuditKind {
    fn from(kind: ExtensionAuditKind) -> Self {
        kind.0
    }
}

impl<'de> Deserialize<'de> for ExtensionAuditKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let kind = String::deserialize(deserializer)?;
        crate::audit::extension_kind(&kind)
            .map(ExtensionAuditKind)
            .ok_or_else(|| {
                serde::de::Error::custom(format!("{kind:?} is not an extension-owned audit kind"))
            })
    }
}

/// The browser->host frames the host answers itself, parsed once by [`classify_nm_frame`]. Each variant is
/// the request shape of the same-named [`EnclaveControl`] / [`AdminControl`] / [`PolicyControl`] /
/// [`WebAuthnControl`] variant
/// (the extension's generated writer types come from those); the
/// `host_request_variants_match_their_wire_enum_variants` test holds them equal. Empty variants are
/// struct variants (`{}`) because `deny_unknown_fields` skips unit variants of an internally tagged enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostRequest {
    /// Sign the host-key challenge with the host key; answered at once, no prompt.
    EnclaveChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    /// Delete the host key; not presence-gated (it only reduces capability).
    EnclaveRevoke {},
    ClientList {},
    ClientRevoke {
        name: String,
    },
    /// Opens the presence exchange; the [`AdminControl`] roster states the replies. The name and anchor are
    /// validated by their own parsers, so a malformed one never reaches the exchange.
    ClientPair {
        name: crate::allowlist::ClientName,
        anchor: crate::allowlist::Anchor,
    },
    KillStatus {},
    KillEngage {},
    /// Opens the presence exchange; the [`AdminControl`] roster states the replies.
    KillRelease {},
    /// Fire-and-forget: recorded with the surface stamped host-side, no reply.
    AuditEvent {
        #[cfg_attr(feature = "envelope-schema", schemars(with = "String"))]
        kind: ExtensionAuditKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        outcome: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cid: Option<String>,
    },
    /// Read-only: the facts plain `doctor` gathers, nothing probed beyond its passive socket connect.
    DoctorReport {},
    /// Read-only; an absent `limit` reads as the CLI's default.
    AuditRead {
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<AuditReadLimit>,
    },
    RegistrationStatus {},
    /// Re-registers the detected browsers, or exactly the named ones, through the same path as `doctor
    /// --fix`; idempotent, and capability-neutral toward MCP clients (it points browsers at this binary and
    /// nothing else).
    RegistrationRepair {
        #[serde(skip_serializing_if = "Option::is_none")]
        browsers: Option<RepairBrowsers>,
    },
    PolicyGet {},
    /// The free restriction lane; the seam refuses a relaxation, so no presence gate stands here.
    PolicyRestrict {
        overlay: crate::policy::PolicyOverlay,
    },
    /// Opens the presence exchange for a signed write; the [`PolicyControl`] roster states the replies.
    PolicySet {
        overlay: crate::policy::PolicyOverlay,
    },
    PolicyHistory {},
    /// Free when the target only tightens, the presence exchange when it relaxes anything.
    PolicyRollback {
        revision: u64,
        entry: Option<crate::policy::HistoryEntryRef>,
    },
    LangGet {},
    LangSet {
        value: String,
    },
    EnrollBegin {},
    EnrollFinish {
        attestation_object: String,
        client_data_json: String,
    },
    PresenceBegin {
        action: String,
        origin: String,
    },
    PresenceAssert {
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    PresenceConfirm {
        nonce: String,
    },
    /// Forget this browser's enrollments; not presence-gated (it only reduces capability).
    BrowserRevoke {},
}

/// How the native host's stdin->socket pump must treat one inbound frame. Only `Forward` reaches the
/// MCP server: a frame wearing any [`HostControlTag`] is answered or dropped here, and one arriving FROM
/// the server is dropped as an injection ([`host_control_type`]).
#[derive(Debug)]
pub enum FrameDisposition {
    /// Not a control frame: forward to the MCP server unchanged. Bridge requests carry `op` (no `type`),
    /// and the socket handshake frames (`challenge`/`response`) never traverse the pump, so nothing
    /// legitimate collides with the control tags.
    Forward,
    /// A well-formed request: answer it locally, never forward it.
    Handle(HostRequest),
    /// A control tag whose frame does not parse as a [`HostRequest`]: a malformed request, or a
    /// host->extension frame the browser leg never legitimately originates. Never forwarded; answered per
    /// [`HostControlTag::malformed_reply`]. `error` is serde's reason, for the log.
    Malformed { tag: HostControlTag, error: String },
}

/// Classify one native-messaging frame for the pump. Pure, so the handled-vs-forwarded decision is
/// unit-testable without a socket.
pub fn classify_nm_frame(frame: &Value) -> FrameDisposition {
    let Some(tag) = host_control_type(frame) else {
        return FrameDisposition::Forward;
    };
    match HostRequest::deserialize(frame) {
        Ok(request) => FrameDisposition::Handle(request),
        Err(error) => FrameDisposition::Malformed {
            tag,
            error: error.to_string(),
        },
    }
}

/// The host-control `type` tag carried by `frame`, or `None`. The socket->stdout pump uses it to drop
/// control frames arriving FROM the MCP server: the ceremony and the admin exchange run strictly between
/// the extension and the host, so zero trust applies to our own server too. An attested-but-misbehaving
/// server must not inject an `enclave_error` that burns the extension's outstanding nonce, an
/// `enclave_revoked` that provokes a false fail-closed "compromised" mark, or a forged
/// `client_list_result` / `policy_current`.
pub fn host_control_type(frame: &Value) -> Option<HostControlTag> {
    // Only a STRING `type` can be a control tag. Deserializing the raw `Value` would also accept the
    // externally tagged spelling `{"type": {"kill_status": null}}`, turning relay traffic into a control frame.
    let tag = frame.get("type").and_then(Value::as_str)?;
    HostControlTag::deserialize(StrDeserializer::<serde::de::value::Error>::new(tag)).ok()
}

#[cfg(test)]
mod tests;
