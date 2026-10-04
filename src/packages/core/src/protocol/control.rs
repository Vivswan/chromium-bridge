//! Host-handled control frames on the native-messaging channel: enclave enrollment and presence,
//! client-allowlist admin, kill switch and audit, policy and shared language. [`classify_nm_frame`]
//! routes each inbound frame; [`FrameDisposition`] states what reaches the MCP server.

use std::fmt;

use serde::de::value::StrDeserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Enrollment and per-action presence frames, answered by the native host itself: the stdin->socket pump
/// signs a challenge with the Secure Enclave key (raising the user-presence prompt) and never forwards these
/// frames to the MCP server. The host keeps no replay state and signs any valid challenge, so freshness is
/// the extension's job: a fresh single-use CSPRNG nonce per challenge, a proof accepted only for the
/// outstanding nonce and verified against its PINNED key, never the `pubkey` field (trustworthy only during
/// the user-verified enrollment ceremony).
///
/// ```text
/// nonce            -> non-empty, NUL-free, at most 256 BYTES (MAX_NONCE_LEN)
/// context          -> optional, NUL-free, at most 4096 BYTES (MAX_CONTEXT_LEN); absent and "" sign identically
/// sig              -> base64 of the raw 64-byte IEEE P1363 r||s ECDSA P-256/SHA-256 signature over
///                     UTF8(domain) || 0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")
/// domain           -> chromium-bridge-enclave-v1 (enrollment) or chromium-bridge-presence-v1 (presence),
///                     so neither statement type can ever be replayed as the other
/// key_id / pubkey  -> lowercase-hex SHA-256 of the 65-byte X9.63 public key / base64 of those bytes
/// error reason     -> REASON_CODES; presence adds bridge_killed and busy (the host refuses, without prompting,
///                     while the kill switch is engaged or unreadable, or another presence round is in flight)
/// enclave_revoke   -> deletes the enrollment key, then best-effort clears the recorded policy baseline and bumps the
///                     revocation epoch; not presence-gated (it only reduces capability). Answered
///                     enclave_revoked once the key is gone (even when none existed, and even when the baseline clear
///                     or epoch bump failed: those are only logged); enclave_error carries the key deletion's
///                     reason code (keychain_error, also for an unavailable runtime lock; unsupported_platform off macOS)
/// enclave_revoked  -> also PUSHED unprompted when the host sees the key revoked out-of-band (chromium-bridge
///                     revoke, pair --reset), so a pinned extension flips to its fail-closed compromised state
///                     without waiting for a reverify; without a pin it is a no-op
/// ```
///
/// Every error is a denial: the extension fails the confirmation closed, never falls back to a softer surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnclaveControl {
    EnclaveChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    EnclaveProof {
        sig: String,
        key_id: String,
        pubkey: String,
    },
    EnclaveError {
        reason: String,
    },
    /// Extension -> host: delete the enrollment key.
    EnclaveRevoke {},
    /// Host -> extension: the enrollment key is gone (ack or proactive push).
    EnclaveRevoked {},
    /// Extension -> host: ask for one per-action user-presence approval.
    PresenceChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    /// Host -> extension: the signed presence approval.
    PresenceProof {
        sig: String,
        key_id: String,
        pubkey: String,
    },
    /// Host -> extension: the presence round failed; the confirmation is
    /// denied.
    PresenceError {
        reason: String,
    },
}

/// Host-admin frames, answered by the native host itself exactly like [`EnclaveControl`]: never forwarded
/// to the MCP server, and dropped if the server leg tries to inject one. They give the options UI the
/// trusted-client allowlist, the global kill switch, and the audit trail, and arrive only from the extension
/// Chrome connected to this host (`allowed_origins`). List/revoke and `kill_engage` only reduce capability;
/// `kill_release` would RESTORE it, so the host refuses it but keeps it parsed, so a shipped extension gets
/// an audited refusal, never a silent drop.
///
/// ```text
/// client_list         -> client_list_result { ok, enrolled, clients, error? }; a load failure (including the
///                        tamper case) is ok: false with the error text, the UI shows it and guesses nothing
/// client_revoke       -> client_revoke_result { ok, error? }; the revocation-epoch bump shares the critical
///                        section, so a live broker drops that client's connections
/// kill_status/engage  -> kill_status_result { ok, killed?, error? }; also PUSHED unsolicited when the host's
///                        revocation watch sees the kill marker move, and at startup only when killed or unreadable
///                        (a healthy host waits for the extension's kill_status query), so the SW-only mirror
///                        never polls; ok: false carries no killed claim (fail closed on unknown)
/// audit_event         -> no reply; the host accepts only the extension-owned kinds (crate::audit::extension_kind)
///                        and stamps the surface itself, so the frame cannot forge host-side events like
///                        admissions or kills; cid joins a confirm_shown to its verdict
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminControl {
    /// Extension -> host: report the trusted-client allowlist.
    ClientList {},
    /// Host -> extension: the allowlist (or the load error, fail closed).
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
    /// Extension -> host: report the kill-switch state.
    KillStatus {},
    /// Extension -> host: engage the global kill switch.
    KillEngage {},
    /// Extension -> host: release the global kill switch.
    KillRelease {},
    /// Host -> extension: the kill-switch state. The reply to all three kill
    /// frames, and pushed unsolicited on observed transitions. `killed` is
    /// absent when `ok` is false (the state could not be read; the extension
    /// fails closed on unknown).
    KillStatusResult {
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        killed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: one extension-side decision for the audit trail.
    /// Fire-and-forget; no reply frame.
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
        /// Per-confirmation correlation id; see the module docs.
        #[serde(skip_serializing_if = "Option::is_none")]
        cid: Option<String>,
    },
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
///
/// ```text
/// policy_get         -> policy_current; the extension sends it only on a connection where the host has
///                       already pushed a policy frame (never speak first): a host that does not know the
///                       frame would forward it, and the MCP server's strict `BridgeResp` parse would tear
///                       the browser leg down
/// lang_get/lang_set  -> lang_current { value, seq }; `seq` suppresses the sender's own echo
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyControl {
    /// Extension -> host: request the current policy.
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
    /// Extension -> host: request the current shared language.
    LangGet {},
    /// Extension -> host: a user-gesture language change.
    LangSet { value: String },
    /// Host -> extension: the shared language and its echo-suppression
    /// sequence (the reply to both `lang_*` requests, and pushed on change).
    LangCurrent { value: String, seq: u64 },
}

/// The wire `type` tag of every host-handled control frame: the variants of [`EnclaveControl`],
/// [`AdminControl`], and [`PolicyControl`], spelled by serde. Both pumps key on this one set
/// ([`FrameDisposition`], [`host_control_type`]); the `host_control_tags_mirror_the_wire_enums` test
/// holds this list to those three enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HostControlTag {
    EnclaveChallenge,
    EnclaveProof,
    EnclaveError,
    EnclaveRevoke,
    EnclaveRevoked,
    PresenceChallenge,
    PresenceProof,
    PresenceError,
    ClientList,
    ClientListResult,
    ClientRevoke,
    ClientRevokeResult,
    KillStatus,
    KillEngage,
    KillRelease,
    KillStatusResult,
    AuditEvent,
    PolicyGet,
    PolicyCurrent,
    LangGet,
    LangSet,
    LangCurrent,
}

/// Which way a control frame travels. The browser->host set is the [`HostRequest`] roster; the
/// `host_request_variants_match_their_wire_enum_variants` test holds the three equal: this table, the
/// HostRequest variants, and the writer types the extension generates.
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
            | HostControlTag::PresenceChallenge
            | HostControlTag::ClientList
            | HostControlTag::ClientRevoke
            | HostControlTag::KillStatus
            | HostControlTag::KillEngage
            | HostControlTag::KillRelease
            | HostControlTag::AuditEvent
            | HostControlTag::PolicyGet
            | HostControlTag::LangGet
            | HostControlTag::LangSet => Direction::BrowserToHost,
            HostControlTag::EnclaveProof
            | HostControlTag::EnclaveError
            | HostControlTag::EnclaveRevoked
            | HostControlTag::PresenceProof
            | HostControlTag::PresenceError
            | HostControlTag::ClientListResult
            | HostControlTag::ClientRevokeResult
            | HostControlTag::KillStatusResult
            | HostControlTag::PolicyCurrent
            | HostControlTag::LangCurrent => Direction::HostToBrowser,
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
            HostControlTag::PresenceChallenge => MalformedReply::Send(Box::new(
                EnclaveControl::PresenceError {
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
            HostControlTag::LangGet | HostControlTag::LangSet => MalformedReply::LangCurrent,
            // No error-reply contract: the genuine extension sends the exact empty revoke shape, and an audit
            // event is fire-and-forget. Dropping fails closed without inventing a misleading reason code.
            HostControlTag::EnclaveRevoke | HostControlTag::AuditEvent => MalformedReply::Drop,
            // Host->extension frames: the browser leg never legitimately originates one.
            HostControlTag::EnclaveProof
            | HostControlTag::EnclaveError
            | HostControlTag::EnclaveRevoked
            | HostControlTag::PresenceProof
            | HostControlTag::PresenceError
            | HostControlTag::ClientListResult
            | HostControlTag::ClientRevokeResult
            | HostControlTag::KillStatusResult
            | HostControlTag::PolicyCurrent
            | HostControlTag::LangCurrent => MalformedReply::Drop,
        }
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

/// A host->extension control frame of any of the three wire enums, serialized as that frame.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum HostReply {
    Enclave(EnclaveControl),
    Admin(AdminControl),
    Policy(PolicyControl),
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
/// the request shape of the same-named [`EnclaveControl`] / [`AdminControl`] / [`PolicyControl`] variant
/// (the extension's generated writer types come from those); the
/// `host_request_variants_match_their_wire_enum_variants` test holds them equal. Empty variants are
/// struct variants (`{}`) because `deny_unknown_fields` skips unit variants of an internally tagged enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostRequest {
    /// Sign the enrollment challenge. Signing blocks the pump until the user answers the presence prompt,
    /// accepted because a challenge only arrives during the user-present enrollment ceremony.
    EnclaveChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    /// Delete the enrollment key; not presence-gated (it only reduces capability).
    EnclaveRevoke {},
    /// Sign one per-action presence statement, on its own thread so a tap never head-of-line blocks the pump.
    PresenceChallenge {
        nonce: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
    ClientList {},
    ClientRevoke {
        name: String,
    },
    KillStatus {},
    KillEngage {},
    /// Refused with an audited `kill_status_result { ok: false }`: release is `chromium-bridge unkill`
    /// only, but a shipped extension gets a reply, never a silent drop.
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
    PolicyGet {},
    LangGet {},
    LangSet {
        value: String,
    },
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
