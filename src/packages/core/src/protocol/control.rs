//! Host-handled control frames on the native-messaging channel: enclave
//! enrollment and presence, client-allowlist admin, kill switch and audit,
//! policy and shared language. [`classify_nm_frame`] routes each inbound
//! frame: these types are answered by the host itself, everything else is
//! forwarded to the MCP server.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Enrollment (ADR-0021) and per-action presence (ADR-0031) frames, answered by the native host itself: the
/// stdin->socket pump signs a challenge with the Secure Enclave key (raising the user-presence prompt) and
/// never forwards these frames to the MCP server. The host keeps no replay state and signs any valid challenge,
/// so freshness is the extension's job: a fresh single-use CSPRNG nonce per challenge, a proof accepted only for
/// the outstanding nonce and verified against its PINNED key, never the `pubkey` field (trustworthy only during
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
///                     revocation epoch (ADR-0025); not presence-gated (it only reduces capability). Answered
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Extension -> host: delete the enrollment key (ADR-0025). An empty
    /// struct variant so `deny_unknown_fields` applies (unit variants of
    /// internally tagged enums silently skip it).
    EnclaveRevoke {},
    /// Host -> extension: the enrollment key is gone (ack or proactive push).
    EnclaveRevoked {},
    /// Extension -> host: ask for one per-action user-presence approval
    /// (ADR-0031).
    PresenceChallenge {
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// Host-admin frames (ADR-0025/0030), answered by the native host itself exactly like [`EnclaveControl`]:
/// never forwarded to the MCP server, and dropped if the server leg tries to inject one. They give the
/// options UI the trusted-client allowlist, the global kill switch, and the audit trail, and arrive only from
/// the extension Chrome connected to this host (`allowed_origins`). List/revoke and `kill_engage` only reduce
/// capability; `kill_release` would RESTORE it, so the host refuses it (ADR-0032 decision 6) but keeps it
/// parsed, so a shipped extension gets an audited refusal, never a silent drop.
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: revoke one trusted client by name.
    ClientRevoke { name: String },
    /// Host -> extension: the revocation outcome.
    ClientRevokeResult {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: report the kill-switch state (ADR-0030).
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        killed: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: one extension-side decision for the audit trail
    /// (ADR-0030). Fire-and-forget; no reply frame.
    AuditEvent {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// Per-confirmation correlation id (ADR-0030); see the module docs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cid: Option<String>,
    },
}

/// The kill-switch state as the host reports it, before it is flattened onto
/// the pinned wire triple: exactly readable-with-verdict or
/// unreadable-with-error. The wire variant
/// ([`AdminControl::KillStatusResult`]) stays `{ ok, killed?, error? }` for
/// contract stability, but hand-assembling it at every reply site let the
/// mixtures the extension must never see - `ok: true` with no `killed`
/// claim, `ok: false` asserting one anyway - compile. Every producer builds
/// one of these instead and lets [`into_frame`](KillStatus::into_frame) emit
/// the only two flat shapes the contract means.
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

/// Why the host has no usable policy to report (ADR-0032 decision 4): the structured `reason` on a
/// `policy_current { ok: false }` frame, which decides whether the extension sends its one-shot `legacy_settings`.
///
/// ```text
/// absent                    -> a capable host that genuinely has no baseline yet: the extension sends legacy_settings
/// damaged, unreadable       -> the extension stays on its deny baseline
/// field missing (old host)  -> reads as "never send": fail closed on absence of the signal
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyUnavailableReason {
    /// No policy baseline exists on this host yet (the pre-cutover state).
    Absent,
    /// A baseline exists but is unparsable, or its overlay relaxes it: the
    /// store is present but its content is damaged or tampered.
    Damaged,
    /// The store could not be read (an I/O error distinct from absence).
    Unreadable,
}

impl PolicyUnavailableReason {
    /// The camelCase wire token, matching the extension's pinned enum. Single
    /// words, so camelCase is the lowercase spelling.
    pub fn wire(self) -> &'static str {
        match self {
            PolicyUnavailableReason::Absent => "absent",
            PolicyUnavailableReason::Damaged => "damaged",
            PolicyUnavailableReason::Unreadable => "unreadable",
        }
    }
}

/// The policy state the host reports, before it is flattened onto the pinned
/// `policy_current` wire triple (ADR-0032 decision 4) - the [`KillStatus`]
/// discipline applied to the policy push. The wire variant
/// ([`PolicyControl::PolicyCurrent`]) stays `{ ok, baseline?, sig?, overlay?,
/// reason?, error? }` for contract stability, but hand-assembling it let the
/// mixtures the extension must never see compile: `ok: false` carrying a
/// baseline, a `sig` with no baseline, an `ok: true` with an error. Every
/// producer builds one of these instead and lets
/// [`into_frame`](PolicyStatus::into_frame) emit the only two flat shapes the
/// contract means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyStatus {
    /// The store was readable: the EXACT signed baseline bytes (base64), the
    /// optional signature (`None` is the app-floor unsigned baseline), and the
    /// optional restriction overlay. A signature can never travel without the
    /// baseline it covers, because both live inside this one variant.
    Present {
        baseline_b64: String,
        sig_b64: Option<String>,
        overlay: Option<crate::policy::PolicyOverlay>,
    },
    /// No usable policy: `ok: false` with an error, a structured `reason` (`None` only when the frame
    /// answers a malformed request rather than reporting a store state), and NO baseline claim, so the
    /// extension keeps its deny baseline rather than trusting bytes nobody vouched for.
    Unavailable {
        reason: Option<PolicyUnavailableReason>,
        error: String,
    },
}

impl PolicyStatus {
    /// The pinned `policy_current` wire frame for this state: `baseline` is
    /// present exactly when the store was readable, `error` and the structured
    /// `reason` exactly when not, and a `sig` never appears without its
    /// `baseline`.
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
                reason: None,
                error: None,
            },
            PolicyStatus::Unavailable { reason, error } => PolicyControl::PolicyCurrent {
                ok: false,
                baseline: None,
                sig: None,
                overlay: None,
                reason: reason.map(|r| r.wire().to_string()),
                error: Some(error),
            },
        }
    }
}

/// Policy and language frames (ADR-0032), host-handled exactly like [`EnclaveControl`] and
/// [`AdminControl`]: never forwarded to the MCP server, dropped when the server leg tries to inject one.
/// The host pushes `policy_current` and `lang_current` unsolicited, at every connect and on every observed
/// change, which is why those two carry no request disposition: one arriving inbound is an injection.
///
/// ```text
/// policy_get         -> policy_current; sent only on a connection where the host has already pushed a
///                       policy frame (never speak first, decision 4): an old host would `Forward` it and
///                       the MCP server's strict `BridgeResp` parse would tear the browser leg down
/// legacy_settings    -> no reply; recorded host-side as a pending import, never applied (decision 8)
/// lang_get/lang_set  -> lang_current { value, seq }; `seq` suppresses the sender's own echo (decision 7)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "envelope-schema", derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyControl {
    /// Extension -> host: request the current policy. An empty struct
    /// variant so `deny_unknown_fields` applies (unit variants of internally
    /// tagged enums silently skip it).
    PolicyGet {},
    /// Host -> extension: the policy state (connect/change push, and the
    /// reply to `policy_get`).
    PolicyCurrent {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        baseline: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sig: Option<String>,
        /// The unsigned restriction overlay, strict-parsed at the frame
        /// boundary: an overlay carrying a field this catalogue does not own
        /// fails the whole frame parse, fail closed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        overlay: Option<crate::policy::PolicyOverlay>,
        /// Why no policy is available, when `ok: false` (ADR-0032 decision 4): the [`PolicyUnavailableReason`] wire
        /// token, absent on `ok: true`. OPTIONAL, so an old host omits it and the extension reads a missing field as
        /// "never send" (fail closed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Extension -> host: the snapshotted legacy settings bag for the
    /// first-run import (recorded pending, never applied).
    LegacySettings { bag: Value },
    /// Extension -> host: request the current shared language.
    LangGet {},
    /// Extension -> host: a user-gesture language change.
    LangSet { value: String },
    /// Host -> extension: the shared language and its echo-suppression
    /// sequence (the reply to both `lang_*` requests, and pushed on change).
    LangCurrent { value: String, seq: u64 },
}

/// Ties every control-frame variant to its serde `type` tag, once. Expands to
/// a tag-set constant and a `wire_tag` method whose match is EXHAUSTIVE over
/// the enum - no wildcard arm - so adding a variant fails to compile right
/// here until its tag joins the list, and the new tag then flows into
/// [`classify_nm_frame`] and [`host_control_type`] automatically (both consume
/// the constant). The `every_control_variant_tag_is_derived_and_recognized`
/// test asserts each listed tag is the tag serde actually emits, so the list
/// cannot drift from the `#[serde(tag = "type")]` attributes either.
macro_rules! control_wire_tags {
    ($Enum:ident, $TAGS:ident, { $($Variant:ident => $tag:literal),+ $(,)? }) => {
        /// The serde `type` tag of every variant, in declaration order.
        /// Emitted by `control_wire_tags!` from the same list as `wire_tag`.
        pub const $TAGS: &[&str] = &[$($tag),+];

        impl $Enum {
            /// The serde `type` tag this frame serializes under. The match is
            /// exhaustive on purpose: a new variant fails to compile until it
            /// is added to the `control_wire_tags!` list, which is what keeps
            /// the classifiers' tag set complete.
            pub fn wire_tag(&self) -> &'static str {
                match self {
                    $($Enum::$Variant { .. } => $tag,)+
                }
            }
        }
    };
}

control_wire_tags!(EnclaveControl, ENCLAVE_CONTROL_TAGS, {
    EnclaveChallenge => "enclave_challenge",
    EnclaveProof => "enclave_proof",
    EnclaveError => "enclave_error",
    EnclaveRevoke => "enclave_revoke",
    EnclaveRevoked => "enclave_revoked",
    PresenceChallenge => "presence_challenge",
    PresenceProof => "presence_proof",
    PresenceError => "presence_error",
});

control_wire_tags!(AdminControl, ADMIN_CONTROL_TAGS, {
    ClientList => "client_list",
    ClientListResult => "client_list_result",
    ClientRevoke => "client_revoke",
    ClientRevokeResult => "client_revoke_result",
    KillStatus => "kill_status",
    KillEngage => "kill_engage",
    KillRelease => "kill_release",
    KillStatusResult => "kill_status_result",
    AuditEvent => "audit_event",
});

control_wire_tags!(PolicyControl, POLICY_CONTROL_TAGS, {
    PolicyGet => "policy_get",
    PolicyCurrent => "policy_current",
    LegacySettings => "legacy_settings",
    LangGet => "lang_get",
    LangSet => "lang_set",
    LangCurrent => "lang_current",
});

/// The host-directed admin REQUEST kinds: the [`AdminControl`] frames the
/// extension sends and the host must answer. Carried by
/// [`FrameDisposition::MalformedAdmin`] so the malformed-reply builder matches
/// exhaustively - the reply frame type provably corresponds to the request
/// type, with no string catch-all for a new kind to ride into the wrong reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminKind {
    ClientList,
    ClientRevoke,
    KillStatus,
    KillEngage,
    KillRelease,
}

/// Ties every [`AdminKind`] variant to its wire tag AND enumerates the full
/// kind set, from one list - the `control_wire_tags!` idea, specialized to
/// this unit-variant request-kind enum, where the same list can also
/// CONSTRUCT the values. `wire_tag`'s match is exhaustive with no wildcard,
/// so a new variant fails to compile until it joins the list, and joining
/// the list is the same edit that grows [`AdminKind::ALL`] - the kind set
/// cannot lag the enum.
macro_rules! admin_request_kinds {
    ($($Variant:ident => $tag:literal),+ $(,)?) => {
        impl AdminKind {
            /// Every request kind, in declaration order. Emitted by
            /// `admin_request_kinds!` from the same list as `wire_tag`, so
            /// it is exhaustive by construction.
            pub const ALL: &'static [AdminKind] = &[$(AdminKind::$Variant),+];

            /// The wire `type` tag of the request this kind names (for logs
            /// and the error text in the `ok: false` reply). Exhaustive with
            /// no wildcard on purpose (see the macro docs), and `const` so
            /// the assertion below can tie every tag to the derived
            /// [`ADMIN_CONTROL_TAGS`] at compile time.
            pub const fn wire_tag(self) -> &'static str {
                match self {
                    $(AdminKind::$Variant => $tag,)+
                }
            }
        }
    };
}

admin_request_kinds!(
    ClientList => "client_list",
    ClientRevoke => "client_revoke",
    KillStatus => "kill_status",
    KillEngage => "kill_engage",
    KillRelease => "kill_release",
);

/// Compile-time: every [`AdminKind`] tag is one of the derived
/// [`ADMIN_CONTROL_TAGS`] (the `control_wire_tags!` list the serde
/// round-trip test pins), and no two kinds share a tag - so `wire_tag`'s
/// literals cannot drift from the tag machinery. The exact kind<->tag
/// pairing (which tag names which kind) is pinned at runtime by
/// `admin_kind_tags_match_their_classification`.
const _: () = {
    const fn str_eq(a: &str, b: &str) -> bool {
        let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        while let ([ha, rest_a @ ..], [hb, rest_b @ ..]) = (a, b) {
            if *ha != *hb {
                return false;
            }
            a = rest_a;
            b = rest_b;
        }
        true
    }
    const fn is_admin_control_tag(tag: &str) -> bool {
        let mut tags = ADMIN_CONTROL_TAGS;
        while let [head, rest @ ..] = tags {
            if str_eq(head, tag) {
                return true;
            }
            tags = rest;
        }
        false
    }
    let mut kinds: &[AdminKind] = AdminKind::ALL;
    while let [kind, rest @ ..] = kinds {
        assert!(
            is_admin_control_tag(kind.wire_tag()),
            "an AdminKind wire_tag is not a derived AdminControl tag"
        );
        let mut later = rest;
        while let [other, more @ ..] = later {
            assert!(
                !str_eq(kind.wire_tag(), other.wire_tag()),
                "two AdminKind variants share a wire tag"
            );
            later = more;
        }
        kinds = rest;
    }
};

/// The host-directed policy/language REQUEST kinds (ADR-0032): the
/// [`PolicyControl`] frames the extension sends and the host must answer with
/// a reply of a matching type. Carried by [`FrameDisposition::MalformedPolicy`]
/// so the malformed-reply builder matches exhaustively - the same discipline
/// as [`AdminKind`]. `LegacySettings` is deliberately NOT here: it is
/// fire-and-forget (recorded pending, never answered), so a malformed one is
/// dropped with no reply, exactly like a malformed `audit_event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    PolicyGet,
    LangGet,
    LangSet,
}

/// Ties every [`PolicyKind`] variant to its wire tag AND enumerates the full
/// kind set from one list - the [`admin_request_kinds!`] idea for the
/// policy/language request kinds. Exhaustive `wire_tag` with no wildcard, so a
/// new variant fails to compile until it joins the list.
macro_rules! policy_request_kinds {
    ($($Variant:ident => $tag:literal),+ $(,)?) => {
        impl PolicyKind {
            /// Every request kind, in declaration order.
            pub const ALL: &'static [PolicyKind] = &[$(PolicyKind::$Variant),+];

            /// The wire `type` tag of the request this kind names (for logs
            /// and the malformed reply). Exhaustive with no wildcard, and
            /// `const` so the assertion below can tie every tag to the derived
            /// [`POLICY_CONTROL_TAGS`] at compile time.
            pub const fn wire_tag(self) -> &'static str {
                match self {
                    $(PolicyKind::$Variant => $tag,)+
                }
            }
        }
    };
}

policy_request_kinds!(
    PolicyGet => "policy_get",
    LangGet => "lang_get",
    LangSet => "lang_set",
);

/// Compile-time: every [`PolicyKind`] tag is one of the derived
/// [`POLICY_CONTROL_TAGS`], and no two kinds share a tag - so `wire_tag`'s
/// literals cannot drift from the tag machinery (the [`AdminKind`] assertion,
/// specialized to the policy request kinds).
const _: () = {
    const fn str_eq(a: &str, b: &str) -> bool {
        let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        while let ([ha, rest_a @ ..], [hb, rest_b @ ..]) = (a, b) {
            if *ha != *hb {
                return false;
            }
            a = rest_a;
            b = rest_b;
        }
        true
    }
    const fn is_policy_control_tag(tag: &str) -> bool {
        let mut tags = POLICY_CONTROL_TAGS;
        while let [head, rest @ ..] = tags {
            if str_eq(head, tag) {
                return true;
            }
            tags = rest;
        }
        false
    }
    let mut kinds: &[PolicyKind] = PolicyKind::ALL;
    while let [kind, rest @ ..] = kinds {
        assert!(
            is_policy_control_tag(kind.wire_tag()),
            "a PolicyKind wire_tag is not a derived PolicyControl tag"
        );
        let mut later = rest;
        while let [other, more @ ..] = later {
            assert!(
                !str_eq(kind.wire_tag(), other.wire_tag()),
                "two PolicyKind variants share a wire tag"
            );
            later = more;
        }
        kinds = rest;
    }
};

/// The fields of one accepted `audit_event` frame (ADR-0030), traveling by
/// name from [`classify_nm_frame`] to the audit sink. `kind` is already the
/// typed, extension-owned [`crate::audit::AuditKind`]: classification maps the
/// wire string through [`crate::audit::extension_kind`], so a frame claiming a
/// host-owned kind (an admission, a kill) can never be represented as
/// recordable past this boundary.
#[derive(Debug)]
pub struct AuditEventFields {
    pub kind: crate::audit::AuditKind,
    pub outcome: Option<String>,
    pub tool: Option<String>,
    pub name: Option<String>,
    pub detail: Option<String>,
    pub cid: Option<String>,
}

/// How the native host's stdin->socket pump must treat one inbound frame.
#[derive(Debug)]
pub enum FrameDisposition {
    /// Not a control frame: forward to the MCP server unchanged.
    Forward,
    /// A well-formed `enclave_challenge`: answer it locally, do not forward.
    Challenge {
        nonce: String,
        context: Option<String>,
    },
    /// A well-formed `enclave_revoke` (ADR-0025): delete the enrollment key
    /// locally, bump the revocation epoch, reply `enclave_revoked`.
    RevokeHostKey,
    /// A well-formed `presence_challenge` (ADR-0031): sign the per-action
    /// presence statement locally (raising the user-presence prompt), do not
    /// forward.
    PresenceChallenge {
        nonce: String,
        context: Option<String>,
    },
    /// A well-formed `client_list` (ADR-0025): report the allowlist.
    ClientList,
    /// A well-formed `client_revoke` (ADR-0025): revoke the named client.
    ClientRevoke { name: String },
    /// A well-formed `kill_status` (ADR-0030): report the kill-switch state.
    KillStatus,
    /// A well-formed `kill_engage` (ADR-0030): engage the kill switch.
    KillEngage,
    /// A well-formed `kill_release` (ADR-0030): a request to release the kill
    /// switch, which the host REFUSES with an audited `kill_status_result`
    /// (ADR-0032 decision 6 retired the extension release surface; release is
    /// `chromium-bridge unkill` only).
    KillRelease,
    /// A well-formed `audit_event` (ADR-0030) carrying an extension-owned
    /// kind: record one extension-side decision in the audit trail.
    /// Fire-and-forget, no reply.
    AuditEvent(AuditEventFields),
    /// A well-formed `audit_event` whose `kind` is not extension-owned
    /// ([`crate::audit::extension_kind`]): the browser leg must not forge
    /// host-side events (admissions, kills) into the trail. Dropped at
    /// classification; the offending kind rides along for the forensic log.
    DropForeignAuditKind { kind: String },
    /// A control-frame `type` that is not addressed to the host (a stray
    /// proof/error/revoked/result, or a malformed host-directed frame with no
    /// defined error reply) - drop it, never forward it.
    Drop(&'static str),
    /// Carries the `enclave_challenge` type but does not parse as that frame:
    /// reply `enclave_error { reason: "invalid_challenge" }`, do not forward.
    Malformed,
    /// Carries the `presence_challenge` type but does not parse as that
    /// frame: reply `presence_error { reason: "invalid_challenge" }`, do not
    /// forward.
    MalformedPresence,
    /// Carries a `client_*`/`kill_*` request type but does not parse as that
    /// frame: reply the matching `*_result { ok: false }`, do not forward.
    MalformedAdmin(AdminKind),
    /// A well-formed `policy_get` (ADR-0032 decision 4): answer with
    /// `policy_current` from the host store.
    PolicyGet,
    /// A well-formed `legacy_settings` (ADR-0032 decision 8): the snapshotted
    /// legacy settings bag, recorded host-side as a pending import
    /// ([`crate::pending_import`], first-bag-wins) and never applied.
    /// Fire-and-forget, no reply. Routed off the forward path (an old host
    /// would have classified it `Forward`, tearing the browser leg down).
    LegacySettings { bag: Value },
    /// A well-formed `lang_get` (ADR-0032 decision 7): answer with
    /// `lang_current` from the language store.
    LangGet,
    /// A well-formed `lang_set` (ADR-0032 decision 7): apply the requested
    /// language (bumping the sequence only if it changed), answer
    /// `lang_current`.
    LangSet { value: String },
    /// Carries a `policy_get`/`lang_get`/`lang_set` type but does not parse as
    /// that frame: reply the matching frame with the unchanged state (a
    /// malformed `lang_set` replies `lang_current` with the value+seq that
    /// stand, decision 7), do not forward.
    MalformedPolicy(PolicyKind),
    /// Carries the `legacy_settings` type but does not parse as that frame (a
    /// missing or mistyped bag): dropped, never forwarded - fire-and-forget
    /// owes no reply - but audited as a `dropped_malformed` receipt
    /// (native_host), because the drop may be a version-skewed legitimate
    /// extension losing its ONE migration send. Carries only the frame's
    /// compact byte count: the content failed to parse and is never quoted
    /// into any log or trail.
    MalformedLegacySettings { bytes: usize },
}

/// Resolve `tag` to its `'static` copy in the derived host-control tag set
/// ([`ENCLAVE_CONTROL_TAGS`] + [`ADMIN_CONTROL_TAGS`] +
/// [`POLICY_CONTROL_TAGS`]), or `None` for anything that is not a
/// host-handled control tag. Both classifiers key on this one set, so a
/// variant added to any control enum (which the exhaustive `wire_tag`
/// matches force into the set) is recognized by both from the moment it
/// compiles.
fn host_control_tag(tag: &str) -> Option<&'static str> {
    ENCLAVE_CONTROL_TAGS
        .iter()
        .chain(ADMIN_CONTROL_TAGS)
        .chain(POLICY_CONTROL_TAGS)
        .copied()
        .find(|t| *t == tag)
}

/// Classify one native-messaging frame for the pump. Pure, so the
/// handled-vs-forwarded decision is unit-testable without a socket. Keyed on
/// the exact `type` tags of [`EnclaveControl`], [`AdminControl`], and
/// [`PolicyControl`] via the derived tag set: bridge requests carry `op` (no
/// `type`), and the socket handshake frames (`challenge`/`response`) never
/// traverse the pump, so nothing legitimate collides.
pub fn classify_nm_frame(frame: &Value) -> FrameDisposition {
    // Resolve against the derived tag set first: anything outside it forwards,
    // and anything inside it can never fall through to Forward below - the
    // final arm only ever sees control tags, and drops them.
    let Some(tag) = frame
        .get("type")
        .and_then(Value::as_str)
        .and_then(host_control_tag)
    else {
        return FrameDisposition::Forward;
    };
    match tag {
        "enclave_challenge" => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::EnclaveChallenge { nonce, context }) => {
                FrameDisposition::Challenge { nonce, context }
            }
            _ => FrameDisposition::Malformed,
        },
        "enclave_revoke" => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::EnclaveRevoke {}) => FrameDisposition::RevokeHostKey,
            // No error-reply contract exists for a malformed revoke (the
            // genuine extension sends the exact empty shape); dropping it
            // fails closed without inventing a misleading reason code.
            _ => FrameDisposition::Drop("malformed enclave_revoke"),
        },
        "presence_challenge" => match serde_json::from_value(frame.clone()) {
            Ok(EnclaveControl::PresenceChallenge { nonce, context }) => {
                FrameDisposition::PresenceChallenge { nonce, context }
            }
            _ => FrameDisposition::MalformedPresence,
        },
        "client_list" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::ClientList {}) => FrameDisposition::ClientList,
            _ => FrameDisposition::MalformedAdmin(AdminKind::ClientList),
        },
        "client_revoke" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::ClientRevoke { name }) => FrameDisposition::ClientRevoke { name },
            _ => FrameDisposition::MalformedAdmin(AdminKind::ClientRevoke),
        },
        "kill_status" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillStatus {}) => FrameDisposition::KillStatus,
            _ => FrameDisposition::MalformedAdmin(AdminKind::KillStatus),
        },
        "kill_engage" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillEngage {}) => FrameDisposition::KillEngage,
            _ => FrameDisposition::MalformedAdmin(AdminKind::KillEngage),
        },
        "kill_release" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::KillRelease {}) => FrameDisposition::KillRelease,
            _ => FrameDisposition::MalformedAdmin(AdminKind::KillRelease),
        },
        "audit_event" => match serde_json::from_value(frame.clone()) {
            Ok(AdminControl::AuditEvent {
                kind,
                outcome,
                tool,
                name,
                detail,
                cid,
            }) => match crate::audit::extension_kind(&kind) {
                Some(kind) => FrameDisposition::AuditEvent(AuditEventFields {
                    kind,
                    outcome,
                    tool,
                    name,
                    detail,
                    cid,
                }),
                // A host-owned kind from the browser leg is a forgery attempt
                // (or a confused extension); refuse it HERE so no disposition
                // ever carries a recordable host-side kind. The offending
                // value travels with the drop for the forensic log.
                None => FrameDisposition::DropForeignAuditKind { kind },
            },
            // Fire-and-forget has no reply contract; a malformed event is
            // dropped (and logged), never recorded as if it were valid.
            _ => FrameDisposition::Drop("malformed audit_event"),
        },
        "policy_get" => match serde_json::from_value(frame.clone()) {
            Ok(PolicyControl::PolicyGet {}) => FrameDisposition::PolicyGet,
            _ => FrameDisposition::MalformedPolicy(PolicyKind::PolicyGet),
        },
        "legacy_settings" => match serde_json::from_value(frame.clone()) {
            Ok(PolicyControl::LegacySettings { bag }) => FrameDisposition::LegacySettings { bag },
            // Fire-and-forget has no reply contract; a malformed bag is dropped,
            // never forwarded, and audited with only its size (the frame may be a
            // legitimate extension's one migration send, lost to version skew).
            _ => FrameDisposition::MalformedLegacySettings {
                bytes: serde_json::to_vec(frame).map(|b| b.len()).unwrap_or(0),
            },
        },
        "lang_get" => match serde_json::from_value(frame.clone()) {
            Ok(PolicyControl::LangGet {}) => FrameDisposition::LangGet,
            _ => FrameDisposition::MalformedPolicy(PolicyKind::LangGet),
        },
        "lang_set" => match serde_json::from_value(frame.clone()) {
            Ok(PolicyControl::LangSet { value }) => FrameDisposition::LangSet { value },
            _ => FrameDisposition::MalformedPolicy(PolicyKind::LangSet),
        },
        // Every remaining control tag names a frame the browser leg never
        // legitimately originates (proofs, errors, results, the revoked push,
        // and the host->extension `policy_current`/`lang_current` pushes) -
        // and any control variant added in the future lands here too until it
        // is given a handler arm above: dropped, never forwarded. Fail closed
        // by construction.
        other => FrameDisposition::Drop(other),
    }
}

/// The host-control `type` tag carried by `frame` (any [`EnclaveControl`], [`AdminControl`], or
/// [`PolicyControl`] tag), or `None`. The socket->stdout pump uses it to drop control frames arriving FROM
/// the MCP server: the ceremony and the admin exchange run strictly between the extension and the host, so
/// zero trust applies to our own server too. An attested-but-misbehaving server must not inject an
/// `enclave_error` that burns the extension's outstanding nonce, an `enclave_revoked` that provokes a false
/// fail-closed "compromised" mark, or a forged `client_list_result` / `policy_current` (ADR-0021/0025/0032).
pub fn host_control_type(frame: &Value) -> Option<&'static str> {
    frame
        .get("type")
        .and_then(Value::as_str)
        .and_then(host_control_tag)
}

#[cfg(test)]
mod tests;
