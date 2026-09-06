//! Host-handled control frames on the native-messaging channel: enclave
//! enrollment and presence, client-allowlist admin, kill switch and audit,
//! policy and shared language. [`classify_nm_frame`] routes each inbound
//! frame: these types are answered by the host itself, everything else is
//! forwarded to the MCP server.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Control frames for the enrollment ceremony (ADR-0021), spoken over the
/// native-messaging channel between the extension and the native host. They
/// are HANDLED BY THE HOST ITSELF: the stdin->socket pump answers an
/// `enclave_challenge` locally (signing with the Secure Enclave key, which
/// raises the user-presence prompt) and never forwards these frames to the
/// MCP server. Everything without one of these `type` tags forwards as
/// before, so the protocol is fully backward compatible -
/// an extension that never sends a challenge sees no change.
///
/// Contract (the extension side consumes this):
/// - `enclave_challenge { nonce, context? }`: `nonce` is a non-empty NUL-free
///   string of at most 256 bytes; `context` an optional NUL-free string of at
///   most 4096 bytes. The host keeps no replay state and will sign any valid
///   challenge (raising the presence prompt), so freshness is NORMATIVE on
///   the extension side: the nonce MUST be freshly generated per challenge
///   from a cryptographic RNG (e.g. 32 bytes of `crypto.getRandomValues`,
///   encoded), MUST be single-use, and a proof MUST only be accepted for the
///   exact nonce the extension itself just issued. A proof over any other
///   nonce, or a second proof over a used nonce, MUST be rejected.
/// - `enclave_proof { sig, key_id, pubkey }`: `sig` is base64 of the raw
///   64-byte IEEE P1363 `r||s` ECDSA P-256/SHA-256 signature over
///   `UTF8("chromium-bridge-enclave-v1") || 0x00 || UTF8(nonce) || 0x00 ||
///   UTF8(context or "")`; `key_id` is the lowercase-hex SHA-256 of the
///   65-byte X9.63 public key; `pubkey` is base64 of those 65 bytes. The
///   extension MUST verify `sig` against its PINNED key, not against the
///   `pubkey` field (which is trustworthy only during the user-verified
///   enrollment ceremony itself).
/// - `enclave_error { reason }`: stable codes `unsupported_platform`,
///   `not_enrolled`, `invalid_challenge`, `key_invalid`, `keychain_error`,
///   `signing_failed`.
/// - `enclave_revoke {}` (extension -> host, ADR-0025): delete the enrollment
///   key from the keychain, remove the recorded policy, and bump the
///   revocation epoch. Deletion is not presence-gated (ADR-0021: it only ever
///   reduces capability). Answered with `enclave_revoked` on success (also
///   when no key existed -- the requested end state holds either way) or
///   `enclave_error { keychain_error }` on failure.
/// - `enclave_revoked {}` (host -> extension, ADR-0025): the enrollment key is
///   gone. Sent as the acknowledgement of `enclave_revoke`, and PUSHED
///   host-originated when the host observes the key was revoked out-of-band
///   (`chromium-bridge revoke`, `pair --reset`), so a pinned extension flips
///   to its fail-closed compromised state without waiting for an opt-in
///   reverify. The extension treats it as capability reduction only: with a
///   pin it marks the bridge compromised; without one it is a no-op.
///
/// The PER-ACTION presence frames (ADR-0031) ride the same channel and are
/// likewise host-handled, one round per confirmation of a crown-jewel tool
/// (`page_eval`, `page_upload`):
///
/// - `presence_challenge { nonce, context? }` (extension -> host): same field
///   bounds and freshness rules as `enclave_challenge` (fresh CSPRNG nonce,
///   single-use, proof accepted only for the extension's own outstanding
///   nonce). The signature covers `UTF8("chromium-bridge-presence-v1") ||
///   0x00 || UTF8(nonce) || 0x00 || UTF8(context or "")` - a DIFFERENT
///   domain from the enrollment proof, so neither statement type can ever be
///   replayed as the other. Signing raises the Secure Enclave user-presence
///   prompt; the Touch ID tap is the approval. The host refuses (without
///   prompting) while the kill switch is engaged (`bridge_killed`) and while
///   another presence round is in flight (`busy`).
/// - `presence_proof { sig, key_id, pubkey }` (host -> extension): same
///   encoding as `enclave_proof`, under the presence domain. The extension
///   MUST verify against its PINNED key.
/// - `presence_error { reason }` (host -> extension): the enclave reason
///   codes plus `bridge_killed` and `busy`. Every error is a denial; the
///   extension must fail the confirmation closed, never fall back to a
///   softer surface (the no-downgrade rule).
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

/// Host-admin control frames (ADR-0025/0030), spoken over the native-messaging
/// channel and handled by the native host itself, exactly like
/// [`EnclaveControl`]: never forwarded to the MCP server, and dropped if the
/// server leg tries to inject one. They give the extension's options UI a
/// managed path to the trusted-client allowlist, the global kill switch, and
/// the audit trail:
///
/// - `client_list {}` -> `client_list_result { ok, enrolled, clients, error? }`
///   Read-only. `enrolled` mirrors the CLI's unenrolled/enrolled distinction;
///   `clients` reuses the on-disk entry shape (`{name, anchor: {kind, value},
///   added_unix}`). A load failure (including the ADR-0025 tamper case) comes
///   back as `ok: false` with the error text -- the UI shows it, nothing is
///   guessed.
/// - `client_revoke { name }` -> `client_revoke_result { ok, error? }`
///   Removes one trusted client and bumps the revocation epoch in the same
///   critical section, so a live broker drops that client's connections.
/// - `kill_status {}` / `kill_engage {}` / `kill_release {}` ->
///   `kill_status_result { ok, killed?, error? }` (ADR-0030). The result frame
///   is also PUSHED host-originated, unsolicited: at startup and whenever the
///   host's revocation watch sees the kill marker move, so the extension's
///   SW-only mirror tracks CLI-driven transitions without polling. `ok: false`
///   (state unreadable) carries no `killed` claim; the extension treats it as
///   unknown and fails closed.
/// - `audit_event { kind, outcome?, tool?, name?, detail?, cid? }` (ADR-0030,
///   fire-and-forget, no reply): the extension reports one of ITS OWN
///   user-facing decisions (confirmations, enrollment approvals) for the
///   host's on-disk audit trail. `cid` is the per-confirmation correlation id
///   the extension stamps on a `confirm_shown` and its later verdict so the
///   audit panel joins them exactly. The host accepts only the extension-owned
///   kinds ([`crate::audit::extension_kind`]) and stamps the surface itself,
///   so the frame cannot forge host-side events like admissions or kills.
///
/// Trust: these frames arrive only from the extension Chrome connected to
/// this host (`allowed_origins`). The list/revoke pair adds no capability
/// beyond the CLI's (capability reduction); `kill_engage` is also reduction.
/// `kill_release` would RESTORE capability, so the host refuses it (ADR-0032
/// decision 6 retired the extension release surface); the frame stays parsed
/// so a shipped extension gets an audited refusal, never a silent drop.
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

/// Why the host has no usable policy to report (ADR-0032 decision 4, D-P4-2):
/// the structured cause the `policy_current { ok: false }` frame carries in its
/// optional `reason` field. The Phase-4 extension gates its one-shot
/// `legacy_settings` send on `reason == absent` (it imports only when a
/// capable host genuinely has no baseline yet); `damaged` (an unparsable
/// baseline or a relaxing overlay) and `unreadable` (a store I/O error) are
/// fail-closed states the extension keeps its deny baseline on, never an
/// import trigger. An old host omits the field entirely, which the extension
/// reads as "never send" - fail closed on absence of the signal.
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
    /// No usable policy: the store is absent, unreadable, or malformed. `ok:
    /// false` with an error, a structured `reason` (D-P4-2; `None` only when
    /// the frame answers a malformed request rather than reporting a store
    /// state), and NO baseline claim, so the extension fails closed on its
    /// deny baseline rather than trusting bytes nobody vouched for (decision
    /// 4/5).
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

/// Policy and language control frames (ADR-0032), spoken over the
/// native-messaging channel and host-handled exactly like [`EnclaveControl`]
/// and [`AdminControl`]: never forwarded to the MCP server, and dropped when
/// the server leg tries to inject one. The host answers the four
/// extension-originated frames and pushes `policy_current` / `lang_current`
/// unsolicited (which is why those two carry no request disposition: a result
/// frame arriving inbound is an injection and is dropped).
///
/// - `policy_get {}` (extension -> host): on-demand refresh of the policy
///   state. The extension sends it only on a connection where the host has
///   already pushed a policy frame (the never-speak-first rule, ADR-0032
///   decision 4: an old host would classify it as `Forward` and the MCP
///   server's strict `BridgeResp` parse would tear the browser leg down).
/// - `policy_current { ok, baseline?, sig?, overlay?, reason?, error? }`
///   (host -> extension): the policy state, pushed at every connect and on
///   every observed change, and the reply to `policy_get`. `baseline` is the
///   exact signed document bytes (base64), `sig` its signature, `overlay`
///   the unsigned restriction overlay; `ok: false` carries `error` plus the
///   optional structured `reason` instead (see
///   [`PolicyUnavailableReason`]; fail closed).
/// - `legacy_settings { bag }` (extension -> host): the snapshotted legacy
///   settings bag, recorded host-side as a pending import, never applied
///   (ADR-0032 decision 8).
/// - `lang_get {}` / `lang_set { value }` (extension -> host) and
///   `lang_current { value, seq }` (host -> extension): the shared
///   `uiLanguage` preference, echo-suppressed by `seq` (decision 7).
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
        /// Why no policy is available, when `ok: false` (ADR-0032 D-P4-2): the
        /// camelCase [`PolicyUnavailableReason`] token (`absent`/`damaged`/
        /// `unreadable`). ADDITIVE and OPTIONAL - an old host omits it and the
        /// extension reads a missing field as "never send" (fail closed).
        /// Absent on `ok: true`.
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
            // Fire-and-forget has no reply contract (Phase 4 owns the pending
            // store); a malformed bag is dropped, never forwarded - and
            // audited (the frame may be a legitimate extension's one
            // migration send, lost to version skew), carrying only its size.
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

/// The host-control `type` tag carried by `frame` - any [`EnclaveControl`],
/// [`AdminControl`], or [`PolicyControl`] tag - or `None` for everything
/// else. The native host's socket->stdout pump uses this to drop control
/// frames arriving FROM the MCP server: the ceremony and the admin exchange
/// run strictly between the extension and the host itself, so the server leg
/// has no legitimate reason to ever carry one. Zero trust applies to our own
/// server too - an attested-but-misbehaving server must not be able to
/// inject an `enclave_error` that burns the extension's outstanding nonce,
/// an `enclave_revoked` that provokes a false fail-closed "compromised"
/// mark, a forged `client_list_result` (ADR-0021/0025), or a forged
/// `policy_current` (ADR-0032).
pub fn host_control_type(frame: &Value) -> Option<&'static str> {
    frame
        .get("type")
        .and_then(Value::as_str)
        .and_then(host_control_tag)
}

#[cfg(test)]
mod tests;
