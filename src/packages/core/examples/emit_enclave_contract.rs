//! Emit the enclave signing contract as one JSON document on stdout: the
//! domain-separation strings, the challenge field bounds, the key/signature
//! byte lengths, the `enclave_error` reason codes, and golden-vector
//! fixtures that pin the signed-message encodings across languages - the
//! challenge/presence vectors and the ADR-0032 policy-baseline vectors.
//! `scripts/gen-ops.ts` (run via `moon run gen`) consumes this to generate
//! `src/packages/shared/src/enclave.gen.ts` and `enclave-fixture.gen.ts`;
//! the emitted JSON itself is never checked in - the Rust sources are the
//! contract (ADR-0028).
//!
//! The fixture is signed with the PUBLIC test-vector key (`FIXTURE_KEY_BYTES`
//! in the enclave module; RFC 6979 via the p256 dev-dependency makes the
//! signatures deterministic, so regeneration is byte-identical and the
//! check-gen diff gate stays quiet). Because that scalar is public, the key
//! is deny-listed as an enrollment identity on both sides
//! (`ensure_not_fixture_key` host-side, `ENCLAVE_FIXTURE_KEY_ID` in the
//! extension); this emitter re-derives the fingerprint and fails on a
//! mismatch, so the deny-list constant cannot drift from the scalar.
//!
//! Every proof still exercises the production formatting code: the message
//! bytes come from `challenge_message`/`presence_message`, the signature
//! goes through `der_to_raw_signature` (the same DER -> P1363 conversion the
//! host applies to Security.framework output), and the public key and
//! fingerprint come from `EnclavePublicKey`. The extension's test suite
//! replays the fixture through its WebCrypto verifier, so either side
//! drifting from the shared byte contract breaks a gate.
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --example emit_enclave_contract

use chromium_bridge_core::enclave::{
    challenge_message, der_to_raw_signature, policy_message, presence_message, EnclavePublicKey,
    CHALLENGE_DOMAIN, FIXTURE_KEY_BYTES, FIXTURE_KEY_ID, MAX_CONTEXT_LEN, MAX_NONCE_LEN,
    POLICY_DOMAIN, PRESENCE_DOMAIN, PUBKEY_LEN, REASON_CODES, SIG_LEN,
};
use chromium_bridge_core::identity::PINNED_EXTENSION_ID;
use chromium_bridge_core::policy::{PolicyDoc, PolicyField};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Copy)]
enum Domain {
    Challenge,
    Presence,
}

impl Domain {
    fn as_str(self) -> &'static str {
        match self {
            Domain::Challenge => "challenge",
            Domain::Presence => "presence",
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_slice(&FIXTURE_KEY_BYTES)
        .map_err(|e| format!("fixture scalar is not a valid P-256 key: {e}"))?;
    let point = signing_key.verifying_key().to_sec1_point(false);
    let pubkey = EnclavePublicKey::from_x963(point.as_bytes().to_vec())?;
    // The deny-list constant is pinned to the scalar: generation refuses to
    // proceed if they ever name different keys.
    if pubkey.fingerprint_hex() != FIXTURE_KEY_ID {
        return Err("FIXTURE_KEY_ID does not match the key FIXTURE_KEY_BYTES derives".into());
    }

    // The vector matrix from the SSoT audit: both domains, None-vs-empty
    // context, realistic ceremony pairs (64-hex nonce, ext-shaped contexts),
    // a multi-byte UTF-8 pair (the bounds are BYTE lengths - this pins
    // Rust's str::len against JS TextEncoder), and both bounds at their
    // maximum. The extension ids in the contexts are FOREIGN on purpose (a
    // different id than ours), so no checked-in signature ever covers bytes
    // our real ceremony can construct; the check in the loop enforces it.
    let max_nonce = "n".repeat(MAX_NONCE_LEN);
    let max_context = "c".repeat(MAX_CONTEXT_LEN);
    let hex_nonce = "9f".repeat(32); // shape of generateNonce(): 64 lowercase hex chars
    let presence_context = format!(
        "ext:gijmanfkddbcbmkfmplnjcbmpnjmocpk:presence:eval:{}",
        "ab".repeat(32)
    );
    let vectors: &[(Domain, &str, Option<&str>)] = &[
        (Domain::Challenge, "abc", Some("ctx")),
        (Domain::Challenge, "abc", None),
        (Domain::Challenge, "abc", Some("")),
        (Domain::Presence, "abc", Some("ctx")),
        (
            Domain::Challenge,
            &hex_nonce,
            Some("ext:gijmanfkddbcbmkfmplnjcbmpnjmocpk:pair"),
        ),
        // The production presence context shape (confirm/presence.ts):
        // ext:<id>:presence:<kind>:<sha256hex>, kind in ConfirmPayload's
        // vocabulary ("eval" / "upload").
        (Domain::Presence, &hex_nonce, Some(&presence_context)),
        // Multi-byte UTF-8 in both fields (2-, 3-, and 4-byte sequences).
        (
            Domain::Challenge,
            "utf8-\u{e9}-nonce",
            Some("ctx-\u{4e2d}\u{6587}-\u{1f512}"),
        ),
        (Domain::Challenge, &max_nonce, Some(&max_context)),
    ];

    let mut vector_values: Vec<Value> = Vec::with_capacity(vectors.len());
    for &(domain, nonce, context) in vectors {
        if let Some(ctx) = context {
            if ctx.contains(PINNED_EXTENSION_ID) {
                return Err(
                    "fixture contexts must never carry OUR extension id: a signature \
                            over bytes the real ceremony can construct would weaken the \
                            fixture key's never-enrollable margin"
                        .into(),
                );
            }
        }
        let message = match domain {
            Domain::Challenge => challenge_message(nonce, context),
            Domain::Presence => presence_message(nonce, context),
        }?;
        let sig: Signature = signing_key.sign(&message);
        // Route the signature through the production DER -> P1363
        // converter, exactly as the host converts Security.framework
        // output, and cross-check it against p256's own raw form.
        let raw = der_to_raw_signature(sig.to_der().as_bytes())?;
        if raw.as_slice() != sig.to_bytes().as_slice() {
            return Err("der_to_raw_signature disagrees with p256's raw signature form".into());
        }
        vector_values.push(json!({
            "domain": domain.as_str(),
            "nonce": nonce,
            "context": context,
            "messageHex": hex(&message),
            "sigB64": chromium_bridge_core::enclave::base64_encode(&raw),
        }));
    }

    // The POLICY_DOMAIN vectors (ADR-0032 decision 3): the exact serialized
    // PolicyDoc bytes the signature covers, signed with the same
    // deterministic fixture key, so the extension's policy golden test can
    // replay a full baseline-verify (WebCrypto over `policy_message` bytes,
    // then strict parse of the same bytes). One deny-baseline revision-1
    // document with an empty touched set, and one relaxed document whose
    // touched set names its edits (the scoped-relaxation shape the ratchet
    // checks). Validated before signing: a malformed fixture document must
    // fail generation, never ship as a "verified" baseline.
    let baseline_doc = PolicyDoc {
        revision: 1,
        ..PolicyDoc::default()
    };
    let relaxed_doc = PolicyDoc {
        revision: 2,
        touched: vec![
            PolicyField::PageEvalEnabled,
            PolicyField::ConfirmGraceMs,
            PolicyField::DisabledTools,
        ],
        page_eval_enabled: true,
        confirm_grace_ms: 120_000,
        disabled_tools: vec!["page_upload".to_string()],
        ..PolicyDoc::default()
    };
    let mut policy_vectors: Vec<Value> = Vec::new();
    for doc in [&baseline_doc, &relaxed_doc] {
        doc.validate()
            .map_err(|e| format!("policy fixture document is malformed: {e}"))?;
        let doc_bytes = serde_json::to_vec(doc)?;
        let message = policy_message(&doc_bytes);
        let sig: Signature = signing_key.sign(&message);
        let raw = der_to_raw_signature(sig.to_der().as_bytes())?;
        if raw.as_slice() != sig.to_bytes().as_slice() {
            return Err("der_to_raw_signature disagrees with p256's raw signature form".into());
        }
        policy_vectors.push(json!({
            "docB64": chromium_bridge_core::enclave::base64_encode(&doc_bytes),
            "messageHex": hex(&message),
            "sigB64": chromium_bridge_core::enclave::base64_encode(&raw),
        }));
    }

    let out = json!({
        "challengeDomain": CHALLENGE_DOMAIN,
        "presenceDomain": PRESENCE_DOMAIN,
        "maxNonceLen": MAX_NONCE_LEN,
        "maxContextLen": MAX_CONTEXT_LEN,
        "pubkeyLen": PUBKEY_LEN,
        "sigLen": SIG_LEN,
        "reasonCodes": REASON_CODES,
        "fixture": {
            "pubkeyB64": pubkey.to_base64(),
            "keyIdHex": pubkey.fingerprint_hex(),
            "vectors": vector_values,
        },
        "policyFixture": {
            "policyDomain": POLICY_DOMAIN,
            "vectors": policy_vectors,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
