//! The byte-input fuzz targets as plain functions over `&[u8]`: each `fuzz_targets/<name>.rs` binary
//! wraps the same-named function in `fuzz_target!`, and [`crate::seeds`]' test runs every generated
//! seed through it in-process. Each function is the no-crash contract of one parser on a trust
//! boundary plus the oracle its module doc states; a panic here is a finding, under libFuzzer and
//! under `cargo test` alike.

use std::io::Cursor;

use chromium_bridge_core::enclave::{base64_decode, base64_encode, der_to_raw_signature};
use chromium_bridge_core::identity::NATIVE_HOST_ID;
use chromium_bridge_core::policy::{
    fold, relaxes, restricts_or_equal, PolicyDoc, PolicyHistory, PolicyOverlay, PolicyStore,
    PolicyValues,
};
use chromium_bridge_core::protocol::control::{
    classify_nm_frame, FrameDisposition, HostControlTag,
};
use chromium_bridge_core::protocol::{
    bridge_read, bridge_write, mcp_read, mcp_write, nm_read_frame, nm_write_frame, AttachRequest,
    BridgeReq, Handshake, JsonRpc, ParsedResp, BRIDGE_MAX_LINE, MCP_MAX_LINE, NM_MAX_OUTGOING,
};
use chromium_bridge_core::registration::{fuzz_api, manifest_ownership, Ownership};
use chromium_bridge_core::runtime_record::RuntimeRecord as _;
use serde_json::Value;

/// One byte-input target: its binary and seed-directory name, and the body the binary runs.
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub name: &'static str,
    pub run: fn(&[u8]),
}

pub const NM_FRAME: Target = Target {
    name: "nm_frame",
    run: nm_frame,
};
pub const MCP_JSONRPC: Target = Target {
    name: "mcp_jsonrpc",
    run: mcp_jsonrpc,
};
pub const BRIDGE_ENVELOPE: Target = Target {
    name: "bridge_envelope",
    run: bridge_envelope,
};
pub const HANDSHAKE: Target = Target {
    name: "handshake",
    run: handshake,
};
pub const ATTACH: Target = Target {
    name: "attach",
    run: attach,
};
pub const CLASSIFY_FRAME: Target = Target {
    name: "classify_frame",
    run: classify_frame,
};
pub const ENCLAVE_DER: Target = Target {
    name: "enclave_der",
    run: enclave_der,
};
pub const REGISTRATION_MANIFEST: Target = Target {
    name: "registration_manifest",
    run: registration_manifest,
};
pub const POLICY_DOC: Target = Target {
    name: "policy_doc",
    run: policy_doc,
};

/// The Chrome Native-Messaging frame decoder (4-byte LE length prefix + JSON) on the extension<->host
/// boundary. Oracle: a decoded frame re-encodes to a frame that decodes to the same value, and the
/// encoder refuses only payloads over the outgoing cap.
pub fn nm_frame(data: &[u8]) {
    let Ok(Some(value)) = nm_read_frame(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    match nm_write_frame(&mut bytes, &value) {
        Ok(()) => {
            let again = nm_read_frame(&mut Cursor::new(bytes.as_slice()))
                .expect("the encoded frame must decode")
                .expect("the encoded frame is one message");
            assert_eq!(
                again, value,
                "native-messaging decode -> encode -> decode must be identity"
            );
        }
        Err(_) => {
            let json = serde_json::to_vec(&value).expect("a decoded Value serializes");
            assert!(
                json.len() > NM_MAX_OUTGOING,
                "nm_write_frame refused a frame under the outgoing cap"
            );
        }
    }
}

/// The MCP JSON-RPC NDJSON reader on the harness<->server stdio boundary, the most likely target of a
/// prompt-injection-hijacked client. Oracle: a decoded message re-encodes to a line that decodes to the
/// same value, so a relay forwarding a message cannot change what the broker reads.
pub fn mcp_jsonrpc(data: &[u8]) {
    let Ok(Some(first)) = mcp_read(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    mcp_write(&mut bytes, &first).expect("a decoded JsonRpc must encode");
    // MCP_MAX_LINE counts the newline the writer adds (see its doc), so exactly-cap input re-encodes over it.
    if bytes.len() > MCP_MAX_LINE {
        return;
    }
    let second: JsonRpc = mcp_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded line must decode")
        .expect("the encoded line is one message");
    assert_eq!(
        serde_json::to_value(&first).expect("JsonRpc serializes"),
        serde_json::to_value(&second).expect("JsonRpc serializes"),
        "JsonRpc decode -> encode -> decode must be identity"
    );
}

/// The internal bridge NDJSON envelope reader (server<->native host): arbitrary bytes decoded as a JSON
/// value and as the two typed frames must never panic. `ParsedResp` is the session's production read
/// path, whose `TryFrom` refuses contradictory responses; `BridgeReq` is only written by Rust (the
/// extension parses it inbound), but its flattened command pins the shape the extension must accept.
pub fn bridge_envelope(data: &[u8]) {
    let _: std::io::Result<Option<Value>> = bridge_read(&mut Cursor::new(data));
    let _: std::io::Result<Option<BridgeReq>> = bridge_read(&mut Cursor::new(data));
    let _: std::io::Result<Option<ParsedResp>> = bridge_read(&mut Cursor::new(data));
}

/// The authenticated-handshake frame decoder (Challenge / Response), run before the peer is trusted.
/// Oracle: a decoded frame re-encodes to a frame that decodes to the same value, so the MAC and label
/// a verifier reads are the ones the peer wrote.
pub fn handshake(data: &[u8]) {
    let Ok(Some(first)) = bridge_read::<_, Handshake>(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    bridge_write(&mut bytes, &first).expect("a decoded Handshake must encode");
    // BRIDGE_MAX_LINE counts the newline the writer adds (see its doc), so exactly-cap input re-encodes over it.
    if bytes.len() > BRIDGE_MAX_LINE {
        return;
    }
    let second: Handshake = bridge_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded frame must decode")
        .expect("the encoded frame is one line");
    assert_eq!(
        serde_json::to_value(&first).expect("Handshake serializes"),
        serde_json::to_value(&second).expect("Handshake serializes"),
        "Handshake decode -> encode -> decode must be identity"
    );
}

/// The post-handshake role-declaration frame decoder (`AttachRequest`): a malformed or hostile frame
/// must fail closed, never panic the broker. Oracle: decode -> encode -> decode is identity.
pub fn attach(data: &[u8]) {
    let Ok(Some(first)) = bridge_read::<_, AttachRequest>(&mut Cursor::new(data)) else {
        return;
    };
    let mut bytes = Vec::new();
    bridge_write(&mut bytes, &first).expect("a decoded AttachRequest must encode");
    // BRIDGE_MAX_LINE counts the newline the writer adds (see its doc), so exactly-cap input re-encodes over it.
    if bytes.len() > BRIDGE_MAX_LINE {
        return;
    }
    let second: AttachRequest = bridge_read(&mut Cursor::new(bytes.as_slice()))
        .expect("the encoded frame must decode")
        .expect("the encoded frame is one line");
    assert_eq!(
        serde_json::to_value(&first).expect("AttachRequest serializes"),
        serde_json::to_value(&second).expect("AttachRequest serializes"),
        "AttachRequest decode -> encode -> decode must be identity"
    );
}

/// The tag `type_field` spells, by serde's own reading of the string, or `None`.
fn spelled_tag(type_field: Option<&str>) -> Option<HostControlTag> {
    serde_json::from_value(Value::String(type_field?.to_string())).ok()
}

/// The native-messaging control-frame classifier: the router that decides whether an extension-relayed
/// frame is forwarded, answered, or dropped. The oracles are independent of the classifier's own reading
/// of the frame: a forwarded frame carries no string `type` that spells a control tag, a handled or
/// malformed frame's `type` is exactly the tag it was read as, and a parsed request re-classifies to
/// itself from its own serialization.
pub fn classify_frame(data: &[u8]) {
    let Ok(frame) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let type_field = frame.get("type").and_then(Value::as_str);
    match classify_nm_frame(&frame) {
        FrameDisposition::Forward => assert!(
            spelled_tag(type_field).is_none(),
            "a forwarded frame carries no control tag: {frame}"
        ),
        FrameDisposition::Handle(request) => {
            let Ok(again) = serde_json::to_value(&request) else {
                panic!("a parsed request serializes: {request:?}");
            };
            assert_eq!(
                again.get("type").and_then(Value::as_str),
                type_field,
                "the parsed request's tag is the frame's `type`"
            );
            match classify_nm_frame(&again) {
                FrameDisposition::Handle(reparsed) => assert_eq!(
                    reparsed, request,
                    "a request re-classifies to itself from its own serialization"
                ),
                FrameDisposition::Forward | FrameDisposition::Malformed { .. } => {
                    panic!("a request's own serialization must classify as a request: {again}")
                }
            }
        }
        FrameDisposition::Malformed { tag, .. } => {
            assert_eq!(
                type_field,
                Some(tag.to_string().as_str()),
                "the frame's `type` is exactly the tag's wire spelling"
            );
            // Every tag has a defined answer; building it must not panic.
            let _reply = tag.malformed_reply();
        }
    }
}

/// The hand-written strict-DER parser that converts Security.framework ECDSA signatures to WebCrypto's
/// raw r||s form: framework-produced in practice, but the byte parser itself must reject any corruption
/// without panicking.
pub fn enclave_der(data: &[u8]) {
    let _ = der_to_raw_signature(data);
}

/// The ours/foreign decision over attacker-controlled manifest JSON. The security property is
/// never-delete-foreign, so the oracle re-derives the only accepted shape (our exact host id plus one of
/// the two markers this project has ever written) and requires everything else to come back Foreign.
pub fn registration_manifest(data: &[u8]) {
    let contents = String::from_utf8_lossy(data);
    let expect_ours = serde_json::from_str::<Value>(&contents)
        .ok()
        .is_some_and(|manifest| {
            manifest.get("name").and_then(|v| v.as_str()) == Some(NATIVE_HOST_ID)
                && manifest
                    .get("description")
                    .and_then(|v| v.as_str())
                    .is_some_and(|d| {
                        d == fuzz_api::MANIFEST_DESCRIPTION
                            || d == fuzz_api::MANIFEST_DESCRIPTION_LEGACY
                    })
        });
    match manifest_ownership(&contents) {
        Ownership::Ours => assert!(expect_ours, "claimed Ours outside the accepted shape"),
        Ownership::Foreign(_) => assert!(!expect_ours, "our own manifest judged Foreign"),
    }
}

/// The invariants every successfully parsed document must satisfy: validate and values never panic,
/// and the exact serialized bytes reparse to an equal document (what the store's signed-byte round
/// trip depends on).
fn check_doc(doc: &PolicyDoc) {
    let _ = doc.validate();
    let _ = doc.values();
    let bytes = serde_json::to_vec(doc).expect("a parsed PolicyDoc must serialize");
    let back: PolicyDoc =
        serde_json::from_slice(&bytes).expect("serialized PolicyDoc must reparse");
    assert_eq!(&back, doc, "PolicyDoc serde round trip must be identity");
}

/// Folding an overlay over a baseline never panics and is idempotent; returns the folded values for
/// the pairwise lattice check.
fn check_fold(baseline: &PolicyValues, overlay: &PolicyOverlay) -> PolicyValues {
    let once = fold(baseline, overlay);
    assert_eq!(fold(&once, overlay), once, "fold must be idempotent");
    once
}

/// The policy store parse surface: `policy.json` is a same-user-writable file, so every shape read from
/// it (the record envelope through the production decoder, the base64 baseline bytes, the strict
/// PolicyDoc, the overlay, the history ring) must fail closed on hostile bytes. Beyond crash-freedom:
/// a parsed document serde-round-trips to an equal value, the comparison lattice partitions every pair
/// (relaxes XOR restricts_or_equal), fold is idempotent, and the strict base64 decoder accepts exactly
/// one spelling per byte string.
pub fn policy_doc(data: &[u8]) {
    // Every parsed shape contributes its values here; the lattice check at the bottom runs over all
    // pairs (including each value against itself).
    let mut values: Vec<PolicyValues> = Vec::new();

    if let Ok(doc) = serde_json::from_slice::<PolicyDoc>(data) {
        check_doc(&doc);
        values.push(doc.values());
    }

    if let Ok(overlay) = serde_json::from_slice::<PolicyOverlay>(data) {
        values.push(check_fold(&PolicyValues::default(), &overlay));
    }

    if let Ok(store) = PolicyStore::decode(data) {
        // Mirror baseline_doc()'s byte path on the parsed envelope (pure: it reads self.baseline_b64,
        // never the filesystem) and cross-check it against a by-hand decode of the same bytes.
        let by_hand = base64_decode(&store.baseline_b64)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PolicyDoc>(&bytes).ok())
            .filter(|doc| doc.validate().is_ok());
        let via_store = store.baseline_doc().ok();
        assert_eq!(
            by_hand, via_store,
            "baseline_doc must equal strict base64 decode + strict parse + validate"
        );
        if let Some(doc) = via_store {
            check_doc(&doc);
            let baseline = doc.values();
            let overlay = store.overlay.clone().unwrap_or_default();
            let effective = check_fold(&baseline, &overlay);
            assert_eq!(
                store
                    .effective()
                    .expect("a store with a valid baseline must fold"),
                effective,
                "effective() must be the fold of the baseline and the stored overlay"
            );
            values.push(baseline);
            values.push(effective);
        } else {
            assert!(
                store.effective().is_err(),
                "a store whose baseline fails must fail effective() too"
            );
        }
    }

    // The history ring shares the fail-closed posture; parsing it must not panic (its entries are
    // data, never authority, so nothing more to hold).
    let _ = PolicyHistory::decode(data);

    // The lattice partition (the store's direction check depends on it): a pair either relaxes
    // somewhere or restricts-or-holds everywhere, never both, never neither. A violation here IS a
    // finding.
    for a in &values {
        for b in &values {
            assert!(
                relaxes(a, b) != restricts_or_equal(a, b),
                "relaxes and restricts_or_equal must partition every pair"
            );
        }
    }

    // The strict base64 decoder directly: for every accepted input, encoding the decode must
    // reproduce the exact input, the canonicality the signed baseline depends on.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(bytes) = base64_decode(text) {
            assert_eq!(
                base64_encode(&bytes),
                text,
                "base64_decode must accept only the canonical spelling"
            );
        }
    }
}
