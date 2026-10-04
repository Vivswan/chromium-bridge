//! `seeds/policy_doc/`: the four shapes the policy store surface parses, each with its own reader.
//!
//! ```text
//! doc_*      -> strict PolicyDoc parse plus validate()
//! overlay_*  -> strict PolicyOverlay parse
//! store_*    -> PolicyStore::decode (the record envelope) plus effective()
//! history_*  -> PolicyHistory::decode
//! ```

use chromium_bridge_core::enclave::{base64_encode, SIG_LEN};
use chromium_bridge_core::policy::{
    Ms, PolicyDoc, PolicyField, PolicyHistory, PolicyHistoryEntry, PolicyOverlay, PolicyStore,
    DISABLED_TOOLS_MAX_ENTRIES, JS_SAFE_INT_MAX,
};
use chromium_bridge_core::runtime_record::RuntimeRecord as _;
use chromium_bridge_core::tools;
use serde_json::{json, Value};

use super::{compact, edited, repeated_key, without, Directory, Seed};
use crate::targets;

fn reads_doc(bytes: &[u8]) -> bool {
    serde_json::from_slice::<PolicyDoc>(bytes).is_ok_and(|doc| doc.validate().is_ok())
}

fn reads_overlay(bytes: &[u8]) -> bool {
    serde_json::from_slice::<PolicyOverlay>(bytes).is_ok()
}

/// The store loads and its effective policy folds: what every enforcement path needs from the file.
fn reads_store(bytes: &[u8]) -> bool {
    PolicyStore::decode(bytes).is_ok_and(|store| store.effective().is_ok())
}

fn reads_history(bytes: &[u8]) -> bool {
    PolicyHistory::decode(bytes).is_ok()
}

/// The encoded record with its envelope version one above this binary's ladder.
fn above_ladder(record: &Value) -> Value {
    edited(record, |v| {
        let version = v["version"]
            .as_u64()
            .expect("the envelope carries a version");
        v["version"] = json!(version + 1);
    })
}

pub(super) fn directory() -> Directory {
    let touched_doc = PolicyDoc {
        revision: 1,
        touched: PolicyField::ALL.to_vec(),
        ..PolicyDoc::default()
    };
    let first_tool = tools::all()
        .next()
        .expect("the catalogue has at least one tool")
        .name;
    let restriction = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(Ms::ZERO),
        disabled_tools: Some(vec![first_tool.to_string()]),
        ..PolicyOverlay::default()
    };
    let doc = json_of!(PolicyDoc::default());
    let store = PolicyStore {
        baseline_b64: base64_encode(&compact(&doc)),
        sig_b64: Some(base64_encode(&[0u8; SIG_LEN])),
        key_id: Some("example-key".into()),
        overlay: Some(restriction.clone()),
    };
    let unsigned = PolicyStore {
        sig_b64: None,
        key_id: None,
        overlay: None,
        ..store.clone()
    };
    let history = PolicyHistory {
        entries: vec![PolicyHistoryEntry {
            baseline_b64: store.baseline_b64.clone(),
            sig_b64: store.sig_b64.clone(),
            key_id: store.key_id.clone(),
            overlay: store.overlay.clone(),
            superseded_unix: 1_700_000_000,
        }],
    };
    let encode = |bytes: &[u8]| -> Value {
        serde_json::from_slice(bytes).expect("an encoded record is JSON")
    };
    let store_bytes = store.encode().expect("a seed store is under the cap");
    let history_bytes = history.encode().expect("a seed ring is under the cap");
    let store_json = encode(&store_bytes);
    let history_json = encode(&history_bytes);
    let overlay = json_of!(restriction);
    let ms_field = PolicyField::ConfirmGraceMs.wire_name();
    let tools_field = PolicyField::DisabledTools.wire_name();
    Directory {
        target: targets::POLICY_DOC,
        seeds: vec![
            Seed::accepted("doc_default", compact(&doc), reads_doc),
            Seed::accepted(
                "doc_touched_all",
                compact(&json_of!(touched_doc)),
                reads_doc,
            ),
            Seed::accepted("overlay_restrict", compact(&overlay), reads_overlay),
            Seed::accepted("store_signed", store_bytes, reads_store),
            Seed::accepted(
                "store_unsigned",
                unsigned.encode().expect("a seed store is under the cap"),
                reads_store,
            ),
            Seed::accepted("history", history_bytes, reads_history),
            Seed::refused(
                "store_version_above_ladder",
                compact(&above_ladder(&store_json)),
                reads_store,
            ),
            Seed::refused(
                "store_version_missing",
                compact(&without(&store_json, "version")),
                reads_store,
            ),
            Seed::refused(
                "store_unknown_field",
                compact(&edited(&store_json, |v| v["surprise"] = json!(true))),
                reads_store,
            ),
            Seed::refused(
                "store_truncated_base64",
                compact(&edited(&store_json, |v| {
                    let mut b64 = v["baseline_b64"].as_str().expect("base64").to_string();
                    b64.pop();
                    v["baseline_b64"] = json!(b64);
                })),
                reads_store,
            ),
            Seed::refused(
                "store_repeated_key",
                repeated_key(&store_json, "baseline_b64"),
                reads_store,
            ),
            Seed::refused(
                "history_version_above_ladder",
                compact(&above_ladder(&history_json)),
                reads_history,
            ),
            Seed::refused(
                "doc_version_unsupported",
                compact(&edited(&doc, |v| {
                    v["v"] = json!(v["v"].as_u64().expect("a version") + 1);
                })),
                reads_doc,
            ),
            Seed::refused(
                "doc_revision_over_bound",
                compact(&edited(&doc, |v| {
                    v["revision"] = json!(JS_SAFE_INT_MAX + 1);
                })),
                reads_doc,
            ),
            Seed::refused(
                "doc_ms_over_bound",
                compact(&edited(&doc, |v| v[ms_field] = json!(JS_SAFE_INT_MAX + 1))),
                reads_doc,
            ),
            Seed::refused(
                "doc_disabled_tools_over_bound",
                compact(&edited(&doc, |v| {
                    v[tools_field] = json!(vec!["example_tool"; DISABLED_TOOLS_MAX_ENTRIES + 1]);
                })),
                reads_doc,
            ),
            Seed::refused(
                "doc_touched_unknown_field",
                compact(&edited(&doc, |v| v["touched"] = json!(["surprise"]))),
                reads_doc,
            ),
            Seed::refused(
                "doc_unknown_field",
                compact(&edited(&doc, |v| v["surprise"] = json!(true))),
                reads_doc,
            ),
            Seed::refused(
                "overlay_unknown_field",
                compact(&edited(&overlay, |v| v["surprise"] = json!(true))),
                reads_overlay,
            ),
        ],
    }
}
