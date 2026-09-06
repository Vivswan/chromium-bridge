use super::*;
use serde_json::json;

/// Values differing from the deny baseline only in `hostReverifyMs`.
fn with_reverify(ms: u64) -> PolicyValues {
    PolicyValues {
        host_reverify_ms: ms,
        ..PolicyValues::default()
    }
}

fn with_tools(tools: &[&str]) -> PolicyValues {
    PolicyValues {
        disabled_tools: tools.iter().map(|t| t.to_string()).collect(),
        ..PolicyValues::default()
    }
}

#[test]
fn direction_is_total_over_the_pinned_field_catalogue() {
    // Pins the exact catalogue AND each field's declared direction: a
    // silently added, removed, or reclassified field fails right here.
    let table: Vec<(&str, Direction)> = PolicyField::ALL
        .iter()
        .map(|f| (f.wire_name(), direction(*f)))
        .collect();
    assert_eq!(
        table,
        [
            ("cdpMode", Direction::TruePermissive),
            ("fileUploadEnabled", Direction::TruePermissive),
            ("handleDialogEnabled", Direction::TruePermissive),
            ("pageEvalEnabled", Direction::TruePermissive),
            ("confirmHighRiskClick", Direction::FalsePermissive),
            ("confirmPageEval", Direction::FalsePermissive),
            ("touchIdConfirm", Direction::FalsePermissive),
            ("confirmTabClose", Direction::FalsePermissive),
            ("warnPreciseSnapshot", Direction::FalsePermissive),
            ("evalMask", Direction::FalsePermissive),
            ("hostReverifyMs", Direction::GrowsPermissiveZeroTop),
            ("confirmGraceMs", Direction::GrowsPermissive),
            ("clickToastTimeoutMs", Direction::GrowsPermissive),
            ("evalToastTimeoutMs", Direction::GrowsPermissive),
            ("disabledTools", Direction::ShrinksPermissiveSet),
        ]
    );
}

#[test]
fn wire_names_match_serde_emission_and_round_trip() {
    // The macro derives both from one literal; this pins that serde
    // actually emits it, the same posture as protocol/control.rs's
    // every_control_variant_tag_is_derived_and_recognized.
    for f in PolicyField::ALL {
        let emitted = serde_json::to_value(f).unwrap();
        assert_eq!(emitted, json!(f.wire_name()));
        let back: PolicyField = serde_json::from_value(emitted).unwrap();
        assert_eq!(back, *f);
    }
}

#[test]
fn document_keys_are_exactly_the_scoping_fields_plus_the_wire_names() {
    // PolicyDoc's keys come from rename_all = "camelCase" over the struct
    // fields, PolicyField's from the macro literals. Nothing ties the two
    // together at compile time, so pin their equality here: a struct
    // field rename (or a macro literal edit) that lets them drift makes a
    // touched entry stop naming a document key.
    let doc = serde_json::to_value(PolicyDoc::default()).unwrap();
    let doc_keys: std::collections::BTreeSet<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> = ["v", "revision", "touched"]
        .into_iter()
        .chain(PolicyField::ALL.iter().map(|f| f.wire_name()))
        .collect();
    assert_eq!(doc_keys, expected);
    // The overlay carries exactly the wire-named fields (all optional).
    let full_overlay: PolicyOverlay =
        serde_json::from_value(doc_without_scoping_fields(&doc)).unwrap();
    assert_eq!(
        serde_json::to_value(&full_overlay)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        PolicyField::ALL.len()
    );
}

/// The default document's JSON minus v/revision/touched: a full overlay
/// in wire spelling, for the key-parity pin above.
fn doc_without_scoping_fields(doc: &serde_json::Value) -> serde_json::Value {
    let mut obj = doc.as_object().unwrap().clone();
    obj.remove("v");
    obj.remove("revision");
    obj.remove("touched");
    serde_json::Value::Object(obj)
}

#[test]
fn unknown_touched_field_names_fail_the_parse() {
    // requireEnrollment is retired and uiLanguage is deliberately not a
    // policy field; neither may ride into a touched set.
    for bad in ["requireEnrollment", "uiLanguage", "bogus", "cdpmode", ""] {
        assert!(
            serde_json::from_value::<PolicyField>(json!(bad)).is_err(),
            "field name {bad:?} must be refused"
        );
    }
    let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
    doc["touched"] = json!(["pageEvalEnabled", "requireEnrollment"]);
    assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());
}

#[test]
fn host_reverify_zero_tops_the_permissiveness_scale() {
    // The order a naive numeric comparator gets backwards: 0 = never
    // re-verify = MOST permissive.
    assert!(relaxes(&with_reverify(0), &with_reverify(60_000)));
    assert!(!relaxes(&with_reverify(60_000), &with_reverify(0)));
    assert!(restricts_or_equal(
        &with_reverify(60_000),
        &with_reverify(0)
    ));
    assert!(!restricts_or_equal(
        &with_reverify(0),
        &with_reverify(60_000)
    ));
    // Among positive values permissiveness grows with the number.
    assert!(relaxes(&with_reverify(60_000), &with_reverify(1_000)));
    assert!(!relaxes(&with_reverify(1_000), &with_reverify(60_000)));
    assert!(restricts_or_equal(
        &with_reverify(1_000),
        &with_reverify(60_000)
    ));
    assert!(!restricts_or_equal(
        &with_reverify(60_000),
        &with_reverify(1_000)
    ));
}

#[test]
fn revision_parses_only_inside_the_js_safe_bound() {
    let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
    doc["revision"] = json!(9_007_199_254_740_991u64);
    let parsed: PolicyDoc = serde_json::from_value(doc.clone()).unwrap();
    assert_eq!(parsed.revision, JS_SAFE_INT_MAX);
    doc["revision"] = json!(9_007_199_254_740_992u64);
    assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());
    // validate() covers the constructed-in-code path the parser never
    // sees (set_signed must refuse before any prompt).
    let over = PolicyDoc {
        revision: JS_SAFE_INT_MAX + 1,
        ..PolicyDoc::default()
    };
    assert!(over.validate().is_err());
    assert!(PolicyDoc::default().validate().is_ok());
}

#[test]
fn validate_refuses_a_foreign_document_version() {
    let doc = PolicyDoc {
        v: POLICY_DOC_VERSION + 1,
        ..PolicyDoc::default()
    };
    assert!(doc.validate().is_err());
}

#[test]
fn ms_fields_parse_only_inside_the_js_safe_bound() {
    // The parser differential F2 closes: without this bound a huge ms
    // value signs and stores host-side while the generated Zod (z.int()
    // rejects unsafe integers) refuses the push.
    for field in [
        "hostReverifyMs",
        "confirmGraceMs",
        "clickToastTimeoutMs",
        "evalToastTimeoutMs",
    ] {
        let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        doc[field] = json!(9_007_199_254_740_991u64);
        assert!(
            serde_json::from_value::<PolicyDoc>(doc.clone()).is_ok(),
            "{field} must accept 2^53 - 1"
        );
        doc[field] = json!(9_007_199_254_740_992u64);
        assert!(
            serde_json::from_value::<PolicyDoc>(doc).is_err(),
            "{field} must refuse 2^53"
        );
    }
}

#[test]
fn overlay_ms_fields_parse_only_inside_the_js_safe_bound() {
    // The same differential as the document fields, overlay lane: a
    // huge-but-restricting overlay value is a legal restriction under
    // the zero-top order, so without this bound it would store
    // host-side and then fail the extension's JS-safe frame parse.
    for field in [
        "hostReverifyMs",
        "confirmGraceMs",
        "clickToastTimeoutMs",
        "evalToastTimeoutMs",
    ] {
        let ok = json!({ field: 9_007_199_254_740_991u64 });
        assert!(
            serde_json::from_value::<PolicyOverlay>(ok).is_ok(),
            "overlay {field} must accept 2^53 - 1"
        );
        let over = json!({ field: 9_007_199_254_740_992u64 });
        assert!(
            serde_json::from_value::<PolicyOverlay>(over).is_err(),
            "overlay {field} must refuse 2^53"
        );
    }
    // Absent fields stay None through the bounded deserializer.
    let empty: PolicyOverlay = serde_json::from_value(json!({})).unwrap();
    assert_eq!(empty, PolicyOverlay::default());
}

#[test]
fn validate_bounds_ms_fields_for_constructed_docs() {
    // The parser never sees a constructed document; set_signed relies on
    // validate() to refuse it before any prompt.
    let over = JS_SAFE_INT_MAX + 1;
    for doc in [
        PolicyDoc {
            host_reverify_ms: over,
            ..PolicyDoc::default()
        },
        PolicyDoc {
            confirm_grace_ms: over,
            ..PolicyDoc::default()
        },
        PolicyDoc {
            click_toast_timeout_ms: over,
            ..PolicyDoc::default()
        },
        PolicyDoc {
            eval_toast_timeout_ms: over,
            ..PolicyDoc::default()
        },
    ] {
        assert!(doc.validate().is_err(), "{doc:?} must fail validate()");
    }
    let at_bound = PolicyDoc {
        host_reverify_ms: JS_SAFE_INT_MAX,
        confirm_grace_ms: JS_SAFE_INT_MAX,
        click_toast_timeout_ms: JS_SAFE_INT_MAX,
        eval_toast_timeout_ms: JS_SAFE_INT_MAX,
        ..PolicyDoc::default()
    };
    assert!(at_bound.validate().is_ok());
}

#[test]
fn validate_bounds_disabled_tools_entries() {
    // An oversized list must never validate: the store's write cap
    // refuses to persist what load cannot read back, and these bounds
    // are what keep every valid document under it.
    let doc = |tools: Vec<String>| PolicyDoc {
        disabled_tools: tools,
        ..PolicyDoc::default()
    };
    assert!(doc(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES])
        .validate()
        .is_ok());
    assert!(doc(vec!["t".into(); DISABLED_TOOLS_MAX_ENTRIES + 1])
        .validate()
        .is_err());
    assert!(doc(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES)])
        .validate()
        .is_ok());
    assert!(doc(vec!["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)])
        .validate()
        .is_err());
    assert!(doc(vec![String::new()]).validate().is_err());
}

#[test]
fn validate_refuses_entries_the_cli_transport_cannot_round_trip() {
    // Structural comma fidelity: the co-equal surfaces ship the list as
    // one comma-joined argv value that parse_tool_list re-splits and
    // trims, so a comma inside a name (split into two), surrounding
    // whitespace (trimmed away), or a whitespace-only name (trimmed to
    // empty and dropped) would sign something other than what was
    // written. Every such entry is REFUSED at the validation seams both
    // lanes share - never mangled.
    let doc = |tools: Vec<String>| PolicyDoc {
        disabled_tools: tools,
        ..PolicyDoc::default()
    };
    for bad in [
        "a,b",
        ",",
        "page_eval,",
        " page_eval",
        "page_eval ",
        "\tx",
        " ",
    ] {
        assert!(
            doc(vec![bad.into()]).validate().is_err(),
            "{bad:?} must fail validate()"
        );
    }
    // Positive control: ordinary names still validate.
    assert!(doc(vec!["page_eval".into(), "tab_close".into()])
        .validate()
        .is_ok());
}

#[test]
fn policy_field_wire_names_carry_no_comma() {
    // The audit details and the rollback plan comma-join FIELD wire
    // names (wire_name_list / wire_names); this pins that join faithful
    // for the catalogue itself.
    for field in PolicyField::ALL {
        assert!(
            !field.wire_name().contains(','),
            "{} must not contain a comma",
            field.wire_name()
        );
    }
}

#[test]
fn host_reverify_default_zero_is_the_decided_deny_baseline_exception() {
    // hostReverifyMs's default 0 IS the field's most permissive value -
    // the one deliberate exception to "the deny baseline sits at every
    // field's restrictive pole" (user decision 2026-08-10: the deny
    // mechanism is grants-off + confirmations-on, and today's shipped
    // default of 0 is kept). Pinned together so no future review
    // rediscovers it as a bug.
    assert_eq!(PolicyValues::default().host_reverify_ms, 0);
    assert_eq!(
        direction(PolicyField::HostReverifyMs),
        Direction::GrowsPermissiveZeroTop
    );
}

#[test]
fn touched_set_embeds_and_round_trips_byte_exact() {
    let doc = PolicyDoc {
        revision: 3,
        touched: vec![
            PolicyField::PageEvalEnabled,
            PolicyField::HostReverifyMs,
            PolicyField::DisabledTools,
        ],
        page_eval_enabled: true,
        ..PolicyDoc::default()
    };
    // The exact serialized bytes (what a signature would cover)
    // strict-parse back to the same document, touched set included.
    let bytes = serde_json::to_vec(&doc).unwrap();
    let back: PolicyDoc = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back, doc);
    assert_eq!(back.touched, doc.touched);
    // And the embedded set is spelled in wire names inside those bytes.
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["touched"],
        json!(["pageEvalEnabled", "hostReverifyMs", "disabledTools"])
    );
}

#[test]
fn unknown_fields_are_rejected_fail_closed() {
    let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
    // Positive control: the exact shape parses.
    assert!(serde_json::from_value::<PolicyDoc>(doc.clone()).is_ok());
    doc["surprise"] = json!(true);
    assert!(serde_json::from_value::<PolicyDoc>(doc).is_err());

    assert!(serde_json::from_value::<PolicyOverlay>(json!({})).is_ok());
    assert!(serde_json::from_value::<PolicyOverlay>(json!({
        "disabledTools": ["page_eval"],
    }))
    .is_ok());
    assert!(serde_json::from_value::<PolicyOverlay>(json!({
        "disabledTools": ["page_eval"],
        "surprise": true,
    }))
    .is_err());
    // The retired / excluded settings.ts fields are unknown here too.
    assert!(serde_json::from_value::<PolicyOverlay>(json!({
        "requireEnrollment": false,
    }))
    .is_err());
    assert!(serde_json::from_value::<PolicyOverlay>(json!({
        "uiLanguage": "en",
    }))
    .is_err());
}

#[test]
fn an_empty_overlay_serializes_to_an_empty_object() {
    assert_eq!(
        serde_json::to_value(PolicyOverlay::default()).unwrap(),
        json!({})
    );
}

#[test]
fn the_default_is_the_deny_baseline() {
    let base = PolicyValues::default();
    assert!(!base.cdp_mode);
    assert!(!base.file_upload_enabled);
    assert!(!base.handle_dialog_enabled);
    assert!(!base.page_eval_enabled);
    assert!(base.confirm_high_risk_click);
    assert!(base.confirm_page_eval);
    assert!(base.touch_id_confirm);
    assert!(base.confirm_tab_close);
    assert!(base.warn_precise_snapshot);
    assert!(base.eval_mask);
    assert_eq!(base.host_reverify_ms, 0);
    assert_eq!(base.confirm_grace_ms, 60_000);
    assert_eq!(base.click_toast_timeout_ms, 30_000);
    assert_eq!(base.eval_toast_timeout_ms, 45_000);
    assert!(base.disabled_tools.is_empty());

    let doc = PolicyDoc::default();
    assert_eq!(doc.v, POLICY_DOC_VERSION);
    assert_eq!(doc.revision, 0);
    assert!(doc.touched.is_empty());
    assert_eq!(doc.values(), base);
}

#[test]
fn fold_applies_exactly_the_present_overlay_entries() {
    let base = PolicyValues::default();
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(0),
        disabled_tools: Some(vec!["page_upload".into()]),
        ..PolicyOverlay::default()
    };
    let effective = fold(&base, &overlay);
    assert!(!effective.page_eval_enabled);
    assert_eq!(effective.confirm_grace_ms, 0);
    assert_eq!(effective.disabled_tools, vec!["page_upload".to_string()]);
    // Untouched fields pass through.
    assert_eq!(
        effective.click_toast_timeout_ms,
        base.click_toast_timeout_ms
    );
    assert_eq!(effective.eval_mask, base.eval_mask);
    // An empty overlay is the identity.
    assert_eq!(fold(&base, &PolicyOverlay::default()), base);
}

#[test]
fn disabled_tools_relax_only_when_an_anchor_entry_is_dropped() {
    let anchor = with_tools(&["page_eval", "page_upload"]);
    // Growing the set (or holding it) never relaxes.
    assert!(!relaxes(&anchor.clone(), &anchor));
    assert!(!relaxes(
        &with_tools(&["page_eval", "page_upload", "tab_close"]),
        &anchor
    ));
    // Dropping any anchor entry relaxes, even while adding others.
    assert!(relaxes(&with_tools(&["page_eval"]), &anchor));
    assert!(relaxes(&with_tools(&["page_eval", "tab_close"]), &anchor));
    assert!(relaxes(&with_tools(&[]), &anchor));
}
