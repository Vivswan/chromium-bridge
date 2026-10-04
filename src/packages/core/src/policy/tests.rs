use super::*;
use serde_json::json;

/// Values differing from the deny baseline only in `hostReverifyMs`.
fn with_reverify(ms: u32) -> PolicyValues {
    PolicyValues {
        host_reverify_ms: Ms::from(ms),
        ..PolicyValues::default()
    }
}

/// Values differing from the deny baseline only in `disabledTools`.
fn with_tools(tools: &[&str]) -> PolicyValues {
    PolicyValues {
        disabled_tools: tools.iter().map(|t| t.to_string()).collect(),
        ..PolicyValues::default()
    }
}

/// `field` at its permissive pole and at its restrictive pole, every other
/// field at the deny baseline, read from the catalogue's declared direction.
fn poles(field: PolicyField) -> (PolicyValues, PolicyValues) {
    let mut lax = PolicyValues::default();
    let mut tight = PolicyValues::default();
    match field.kind() {
        FieldKind::Bool(f) => {
            let grant = f.pole() == BoolPole::TruePermissive;
            *lax.bool_mut(f) = grant;
            *tight.bool_mut(f) = !grant;
        }
        FieldKind::Ms(f) => {
            let (l, t) = match f.order() {
                MsOrder::GrowsPermissive => (Ms::from(2u32), Ms::from(1u32)),
                MsOrder::GrowsPermissiveZeroTop => (Ms::ZERO, Ms::from(1u32)),
            };
            *lax.ms_mut(f) = l;
            *tight.ms_mut(f) = t;
        }
        FieldKind::ToolSet(f) => {
            *lax.tools_mut(f) = Vec::new();
            *tight.tools_mut(f) = vec!["page_eval".into()];
        }
    }
    (lax, tight)
}

#[test]
fn every_field_relaxes_exactly_toward_its_declared_pole() {
    // The direction table is the only owner of what relaxes: a field's
    // permissive pole relaxes its restrictive pole, no other field moves, and
    // the reverse never relaxes, for every catalogue field.
    for field in PolicyField::ALL {
        let (lax, tight) = poles(*field);
        let relaxed: Vec<PolicyField> = PolicyField::ALL
            .iter()
            .copied()
            .filter(|f| field_relaxes(*f, &lax, &tight))
            .collect();
        assert_eq!(
            relaxed,
            vec![*field],
            "{} alone must relax toward its declared permissive pole",
            field.wire_name()
        );
        assert!(
            !relaxes(&tight, &lax) && restricts_or_equal(&tight, &lax),
            "{} must not relax away from its declared permissive pole",
            field.wire_name()
        );
    }
}

#[test]
fn the_orders_a_naive_comparator_gets_wrong() {
    // hostReverifyMs: 0 = never re-verify = MOST permissive, above every
    // positive interval. disabledTools: a set, where dropping any anchor
    // entry relaxes whatever else the candidate adds, and order or
    // duplicates carry no meaning.
    let anchor_tools = with_tools(&["page_eval", "page_upload"]);
    let cases = [
        (
            "reverify 0 over 60000",
            with_reverify(0),
            with_reverify(60_000),
            true,
        ),
        (
            "reverify 60000 over 0",
            with_reverify(60_000),
            with_reverify(0),
            false,
        ),
        (
            "reverify 60000 over 1000",
            with_reverify(60_000),
            with_reverify(1_000),
            true,
        ),
        (
            "reverify 1000 over 60000",
            with_reverify(1_000),
            with_reverify(60_000),
            false,
        ),
        (
            "same tool set",
            anchor_tools.clone(),
            anchor_tools.clone(),
            false,
        ),
        (
            "tool superset",
            with_tools(&["page_eval", "page_upload", "tab_close"]),
            anchor_tools.clone(),
            false,
        ),
        (
            "reordered tool set with a duplicate",
            with_tools(&["page_upload", "page_eval", "page_eval"]),
            anchor_tools.clone(),
            false,
        ),
        (
            "one tool dropped",
            with_tools(&["page_eval"]),
            anchor_tools.clone(),
            true,
        ),
        (
            "one tool dropped while another is added",
            with_tools(&["page_eval", "tab_close"]),
            anchor_tools.clone(),
            true,
        ),
        (
            "every tool dropped",
            with_tools(&[]),
            anchor_tools.clone(),
            true,
        ),
    ];
    for (name, candidate, anchor, expected) in cases {
        assert_eq!(relaxes(&candidate, &anchor), expected, "{name}");
        assert_eq!(restricts_or_equal(&candidate, &anchor), !expected, "{name}");
    }
}

#[test]
fn serialized_bytes_are_the_signed_wire_contract() {
    // The signature covers these exact bytes and the extension strict-parses
    // them, so key spelling, key order, and value encoding are an external
    // contract: the bytes must never move.
    let values = PolicyValues {
        cdp_mode: true,
        file_upload_enabled: false,
        handle_dialog_enabled: true,
        page_eval_enabled: false,
        confirm_high_risk_click: false,
        confirm_page_eval: true,
        touch_id_confirm: false,
        confirm_tab_close: true,
        warn_precise_snapshot: false,
        eval_mask: true,
        host_reverify_ms: Ms::from(1u32),
        confirm_grace_ms: Ms::from(2u32),
        click_toast_timeout_ms: Ms::from(3u32),
        eval_toast_timeout_ms: Ms::try_from(JS_SAFE_INT_MAX).unwrap(),
        disabled_tools: vec!["page_eval".into(), "tab_close".into()],
    };
    let fields = concat!(
        r#""cdpMode":true,"#,
        r#""fileUploadEnabled":false,"#,
        r#""handleDialogEnabled":true,"#,
        r#""pageEvalEnabled":false,"#,
        r#""confirmHighRiskClick":false,"#,
        r#""confirmPageEval":true,"#,
        r#""touchIdConfirm":false,"#,
        r#""confirmTabClose":true,"#,
        r#""warnPreciseSnapshot":false,"#,
        r#""evalMask":true,"#,
        r#""hostReverifyMs":1,"#,
        r#""confirmGraceMs":2,"#,
        r#""clickToastTimeoutMs":3,"#,
        r#""evalToastTimeoutMs":9007199254740991,"#,
        r#""disabledTools":["page_eval","tab_close"]"#
    );
    assert_eq!(
        serde_json::to_string(&values).unwrap(),
        format!("{{{fields}}}")
    );
    assert_eq!(
        serde_json::from_str::<PolicyValues>(&format!("{{{fields}}}")).unwrap(),
        values
    );

    let mut overlay = PolicyOverlay::default();
    for field in PolicyField::ALL {
        overlay.set_from(*field, &values);
    }
    assert_eq!(
        serde_json::to_string(&overlay).unwrap(),
        format!("{{{fields}}}")
    );
    assert_eq!(
        serde_json::from_str::<PolicyOverlay>(&format!("{{{fields}}}")).unwrap(),
        overlay
    );
    assert_eq!(
        serde_json::to_string(&PolicyOverlay::default()).unwrap(),
        "{}"
    );

    let doc = PolicyDoc::from_values(
        &values,
        7,
        vec![
            PolicyField::CdpMode,
            PolicyField::EvalToastTimeoutMs,
            PolicyField::DisabledTools,
        ],
    );
    let doc_json = format!(
        r#"{{"v":1,"revision":7,"touched":["cdpMode","evalToastTimeoutMs","disabledTools"],{fields}}}"#
    );
    assert_eq!(serde_json::to_string(&doc).unwrap(), doc_json);
    assert_eq!(serde_json::from_str::<PolicyDoc>(&doc_json).unwrap(), doc);
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
    // The generated Zod (z.int()) refuses unsafe integers: without this
    // bound a huge millisecond value would sign and store host-side while
    // the extension refuses the push. Document and overlay lanes alike; a
    // huge-but-restricting overlay value is a legal restriction under the
    // zero-top order, so the overlay lane needs the bound just as much.
    for field in PolicyField::ALL
        .iter()
        .filter(|f| matches!(f.kind(), FieldKind::Ms(_)))
    {
        let name = field.wire_name();
        let mut doc = serde_json::to_value(PolicyDoc::default()).unwrap();
        doc[name] = json!(JS_SAFE_INT_MAX);
        assert!(
            serde_json::from_value::<PolicyDoc>(doc.clone()).is_ok(),
            "{name} must accept 2^53 - 1"
        );
        doc[name] = json!(JS_SAFE_INT_MAX + 1);
        assert!(
            serde_json::from_value::<PolicyDoc>(doc).is_err(),
            "{name} must refuse 2^53"
        );
        assert!(
            serde_json::from_value::<PolicyOverlay>(json!({ name: JS_SAFE_INT_MAX })).is_ok(),
            "overlay {name} must accept 2^53 - 1"
        );
        assert!(
            serde_json::from_value::<PolicyOverlay>(json!({ name: JS_SAFE_INT_MAX + 1 })).is_err(),
            "overlay {name} must refuse 2^53"
        );
    }
    // Absent fields stay None through the bounded deserializer.
    let empty: PolicyOverlay = serde_json::from_value(json!({})).unwrap();
    assert_eq!(empty, PolicyOverlay::default());
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
fn the_deny_baseline_sits_at_every_boolean_restrictive_pole() {
    // The deny mechanism is grants-off plus confirmations-on, a consistency
    // between the Default table and the catalogue's declared directions that
    // neither can express alone: a new boolean field with a permissive
    // default fails here. The windows are usability defaults, not poles, and
    // hostReverifyMs keeps its decided permissive default (see `Default for
    // PolicyValues`); the deny list has no restrictive end to sit at.
    let base = PolicyValues::default();
    for field in PolicyField::ALL {
        let FieldKind::Bool(f) = field.kind() else {
            continue;
        };
        let restrictive = match direction(*field) {
            Direction::Bool(BoolPole::TruePermissive) => false,
            Direction::Bool(BoolPole::FalsePermissive) => true,
            Direction::Ms(_) | Direction::ShrinksPermissiveSet => {
                panic!("{}: boolean field declared non-boolean", field.wire_name())
            }
        };
        assert_eq!(
            base.get_bool(f),
            restrictive,
            "{} must default to its restrictive pole",
            field.wire_name()
        );
    }
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
fn fold_applies_exactly_the_present_overlay_entries() {
    let base = PolicyValues::default();
    let overlay = PolicyOverlay {
        page_eval_enabled: Some(false),
        confirm_grace_ms: Some(Ms::ZERO),
        disabled_tools: Some(vec!["page_upload".into()]),
        ..PolicyOverlay::default()
    };
    assert_eq!(
        fold(&base, &overlay),
        PolicyValues {
            page_eval_enabled: false,
            confirm_grace_ms: Ms::ZERO,
            disabled_tools: vec!["page_upload".into()],
            ..base.clone()
        }
    );
    // An empty overlay is the identity.
    assert_eq!(fold(&base, &PolicyOverlay::default()), base);
}
