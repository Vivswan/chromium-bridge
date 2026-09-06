use super::*;
use proptest::prelude::*;

/// Millisecond values weighted toward 0 and small collisions, so the
/// zero-top order and the equality edges are exercised constantly.
fn arb_ms() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), 1u64..5, Just(60_000u64), any::<u64>(),]
}

/// Tool lists drawn from a tiny pool, so candidate/anchor pairs overlap,
/// nest, and diverge in every combination.
fn arb_tools() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::sample::select(vec!["page_eval", "page_upload", "tab_close", "click"]),
        0..4,
    )
    .prop_map(|ts| ts.into_iter().map(str::to_string).collect())
}

fn arb_values() -> impl Strategy<Value = PolicyValues> {
    (
        (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()),
        (
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        ),
        (arb_ms(), arb_ms(), arb_ms(), arb_ms()),
        arb_tools(),
    )
        .prop_map(
            |(
                (cdp_mode, file_upload_enabled, handle_dialog_enabled, page_eval_enabled),
                (
                    confirm_high_risk_click,
                    confirm_page_eval,
                    touch_id_confirm,
                    confirm_tab_close,
                    warn_precise_snapshot,
                    eval_mask,
                ),
                (host_reverify_ms, confirm_grace_ms, click_toast_timeout_ms, eval_toast_timeout_ms),
                disabled_tools,
            )| PolicyValues {
                cdp_mode,
                file_upload_enabled,
                handle_dialog_enabled,
                page_eval_enabled,
                confirm_high_risk_click,
                confirm_page_eval,
                touch_id_confirm,
                confirm_tab_close,
                warn_precise_snapshot,
                eval_mask,
                host_reverify_ms,
                confirm_grace_ms,
                click_toast_timeout_ms,
                eval_toast_timeout_ms,
                disabled_tools,
            },
        )
}

/// An overlay built from arbitrary values with a per-field presence
/// mask, so every subset of fields occurs.
fn arb_overlay() -> impl Strategy<Value = PolicyOverlay> {
    (arb_values(), prop::collection::vec(any::<bool>(), 15)).prop_map(|(v, on)| PolicyOverlay {
        cdp_mode: on[0].then_some(v.cdp_mode),
        file_upload_enabled: on[1].then_some(v.file_upload_enabled),
        handle_dialog_enabled: on[2].then_some(v.handle_dialog_enabled),
        page_eval_enabled: on[3].then_some(v.page_eval_enabled),
        confirm_high_risk_click: on[4].then_some(v.confirm_high_risk_click),
        confirm_page_eval: on[5].then_some(v.confirm_page_eval),
        touch_id_confirm: on[6].then_some(v.touch_id_confirm),
        confirm_tab_close: on[7].then_some(v.confirm_tab_close),
        warn_precise_snapshot: on[8].then_some(v.warn_precise_snapshot),
        eval_mask: on[9].then_some(v.eval_mask),
        host_reverify_ms: on[10].then_some(v.host_reverify_ms),
        confirm_grace_ms: on[11].then_some(v.confirm_grace_ms),
        click_toast_timeout_ms: on[12].then_some(v.click_toast_timeout_ms),
        eval_toast_timeout_ms: on[13].then_some(v.eval_toast_timeout_ms),
        disabled_tools: on[14].then(|| v.disabled_tools.clone()),
    })
}

proptest! {
    /// The lattice partition: every candidate/anchor pair either relaxes
    /// somewhere or restricts-or-holds everywhere, never both, never
    /// neither. Real teeth because the two sides are implemented
    /// independently (grant reading vs restrictive reading, per field).
    #[test]
    fn relaxes_and_restricts_or_equal_partition_every_pair(
        candidate in arb_values(),
        anchor in arb_values(),
    ) {
        prop_assert!(relaxes(&candidate, &anchor) != restricts_or_equal(&candidate, &anchor));
    }

    /// Reflexive safety: a policy never relaxes itself (replaying the
    /// current effective policy is idempotent, never a grant).
    #[test]
    fn a_policy_never_relaxes_itself(v in arb_values()) {
        prop_assert!(!relaxes(&v, &v));
        prop_assert!(restricts_or_equal(&v, &v));
    }

    /// The verdict does not depend on the order fields are examined in.
    #[test]
    fn the_verdict_is_field_order_independent(
        candidate in arb_values(),
        anchor in arb_values(),
        order in Just(PolicyField::ALL.to_vec()).prop_shuffle(),
    ) {
        let any_relax = order.iter().any(|f| field_relaxes(*f, &candidate, &anchor));
        prop_assert_eq!(any_relax, relaxes(&candidate, &anchor));
        let all_hold = order
            .iter()
            .all(|f| field_restricts_or_equal(*f, &candidate, &anchor));
        prop_assert_eq!(all_hold, restricts_or_equal(&candidate, &anchor));
    }

    /// Folding the same overlay twice is folding it once.
    #[test]
    fn fold_is_idempotent(baseline in arb_values(), overlay in arb_overlay()) {
        let once = fold(&baseline, &overlay);
        prop_assert_eq!(fold(&once, &overlay), once.clone());
    }
}
