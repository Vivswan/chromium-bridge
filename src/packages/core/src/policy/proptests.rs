use super::*;
use proptest::prelude::*;

/// Millisecond values weighted toward 0 and small collisions, so the
/// zero-top order and the equality edges are exercised constantly.
fn arb_ms() -> impl Strategy<Value = Ms> {
    prop_oneof![Just(0u64), 1u64..5, Just(60_000u64), 0u64..=JS_SAFE_INT_MAX,]
        .prop_map(|ms| Ms::try_from(ms).unwrap())
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

/// Every field drawn independently by its kind, over the catalogue.
fn arb_values() -> BoxedStrategy<PolicyValues> {
    PolicyField::ALL.iter().fold(
        Just(PolicyValues::default()).boxed(),
        |acc, field| match field.kind() {
            FieldKind::Bool(f) => (acc, any::<bool>())
                .prop_map(move |(mut v, x)| {
                    *v.bool_mut(f) = x;
                    v
                })
                .boxed(),
            FieldKind::Ms(f) => (acc, arb_ms())
                .prop_map(move |(mut v, x)| {
                    *v.ms_mut(f) = x;
                    v
                })
                .boxed(),
            FieldKind::ToolSet(f) => (acc, arb_tools())
                .prop_map(move |(mut v, x)| {
                    *v.tools_mut(f) = x;
                    v
                })
                .boxed(),
        },
    )
}

/// An overlay built from arbitrary values with a per-field presence
/// mask, so every subset of fields occurs.
fn arb_overlay() -> impl Strategy<Value = PolicyOverlay> {
    (
        arb_values(),
        prop::collection::vec(any::<bool>(), PolicyField::ALL.len()),
    )
        .prop_map(|(values, present)| {
            let mut overlay = PolicyOverlay::default();
            for (field, on) in PolicyField::ALL.iter().zip(present) {
                if on {
                    overlay.set_from(*field, &values);
                }
            }
            overlay
        })
}

proptest! {
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
    }

    /// Folding the same overlay twice is folding it once.
    #[test]
    fn fold_is_idempotent(baseline in arb_values(), overlay in arb_overlay()) {
        let once = fold(&baseline, &overlay);
        prop_assert_eq!(fold(&once, &overlay), once.clone());
    }
}
