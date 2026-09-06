use proptest::prelude::*;

use super::{next_revision, PolicyWriteError, JS_SAFE_INT_MAX};

/// Baseline revisions across the whole JS-safe range, weighted so the
/// bound edges occur in every run, not just by luck.
fn arb_revision() -> impl Strategy<Value = u64> {
    prop_oneof![
        0..=JS_SAFE_INT_MAX,
        Just(0u64),
        Just(JS_SAFE_INT_MAX - 1),
        Just(JS_SAFE_INT_MAX),
    ]
}

proptest! {
    /// Monotonicity with no wraparound (ADR-0032): a store observed at
    /// baseline revision r mints exactly r + 1, still JS-safe, and the
    /// bound itself refuses (`RevisionOverflow`) instead of wrapping,
    /// saturating, or panicking.
    #[test]
    fn a_grant_write_mints_exactly_the_next_revision(r in arb_revision()) {
        if r == JS_SAFE_INT_MAX {
            prop_assert!(matches!(
                next_revision(Some(r)),
                Err(PolicyWriteError::RevisionOverflow)
            ));
        } else {
            let next = next_revision(Some(r)).unwrap();
            prop_assert_eq!(next, r + 1);
            prop_assert!(next <= JS_SAFE_INT_MAX);
        }
    }
}
