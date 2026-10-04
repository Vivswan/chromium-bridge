//! Ladder for `policy.json` ([`crate::policy::PolicyStore`]).

use crate::runtime_record::Ladder;

pub(crate) const LADDER: Ladder = Ladder {
    first_version: 0,
    rungs: &[],
};
