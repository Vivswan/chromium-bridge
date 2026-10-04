//! Ladder for `policy-history.json` ([`crate::policy::PolicyHistory`]).

use crate::runtime_record::Ladder;

pub(crate) const LADDER: Ladder = Ladder {
    first_version: 0,
    rungs: &[],
};
