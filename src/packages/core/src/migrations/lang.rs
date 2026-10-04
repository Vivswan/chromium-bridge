//! Ladder for `lang.json` ([`crate::lang::LangStore`]).

use crate::runtime_record::Ladder;

pub(crate) const LADDER: Ladder = Ladder {
    first_version: 0,
    rungs: &[],
};
