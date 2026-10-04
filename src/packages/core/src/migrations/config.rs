//! Ladder for `config.json` ([`crate::enclave::HostConfig`]).

use crate::runtime_record::Ladder;

pub(crate) const LADDER: Ladder = Ladder {
    first_version: 0,
    rungs: &[],
};
