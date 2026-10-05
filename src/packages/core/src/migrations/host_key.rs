//! Ladder for `host_key.json` ([`crate::enclave::HostKeyFile`]).

use crate::runtime_record::Ladder;

pub(crate) const LADDER: Ladder = Ladder {
    first_version: 0,
    rungs: &[],
};
