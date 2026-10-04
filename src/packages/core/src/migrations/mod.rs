//! The only home for on-disk compatibility code: one ladder per runtime record, each rung a
//! [`Rung`](crate::runtime_record::Rung) lifting a body from version `i` to `i + 1`.
//! [`crate::runtime_record`] derives each record's version from its ladder.

pub(crate) mod config;
pub(crate) mod lang;
pub(crate) mod policy;
pub(crate) mod policy_history;
pub(crate) mod trust;
