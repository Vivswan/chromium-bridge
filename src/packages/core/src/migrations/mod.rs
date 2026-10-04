//! The only home for on-disk compatibility code: one ladder per runtime record, each rung a
//! [`Rung`](crate::runtime_record::Rung) lifting a body from version `i` to `i + 1`. A record's schema
//! version is its ladder's length, so appending a rung IS the version bump.
//!
//! A record's first rung lands as `<record>/m0001_<slug>.rs` and is appended to that record's `LADDER`.

pub(crate) mod clients;
pub(crate) mod config;
pub(crate) mod lang;
pub(crate) mod policy;
pub(crate) mod policy_history;
pub(crate) mod revocation;
