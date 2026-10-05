//! The only home for on-disk compatibility code: one [`Ladder`](crate::runtime_record::Ladder) per
//! runtime record, each rung lifting a body from version `i` to `i + 1`. The floor rule, and how a
//! record's version derives from its ladder, is stated once on that type.

pub(crate) mod host_key;
pub(crate) mod lang;
pub(crate) mod policy;
pub(crate) mod policy_history;
pub(crate) mod trust;
