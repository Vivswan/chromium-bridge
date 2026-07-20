//! Emit the JSON Schemas schemars derives from the Rust bridge-envelope wire
//! types, as one JSON object `{ "request": ..., "response": ..., "enclave":
//! ..., "admin": ... }` on stdout.
//!
//! The Rust types in `protocol.rs` are the canonical envelope contract
//! (ADR-0028). Two consumers read this output:
//!
//! - `scripts/gen-envelope.ts` (`just gen`) generates the extension's base
//!   wire validators from it (`src/packages/shared/src/envelope-wire.gen.ts`);
//! - `scripts/check-envelope-parity.ts` (CI + `just ci`) diffs it against
//!   `z.toJSONSchema()` of the validators the extension actually enforces -
//!   the generated bases wrapped by a hand-written asymmetry layer - after a
//!   small, documented set of erasure rules (see the rule list in
//!   `src/packages/shared/src/json-schema-normalize.ts`); everything outside
//!   the approved asymmetries must match exactly.
//!
//! Built only when the `envelope-schema` feature is enabled (this example's
//! `required-features`), so schemars stays out of every binary's dependency
//! graph (verify with `cargo tree -e normal -p chromium-bridge`).
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --features envelope-schema \
//!     --example emit_envelope_schema

use chromium_bridge_core::protocol::{AdminControl, BridgeReq, BridgeResp, EnclaveControl};

fn main() {
    let out = serde_json::json!({
        "request": schemars::schema_for!(BridgeReq),
        "response": schemars::schema_for!(BridgeResp),
        // The host-handled control frames (ADR-0021/0025/0030/0031). Emitted
        // as the whole internally-tagged enums; the parity script splits them
        // per `type` tag and diffs each host->extension frame against its
        // hand-written Zod validator in src/packages/shared/src/enclave.ts
        // (AdminControl embeds allowlist::ClientEntry, covered inline).
        "enclave": schemars::schema_for!(EnclaveControl),
        "admin": schemars::schema_for!(AdminControl),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
