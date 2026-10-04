//! Emit the JSON Schemas schemars derives from the Rust bridge-envelope wire
//! types, as one JSON object `{ "request": ..., "response": ..., "enclave":
//! ..., "admin": ..., "policy": ..., "webauthn": ... }` on stdout.
//!
//! The Rust types in `protocol.rs` and `protocol/control.rs` are the canonical
//! envelope contract. The request is emitted with its subschemas inlined (no
//! `$defs`): its flattened `BridgeCommand` references one args struct per
//! tool, and the consumer splits the command per op by structure, never by
//! name. One consumer reads this output: `scripts/gen-envelope.ts` (`moon run
//! gen`) generates the extension's wire validators from it
//! (`src/packages/shared/src/envelope.gen.ts`): per envelope and control
//! frame the faithful base and, for the frames the extension reads, the
//! enforced validator, which is that base plus the asymmetry table in
//! `src/packages/shared/src/envelope-asymmetries.ts`; `moon run check-gen`
//! fails on a stale diff and `moon run check-envelope` proves each
//! asymmetry.
//!
//! Built only when the `envelope-schema` feature is enabled (this example's
//! `required-features`), so schemars stays out of every binary's dependency
//! graph (verify with `cargo tree -e normal -p chromium-bridge`).
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --features envelope-schema \
//!     --example emit_envelope_schema

use chromium_bridge_core::protocol::control::{
    AdminControl, EnclaveControl, PolicyControl, WebAuthnControl,
};
use chromium_bridge_core::protocol::{BridgeReq, BridgeResp};

fn inlined_schema_for<T: schemars::JsonSchema>() -> schemars::Schema {
    let mut settings = schemars::generate::SchemaSettings::default();
    settings.inline_subschemas = true;
    settings.into_generator().into_root_schema_for::<T>()
}

fn main() -> Result<(), serde_json::Error> {
    let out = serde_json::json!({
        "request": inlined_schema_for::<BridgeReq>(),
        "response": schemars::schema_for!(BridgeResp),
        // The host-handled control frames, emitted as whole internally-tagged
        // enums; scripts/gen-envelope.ts splits them per `type` tag.
        "enclave": schemars::schema_for!(EnclaveControl),
        "admin": schemars::schema_for!(AdminControl),
        "policy": schemars::schema_for!(PolicyControl),
        "webauthn": schemars::schema_for!(WebAuthnControl),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
