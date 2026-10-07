//! Emit the JSON Schemas schemars derives from the Rust bridge-envelope wire
//! types, as one JSON object `{ "request": ..., "response": ..., "signal": ...,
//! "enclave": ..., "admin": ..., "policy": ..., "webauthn": ... }` on stdout.
//!
//! The Rust types in `protocol.rs` and `protocol/control.rs` are the canonical
//! envelope contract. The request is emitted with its subschemas inlined (no
//! `$defs`): its flattened `BridgeCommand` references one args struct per
//! tool, and the consumer splits the command per op by structure, never by
//! name. One consumer reads this output: `scripts/gen-envelope.ts` (`moon run
//! gen`) generates the extension's wire validators from it
//! (`src/packages/shared/generated/envelope.ts`): per envelope and control
//! frame the faithful base and, for the frames the extension reads, the
//! enforced validator, which is that base plus the asymmetry table in
//! `src/packages/shared/src/envelope-asymmetries.ts`; `moon run
//! check-envelope` proves each asymmetry.
//!
//! Built only when the `envelope-schema` feature is enabled (this example's
//! `required-features`), so schemars stays out of every binary's dependency
//! graph (verify with `cargo tree -e normal -p chromium-bridge`).
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --features envelope-schema \
//!     --example emit_envelope_schema

use std::error::Error;

use chromium_bridge_core::protocol::control::{
    AdminControl, Direction, EnclaveControl, HostControlTag, PolicyControl, WebAuthnControl,
};
use chromium_bridge_core::protocol::{BridgeReq, BridgeResp, BridgeSignal};

fn inlined_schema_for<T: schemars::JsonSchema>() -> schemars::Schema {
    let mut settings = schemars::generate::SchemaSettings::default();
    settings.inline_subschemas = true;
    settings.into_generator().into_root_schema_for::<T>()
}

/// Every control tag with the way it travels, from the tag enum's own schema (its one derived
/// enumeration), so the generator can hold its reader/writer plan to this table: a browser->host
/// frame is one the extension writes, a host->browser frame one it reads.
fn directions() -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn Error>> {
    let schema = serde_json::to_value(schemars::schema_for!(HostControlTag))?;
    let tags = schema
        .get("enum")
        .and_then(serde_json::Value::as_array)
        .ok_or("HostControlTag's schema is not an enum of its tags")?;
    tags.iter()
        .map(|tag| {
            let name = tag.as_str().ok_or("a tag is not a string")?;
            let parsed: HostControlTag = serde_json::from_value(tag.clone())?;
            let direction = match parsed.direction() {
                Direction::BrowserToHost => "browser_to_host",
                Direction::HostToBrowser => "host_to_browser",
            };
            Ok((
                name.to_string(),
                serde_json::Value::String(direction.to_string()),
            ))
        })
        .collect()
}

fn main() -> Result<(), Box<dyn Error>> {
    let out = serde_json::json!({
        "request": inlined_schema_for::<BridgeReq>(),
        "response": schemars::schema_for!(BridgeResp),
        // Server->extension frames beside the request (`cancel`), relayed by the host; the generator
        // emits one strict reader per variant, like the envelopes.
        "signal": schemars::schema_for!(BridgeSignal),
        // The host-handled control frames, emitted as whole internally-tagged
        // enums; scripts/gen-envelope.ts splits them per `type` tag.
        "enclave": schemars::schema_for!(EnclaveControl),
        "admin": schemars::schema_for!(AdminControl),
        "policy": schemars::schema_for!(PolicyControl),
        "webauthn": schemars::schema_for!(WebAuthnControl),
        // Which way each control tag travels; the generator refuses a plan that disagrees.
        "directions": directions()?,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
