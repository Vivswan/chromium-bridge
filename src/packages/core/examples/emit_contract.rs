//! Emit the canonical cross-process contract as one JSON document on stdout:
//! the tool catalogue, the error taxonomy, the capability groupings, the
//! identity constants, and the bridge protocol version. `scripts/gen-ops.ts`
//! (run via `moon run gen`) consumes this to generate the TypeScript side
//! (`src/packages/shared/src/*.gen.ts`); the emitted JSON itself is never checked
//! in - the Rust sources are the contract (ADR-0028).
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --example emit_contract

use chromium_bridge_core::error::ERROR_SPECS;
use chromium_bridge_core::identity::{EXTENSION_MANIFEST_KEY, NATIVE_HOST_ID, PINNED_EXTENSION_ID};
use chromium_bridge_core::protocol::BRIDGE_PROTOCOL_VERSION;
use chromium_bridge_core::tools::{all, CAPABILITIES};
use serde_json::{json, Value};

fn main() {
    let tools: Vec<Value> = all()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "risk": t.risk.as_str(),
                "scope": t.scope.as_str(),
                "permission": t.permission.as_str(),
                "confirmation": t.confirmation.as_str(),
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();

    let errors: Vec<Value> = ERROR_SPECS
        .iter()
        .map(|e| {
            json!({
                "code": e.code,
                "category": e.category.as_str(),
                "retryable": e.retryable,
                "message": e.message,
            })
        })
        .collect();

    let capabilities: Vec<Value> = CAPABILITIES
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "description": c.description,
                "permissions": c.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "tools": c.tools,
            })
        })
        .collect();

    let out = json!({
        "protocolVersion": BRIDGE_PROTOCOL_VERSION,
        "identity": {
            "nativeMessagingHostId": NATIVE_HOST_ID,
            "extensionManifestKey": EXTENSION_MANIFEST_KEY,
            "pinnedExtensionId": PINNED_EXTENSION_ID,
        },
        "tools": tools,
        "errors": errors,
        "capabilities": capabilities,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
