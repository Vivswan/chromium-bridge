//! Emit the canonical cross-process contract as one JSON document on stdout:
//! the tool catalogue (each tool's metadata, grants, and the JSON Schema of
//! its args struct), the error taxonomy, the capability groupings, the
//! identity constants, the protocol versions, the extension-forwarded
//! audit kinds, the refusal-code roster, and the host's user-facing constants (the names and values
//! the docs and the CLI state). `scripts/gen-ops.ts` (run via `moon run gen`)
//! consumes this to generate the TypeScript side (`src/packages/shared/generated/`);
//! the emitted JSON itself is never checked in - the Rust sources are the
//! contract.
//!
//! Run:
//!   cargo run -q -p chromium-bridge-core --example emit_contract

use chromium_bridge_core::audit::{extension_kind_wire_names, DEFAULT_AUDIT_LIMIT};
use chromium_bridge_core::browsers::Browser;
use chromium_bridge_core::enclave::KEY_LABEL;
use chromium_bridge_core::error::ERROR_SPECS;
use chromium_bridge_core::identity::{EXTENSION_MANIFEST_KEY, NATIVE_HOST_ID, PINNED_EXTENSION_ID};
use chromium_bridge_core::ipc::LOCK_FILENAME;
use chromium_bridge_core::log::{Format, Level, FORMAT_ENV, LEVEL_ENV};
use chromium_bridge_core::mcp_server::CLIENT_NAME_ENV;
use chromium_bridge_core::protocol::control::MAX_AUDIT_READ_LIMIT;
use chromium_bridge_core::protocol::{
    BRIDGE_PROTOCOL_VERSION, MCP_META_CLIENT_CAPABILITIES, MCP_META_PROTOCOL_VERSION,
    MCP_META_SERVER_INFO, MCP_PROTOCOL_VERSION,
};
use chromium_bridge_core::tools::{all, capabilities};
use chromium_bridge_core::webauthn::RefusalCode;
use serde_json::{json, Value};
use strum::VariantArray;

fn main() -> Result<(), serde_json::Error> {
    let tools: Vec<Value> = all()
        .map(|t| {
            json!({
                "name": t.name,
                "risk": t.risk.as_str(),
                "scope": t.scope_name(),
                "permission": t.permission.as_str(),
                "confirmation": t.confirmation.as_str(),
                "grants": t.grants.iter().map(|g| g.field().wire_name()).collect::<Vec<_>>(),
                "description": t.description,
                "argsSchema": t.args_schema(),
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

    let capabilities: Vec<Value> = capabilities()
        .iter()
        .map(|c| {
            json!({
                "id": c.id.as_str(),
                "description": c.description,
                "permissions": c.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "tools": c.id.tools().map(|t| t.name).collect::<Vec<_>>(),
            })
        })
        .collect();

    let out = json!({
        "protocolVersion": BRIDGE_PROTOCOL_VERSION,
        "mcpProtocolVersion": MCP_PROTOCOL_VERSION,
        "mcpMetaKeys": {
            "protocolVersion": MCP_META_PROTOCOL_VERSION,
            "clientCapabilities": MCP_META_CLIENT_CAPABILITIES,
            "serverInfo": MCP_META_SERVER_INFO,
        },
        "auditForwardedKinds": extension_kind_wire_names(),
        "refusalCodes": RefusalCode::VARIANTS.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "identity": {
            "nativeMessagingHostId": NATIVE_HOST_ID,
            "extensionManifestKey": EXTENSION_MANIFEST_KEY,
            "pinnedExtensionId": PINNED_EXTENSION_ID,
        },
        "tools": tools,
        "errors": errors,
        "capabilities": capabilities,
        "host": {
            "keychainLabel": KEY_LABEL,
            "lockFilename": LOCK_FILENAME,
            "clientNameEnv": CLIENT_NAME_ENV,
            "logLevelEnv": LEVEL_ENV,
            "logLevels": Level::ALL.map(Level::name),
            "logFormatEnv": FORMAT_ENV,
            "logFormats": Format::ALL.map(Format::name),
            "auditDefaultLimit": DEFAULT_AUDIT_LIMIT,
            "auditReadMaxLimit": MAX_AUDIT_READ_LIMIT,
            "browserKeys": Browser::ALL.map(Browser::key),
        },
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
