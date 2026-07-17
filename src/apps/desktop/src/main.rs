//! chromium-bridge-desktop - the Tauri v2 control-panel shell.
//!
//! Phase 6 signing spike: this app exists to prove the signing and
//! entitlement chain for the bundled `chromium-bridge` host binary (the
//! Secure Enclave toucher). It depends on `chromium-bridge-core` only,
//! never on the host crate; every enforcement decision stays in Rust in
//! core/host (ADR-0023). The real control-panel UI is Phase 9.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// The enclave keychain label, read from core. Exists to prove the
/// app -> core linkage the workspace layout promises.
#[tauri::command]
fn enclave_key_label() -> &'static str {
    chromium_bridge_core::enclave::KEY_LABEL
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![enclave_key_label])
        .run(tauri::generate_context!())
        .expect("tauri app failed to start");
}
