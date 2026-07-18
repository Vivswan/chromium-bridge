//! chromium-bridge-desktop - the Tauri v2 control panel (ADR-0029).
//!
//! The app is a management surface, co-equal with the CLI: every mutating
//! action goes through `chromium_bridge_core`'s engines (registration, kill
//! switch, allowlist) or through the bundled host binary as a subprocess
//! (Secure Enclave operations - the app itself carries no keychain
//! entitlements, ADR-0026). No enforcement decision lives in this crate or
//! in its webview: the UI can only ask; core and the host decide, fail
//! closed, and audit.
//!
//! Commands are `async` so their file/subprocess I/O never runs on the main
//! (window) thread; the Enclave commands additionally use `spawn_blocking`
//! because they block on a Touch ID prompt for as long as the user takes.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cli_tool;
mod clients;
mod host;
mod killswitch;
mod presence_seam;
mod registration_cmds;
mod status;

use serde::Serialize;

/// Run blocking work off the async runtime's reactor, flattening the join
/// error into the command's error string.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("internal task error: {e}"))?
}

// ---- status -------------------------------------------------------------------

#[tauri::command]
async fn bridge_status() -> Result<status::BridgeStatus, String> {
    blocking(|| Ok(status::gather())).await
}

// ---- enclave (via the bundled host subprocess) ----------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnclaveOutcome {
    ok: bool,
    /// The host subcommand's own words, verbatim (stdout + stderr).
    transcript: String,
    /// Fresh `enclave-status --json` after the operation, when readable.
    status: Option<serde_json::Value>,
}

fn run_enclave_op(args: &'static [&'static str]) -> Result<EnclaveOutcome, String> {
    let run = host::run_host(args)?;
    Ok(EnclaveOutcome {
        ok: run.ok,
        transcript: run.transcript(),
        status: host::enclave_status_value().ok(),
    })
}

#[tauri::command]
async fn enclave_status() -> Result<serde_json::Value, String> {
    blocking(host::enclave_status_value).await
}

/// The enrollment ceremony (`pair` / `pair --reset`): raises the real Touch
/// ID prompt from the signed host. The returned status carries the
/// fingerprint for the user to compare against the extension's enrollment
/// screen - the same one `pair` prints.
#[tauri::command]
async fn enclave_pair(reset: bool) -> Result<EnclaveOutcome, String> {
    blocking(move || {
        run_enclave_op(if reset {
            &["pair", "--reset"]
        } else {
            &["pair"]
        })
    })
    .await
}

#[tauri::command]
async fn enclave_revoke() -> Result<EnclaveOutcome, String> {
    blocking(|| run_enclave_op(&["revoke"])).await
}

// ---- native-messaging registration ---------------------------------------------

#[tauri::command]
async fn browsers_list() -> Result<Vec<registration_cmds::BrowserRow>, String> {
    blocking(registration_cmds::list).await
}

#[tauri::command]
async fn browser_register(key: String) -> Result<Vec<String>, String> {
    blocking(move || registration_cmds::register_browser(&key)).await
}

#[tauri::command]
async fn browser_unregister(key: String) -> Result<String, String> {
    blocking(move || registration_cmds::unregister_browser(&key)).await
}

#[tauri::command]
async fn manifest_dir_register(dir: String) -> Result<Vec<String>, String> {
    blocking(move || registration_cmds::register_manifest_dir(&dir)).await
}

#[tauri::command]
async fn manifest_dir_unregister(dir: String) -> Result<String, String> {
    blocking(move || registration_cmds::unregister_manifest_dir(&dir)).await
}

#[tauri::command]
async fn first_launch_register() -> Result<Option<registration_cmds::FirstRunReport>, String> {
    blocking(registration_cmds::first_launch_register).await
}

// ---- kill switch + audit --------------------------------------------------------

#[tauri::command]
async fn kill_engage() -> Result<u64, String> {
    blocking(killswitch::engage).await
}

#[tauri::command]
async fn kill_release() -> Result<u64, String> {
    blocking(killswitch::release).await
}

#[tauri::command]
async fn audit_read(limit: usize) -> Result<killswitch::AuditPage, String> {
    // Bound the page like the CLI bounds --limit: the file is size-capped,
    // but the webview does not need more than one screenful of history.
    let limit = limit.clamp(1, 2000);
    blocking(move || killswitch::read(limit)).await
}

// ---- trusted clients --------------------------------------------------------------

#[tauri::command]
async fn clients_list() -> Result<clients::ClientsPayload, String> {
    blocking(clients::list).await
}

#[tauri::command]
async fn client_revoke(name: String) -> Result<bool, String> {
    blocking(move || clients::revoke(&name)).await
}

#[tauri::command]
async fn client_pair(
    name: String,
    anchor_kind: String,
    anchor_value: String,
) -> Result<(), String> {
    blocking(move || clients::pair(&name, &anchor_kind, &anchor_value)).await
}

// ---- CLI tool, MCP snippet, extension ------------------------------------------

#[tauri::command]
async fn cli_tool_status() -> Result<cli_tool::CliToolStatus, String> {
    blocking(cli_tool::status).await
}

#[tauri::command]
async fn cli_tool_install() -> Result<cli_tool::CliToolStatus, String> {
    blocking(cli_tool::install).await
}

#[tauri::command]
async fn cli_tool_uninstall() -> Result<cli_tool::CliToolStatus, String> {
    blocking(cli_tool::uninstall).await
}

#[tauri::command]
async fn mcp_snippet() -> Result<cli_tool::McpSnippet, String> {
    blocking(cli_tool::mcp_snippet).await
}

#[tauri::command]
async fn extension_info() -> Result<cli_tool::ExtensionInfo, String> {
    blocking(|| Ok(cli_tool::extension_info())).await
}

#[tauri::command]
async fn extension_reveal() -> Result<(), String> {
    blocking(|| {
        let dir =
            cli_tool::extension_dir().ok_or("the unpacked extension directory was not found")?;
        cli_tool::reveal(&dir)
    })
    .await
}

#[tauri::command]
async fn audit_reveal() -> Result<(), String> {
    blocking(|| {
        let path = chromium_bridge_core::audit::audit_path();
        let dir = path
            .parent()
            .ok_or("the audit path has no parent directory")?;
        cli_tool::reveal(dir)
    })
    .await
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            bridge_status,
            enclave_status,
            enclave_pair,
            enclave_revoke,
            browsers_list,
            browser_register,
            browser_unregister,
            manifest_dir_register,
            manifest_dir_unregister,
            first_launch_register,
            kill_engage,
            kill_release,
            audit_read,
            clients_list,
            client_revoke,
            client_pair,
            cli_tool_status,
            cli_tool_install,
            cli_tool_uninstall,
            mcp_snippet,
            extension_info,
            extension_reveal,
            audit_reveal,
        ])
        .run(tauri::generate_context!())
        .expect("tauri app failed to start");
}
