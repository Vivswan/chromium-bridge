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
mod epochs;
mod host;
mod import_cmds;
mod killswitch;
mod policy_cmds;
mod presence_seam;
mod registration_cmds;
mod status;
#[cfg(all(test, feature = "ts-export"))]
mod ts_export;

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
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
struct EnclaveOutcome {
    ok: bool,
    /// The host subcommand's own words, verbatim (stdout + stderr).
    transcript: String,
    /// Fresh `enclave-status --json` after the operation, when readable. The
    /// typed report the core defines and the host emits (`null` when the
    /// follow-up read failed).
    status: Option<chromium_bridge_core::enclave::EnclaveStatusReport>,
}

fn run_enclave_op(args: &'static [&'static str]) -> Result<EnclaveOutcome, String> {
    let run = host::run_host(args)?;
    Ok(EnclaveOutcome {
        ok: run.ok,
        transcript: run.transcript(),
        status: host::enclave_status_report().ok(),
    })
}

#[tauri::command]
async fn enclave_status() -> Result<chromium_bridge_core::enclave::EnclaveStatusReport, String> {
    blocking(host::enclave_status_report).await
}

/// The enrollment ceremony (`pair` / `pair --reset`): raises the real Touch
/// ID prompt from the signed host. The returned status carries the
/// fingerprint for the user to compare against the extension's enrollment
/// screen - the same one `pair` prints. The argv comes from the core's
/// `cli::argv` consts, the same spellings its parser matches, so a renamed
/// subcommand is a compile-time break here rather than a runtime dead button.
#[tauri::command]
async fn enclave_pair(reset: bool) -> Result<EnclaveOutcome, String> {
    use chromium_bridge_core::cli::argv;
    blocking(move || {
        run_enclave_op(if reset {
            &[argv::PAIR, argv::RESET_FLAG]
        } else {
            &[argv::PAIR]
        })
    })
    .await
}

#[tauri::command]
async fn enclave_revoke() -> Result<EnclaveOutcome, String> {
    blocking(|| run_enclave_op(&[chromium_bridge_core::cli::argv::REVOKE])).await
}

// ---- policy (ADR-0032 decision 5: the app editing surface) ----------------------

#[tauri::command]
async fn policy_status() -> Result<chromium_bridge_core::policy::PolicyStatusReport, String> {
    blocking(|| Ok(chromium_bridge_core::policy::gather_policy_status())).await
}

#[tauri::command]
async fn policy_history() -> Result<chromium_bridge_core::policy::PolicyHistoryReport, String> {
    blocking(chromium_bridge_core::policy::gather_history_report).await
}

/// The deny baseline (the core's canonical defaults): what the editor seeds
/// its draft from while no baseline exists yet, so the webview never
/// hardcodes a policy value.
#[tauri::command]
async fn policy_defaults() -> Result<chromium_bridge_core::policy::PolicyValues, String> {
    blocking(|| Ok(policy_cmds::defaults())).await
}

/// Read-only lane classification for the apply flow: which edited fields
/// relax and which tighten, decided in Rust from the core's direction table.
#[tauri::command]
async fn policy_plan(
    overlay: chromium_bridge_core::policy::PolicyOverlay,
) -> Result<policy_cmds::PolicyPlan, String> {
    blocking(move || policy_cmds::plan(overlay)).await
}

/// The FREE lane: restrictions carry no attestation, so this runs
/// in-process. The seam's direction check refuses anything that would relax.
#[tauri::command]
async fn policy_restrict(
    overlay: chromium_bridge_core::policy::PolicyOverlay,
) -> Result<chromium_bridge_core::policy::PolicyStatusReport, String> {
    blocking(move || policy_cmds::restrict(overlay)).await
}

/// The signed GRANT lane (ADR-0026 / ADR-0032 decision 5). Same dialog-first
/// obligation as `kill_release`: only the app's explicit confirm handler may
/// invoke this, after the user has seen exactly which fields relax. On an
/// enrolled Mac it runs the bundled host subprocess (Touch ID attributes to
/// the signed host); on a GENUINELY unenrolled, Enclave-capable Mac it
/// carries the app's documented interactive floor instead
/// (`presence_seam::APP_POLICY_FLOOR`), storing an unsigned baseline; every
/// other keyless state refuses (fail closed).
#[tauri::command]
async fn policy_set(
    overlay: chromium_bridge_core::policy::PolicyOverlay,
) -> Result<policy_cmds::PolicyOutcome, String> {
    blocking(move || policy_cmds::set(overlay)).await
}

/// Rollback via the bundled host subprocess: a relaxing rollback raises the
/// host's Touch ID sheet, so the same dialog-first obligation applies.
#[tauri::command]
async fn policy_rollback(revision: u64) -> Result<policy_cmds::PolicyOutcome, String> {
    blocking(move || policy_cmds::rollback(revision)).await
}

// ---- first-run legacy import (ADR-0032 decision 8) -------------------------------

/// The pending legacy-import state, read from the bundled host
/// (`policy pending-import --json`, READ-ONLY) with a present bag already
/// mapped to a reviewable suggestion. Consuming happens only when revision 1
/// signs (`policy_adopt` / `policy_set`), never here.
#[tauri::command]
async fn pending_import() -> Result<import_cmds::PendingImportSurvey, String> {
    blocking(import_cmds::survey).await
}

/// The import screen's Adopt: `policy_set` behind a first-baseline gate, so
/// the reviewed suggestion can only ever become revision 1 (which consumes
/// the pending import). Same dialog-first obligation as `policy_set`.
#[tauri::command]
async fn policy_adopt(
    overlay: chromium_bridge_core::policy::PolicyOverlay,
) -> Result<policy_cmds::PolicyOutcome, String> {
    blocking(move || policy_cmds::adopt(overlay)).await
}

// ---- shared language (ADR-0032 decision 7) ----------------------------------------

#[tauri::command]
async fn lang_current() -> Result<epochs::LangState, String> {
    blocking(epochs::lang_current).await
}

/// USER GESTURE ONLY: the webview may call this exclusively from the
/// language picker's click handler, never from the path that applies an
/// incoming `lang-epoch-changed` event (the echo-loop rule, decision 7).
#[tauri::command]
async fn lang_set(value: String) -> Result<epochs::LangState, String> {
    blocking(move || epochs::lang_set(&value)).await
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

/// Detection only (ADR-0029 as amended): reports the browsers found on the
/// first launch and writes nothing into any browser's configuration.
/// Connecting a browser is always an explicit user action through
/// `browser_register`.
#[tauri::command]
async fn first_launch_detect() -> Result<Option<registration_cmds::FirstRunReport>, String> {
    blocking(registration_cmds::first_launch_detect).await
}

// ---- kill switch + audit --------------------------------------------------------

#[tauri::command]
async fn kill_engage() -> Result<u64, String> {
    blocking(killswitch::engage).await
}

/// Presence-gated. Same dialog-first obligation as `client_pair`: only the
/// modal's confirm handler may invoke this.
#[tauri::command]
async fn kill_release() -> Result<killswitch::ReleaseOutcome, String> {
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

/// Presence-gated. The webview may only invoke this from the confirm
/// handler of its explicit modal dialog - the dialog is what
/// `Floor::AppConfirm` asserts. Returns the presence path that authorized
/// the pairing. `anchor_kind` deserializes into the typed [`clients::AnchorKind`],
/// so an unknown kind is refused by serde before the handler runs.
#[tauri::command]
async fn client_pair(
    name: String,
    anchor_kind: clients::AnchorKind,
    anchor_value: String,
) -> Result<&'static str, String> {
    blocking(move || clients::pair(&name, anchor_kind, &anchor_value)).await
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
    let outcome = tauri::Builder::default()
        .setup(|app| {
            // One background watch for both epochs (D-P4-1): policy_epoch
            // for the editor and the import screen, lang_epoch for the
            // language sync. Events are change notices; commands stay
            // pull-based.
            epochs::spawn_epoch_watch(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bridge_status,
            enclave_status,
            enclave_pair,
            enclave_revoke,
            policy_status,
            policy_history,
            policy_defaults,
            policy_plan,
            policy_restrict,
            policy_set,
            policy_rollback,
            pending_import,
            policy_adopt,
            lang_current,
            lang_set,
            browsers_list,
            browser_register,
            browser_unregister,
            manifest_dir_register,
            manifest_dir_unregister,
            first_launch_detect,
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
        .run(tauri::generate_context!());
    if let Err(e) = outcome {
        eprintln!("chromium-bridge-desktop failed to start: {e}");
        std::process::exit(1);
    }
}
