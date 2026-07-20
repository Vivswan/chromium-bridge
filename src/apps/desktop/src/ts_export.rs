//! Generates the UI's TypeScript view of this crate's Tauri command DTOs:
//! ui/src/lib/commands.gen.ts, one file, deterministic order. Compiled only
//! under `--features ts-export`. The export runs as a cargo test because
//! ts-rs writes bindings by executing generated code, not during macro
//! expansion - `moon run gen-app-types` deletes the file, runs exactly this
//! test (which must recreate it), and formats the result with Biome. CI's
//! desktop job then regenerates and fails on a stale diff, like the shared
//! *.gen.ts modules.
//!
//! Every exported type must be listed here explicitly; a new command's DTO
//! is added here alongside its `#[derive(TS)]`. Forgetting a type that
//! another declaration references leaves an undefined name in the generated
//! file, which `moon run typecheck` then rejects - a loud failure, not drift.

use std::fmt::Write as _;

use ts_rs::{Config, TS};

const HEADER: &str = "\
// GENERATED from the desktop crate's Tauri command DTOs (src/apps/desktop/src/)
// by the ts-export cargo test (src/apps/desktop/src/ts_export.rs) - DO NOT
// EDIT. Edit the Rust structs, then run `moon run gen`.
//
// Display contracts for the app's own webview (trusted same-author IPC over
// Tauri invoke): static types only, no runtime validators - every decision
// stays in Rust. lib/tauri.ts wraps these in the typed `api` facade.

";

/// Append one exported declaration: the type's own doc comment (as JSDoc),
/// then `export type ... = ...;`.
fn push<T: TS + 'static>(out: &mut String, cfg: &Config) {
    if let Some(docs) = <T as TS>::docs() {
        out.push_str(&docs);
    }
    let _ = writeln!(out, "export {}\n", <T as TS>::decl(cfg));
}

#[test]
fn export_commands_gen_ts() {
    // The u64s here are epochs, timestamps, and counts - far below 2^53, and
    // JSON.parse hands the webview plain numbers - so `number`, not ts-rs's
    // default `bigint`.
    let cfg = Config::new().with_large_int("number");
    let mut out = String::from(HEADER);

    // Status.
    push::<crate::status::KillState>(&mut out, &cfg);
    push::<crate::status::ServerStatus>(&mut out, &cfg);
    push::<crate::status::BridgeStatus>(&mut out, &cfg);
    // Enclave (via the bundled host subprocess). The status report and its
    // nested types come from the core, which the host emits and the app parses
    // back; they must precede EnclaveOutcome, which references the report.
    push::<chromium_bridge_core::enclave::EnclaveKeyState>(&mut out, &cfg);
    push::<chromium_bridge_core::enclave::EnclavePolicyReport>(&mut out, &cfg);
    push::<chromium_bridge_core::enclave::EnclaveStatusReport>(&mut out, &cfg);
    push::<crate::EnclaveOutcome>(&mut out, &cfg);
    // Native-messaging registration.
    push::<crate::registration_cmds::BrowserRow>(&mut out, &cfg);
    push::<crate::registration_cmds::FirstRunReport>(&mut out, &cfg);
    // Kill switch + audit (the record types come from the core, which the
    // commands return verbatim).
    push::<crate::killswitch::ReleaseOutcome>(&mut out, &cfg);
    push::<chromium_bridge_core::audit::AuditKind>(&mut out, &cfg);
    push::<chromium_bridge_core::audit::Surface>(&mut out, &cfg);
    push::<chromium_bridge_core::audit::AuditRecord>(&mut out, &cfg);
    push::<crate::killswitch::AuditLine>(&mut out, &cfg);
    push::<crate::killswitch::AuditPage>(&mut out, &cfg);
    // Trusted clients.
    push::<crate::clients::AnchorKind>(&mut out, &cfg);
    push::<crate::clients::ClientRow>(&mut out, &cfg);
    push::<crate::clients::Posture>(&mut out, &cfg);
    push::<crate::clients::ClientsPayload>(&mut out, &cfg);
    // CLI tool, MCP snippet, extension pointers.
    push::<crate::cli_tool::LinkState>(&mut out, &cfg);
    push::<crate::cli_tool::CliToolStatus>(&mut out, &cfg);
    push::<crate::cli_tool::McpSnippet>(&mut out, &cfg);
    push::<crate::cli_tool::ExtensionInfo>(&mut out, &cfg);

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/ui/src/lib/commands.gen.ts");
    std::fs::write(path, &out).unwrap_or_else(|e| panic!("cannot write {path}: {e}"));
    println!("generated {path} from the Tauri command DTOs");
}
