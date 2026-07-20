//! "Install command-line tool" (VS Code-style), the `claude mcp add`
//! snippet, and the bundled-extension pointers. The CLI install is one
//! symlink under the user's own `~/.local/bin`, explicit and reversible:
//! install and remove only ever touch a SYMLINK whose target binary is named
//! `chromium-bridge` - a regular file or any other symlink at that path is
//! refused and left in place, mirroring the registration engine's
//! fail-closed posture toward files we did not write.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::host;

/// The symlink name on PATH; identical to the CLI binary's own name so
/// `chromium-bridge doctor` etc. read naturally.
const LINK_NAME: &str = "chromium-bridge";

/// The symlink's assessed state: `installed` (a symlink to a chromium-bridge
/// binary), `missing`, or `foreign` (something else occupies the path; we
/// will not touch it). An enum rather than a string so the generated TS
/// carries the literal union straight from the serde attribute.
#[derive(Serialize, Clone, Copy)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Installed,
    Missing,
    Foreign,
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct CliToolStatus {
    /// Where the link lives (or would live): `~/.local/bin/chromium-bridge`.
    pub path: String,
    pub state: LinkState,
    /// The link's current target, when installed.
    pub target: Option<String>,
    /// Whether the link's target is exactly the host this app bundles (an
    /// older install or a dev build shows `installed` but not current).
    pub current: bool,
}

fn bin_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("HOME is not set to an absolute path")?;
    Ok(home.join(".local/bin"))
}

fn link_path() -> Result<PathBuf, String> {
    Ok(bin_dir()?.join(LINK_NAME))
}

/// Whether `target` is something this feature may replace or remove: any
/// path whose final component is the chromium-bridge binary. Deliberately
/// tolerant of older bundle locations and dev-build targets - they are all
/// installs of this tool - and nothing else.
fn is_our_target(target: &Path) -> bool {
    target.file_name().is_some_and(|n| n == LINK_NAME)
}

pub fn status() -> Result<CliToolStatus, String> {
    let link = link_path()?;
    let path = link.display().to_string();
    let meta = match std::fs::symlink_metadata(&link) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CliToolStatus {
                path,
                state: LinkState::Missing,
                target: None,
                current: false,
            });
        }
        Err(e) => return Err(format!("cannot inspect {path}: {e}")),
        Ok(m) => m,
    };
    if !meta.file_type().is_symlink() {
        return Ok(CliToolStatus {
            path,
            state: LinkState::Foreign,
            target: None,
            current: false,
        });
    }
    let target = std::fs::read_link(&link).map_err(|e| format!("cannot read {path}: {e}"))?;
    if !is_our_target(&target) {
        return Ok(CliToolStatus {
            path,
            state: LinkState::Foreign,
            target: Some(target.display().to_string()),
            current: false,
        });
    }
    let current = host::resolve_host().is_ok_and(|h| h == target);
    Ok(CliToolStatus {
        path,
        state: LinkState::Installed,
        target: Some(target.display().to_string()),
        current,
    })
}

/// Remove the link only when it is, right now, a symlink to a
/// chromium-bridge binary. The verify and the unlink are back to back in one
/// place; the remaining check-to-unlink gap is the conceded same-user
/// boundary (threat #4), the same residual the registration engine names.
/// `Ok(false)` means there was nothing to remove.
fn remove_verified_link(link: &Path) -> Result<bool, String> {
    let meta = match std::fs::symlink_metadata(link) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("cannot inspect {}: {e}", link.display())),
        Ok(m) => m,
    };
    if !meta.file_type().is_symlink() {
        return Err(format!(
            "{} is not a chromium-bridge symlink; refusing to remove it",
            link.display()
        ));
    }
    let target =
        std::fs::read_link(link).map_err(|e| format!("cannot read {}: {e}", link.display()))?;
    if !is_our_target(&target) {
        return Err(format!(
            "{} is not a chromium-bridge symlink; refusing to remove it",
            link.display()
        ));
    }
    std::fs::remove_file(link).map_err(|e| format!("could not remove {}: {e}", link.display()))?;
    Ok(true)
}

/// Create (or refresh) the symlink to the bundled host. Refuses to replace
/// anything that is not a chromium-bridge symlink.
pub fn install() -> Result<CliToolStatus, String> {
    let target = host::resolve_host()?;
    let link = link_path()?;
    remove_verified_link(&link)?;
    if let Some(dir) = link.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link)
            .map_err(|e| format!("could not create {}: {e}", link.display()))?;
        status()
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Err("installing the CLI symlink is not supported on this platform yet".to_string())
    }
}

/// Remove the symlink - only when it is verifiably ours.
pub fn uninstall() -> Result<CliToolStatus, String> {
    let link = link_path()?;
    remove_verified_link(&link)?;
    status()
}

// ---- MCP snippet and extension pointers --------------------------------------

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct McpSnippet {
    pub host_path: String,
    /// The copy-paste command for Claude Code.
    pub command: String,
}

/// Single-quote a path for a shell snippet (same defusal as the wrapper
/// generator: embedded single quotes become `'\''`).
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub fn mcp_snippet() -> Result<McpSnippet, String> {
    let host = host::resolve_host()?;
    let host_path = host.display().to_string();
    Ok(McpSnippet {
        command: format!(
            "claude mcp add chromium-bridge -- {}",
            shell_quote(&host_path)
        ),
        host_path,
    })
}

#[derive(Serialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[serde(rename_all = "camelCase")]
pub struct ExtensionInfo {
    pub path: Option<String>,
    pub exists: bool,
}

/// Where the unpacked extension lives: bundled under the app's Resources in
/// the signed build, the workspace WXT output in development (a compile-time
/// path, valid only on the machine that built this binary - exactly the dev
/// case). Only a directory that actually holds a manifest.json counts: the
/// user is about to point "Load unpacked" at it.
pub fn extension_dir() -> Option<PathBuf> {
    let loadable = |p: PathBuf| p.join("manifest.json").is_file().then_some(p);
    if let Ok(exe) = std::env::current_exe() {
        if let Some(contents) = exe.parent().and_then(Path::parent) {
            if let Some(bundled) = loadable(contents.join("Resources/extension")) {
                return Some(bundled);
            }
        }
    }
    let dev = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../build/extension/chrome-mv3");
    dev.canonicalize().ok().and_then(loadable)
}

pub fn extension_info() -> ExtensionInfo {
    match extension_dir() {
        Some(p) => ExtensionInfo {
            path: Some(p.display().to_string()),
            exists: true,
        },
        None => ExtensionInfo {
            path: None,
            exists: false,
        },
    }
}

/// Reveal a directory in the platform file manager. Only ever called with
/// paths this module resolved itself (the extension dir, the audit log's
/// directory); the webview cannot pass an arbitrary path.
pub fn reveal(path: &Path) -> Result<(), String> {
    let (cmd, args): (&str, Vec<&std::ffi::OsStr>) = if cfg!(target_os = "macos") {
        ("open", vec![path.as_os_str()])
    } else if cfg!(windows) {
        ("explorer", vec![path.as_os_str()])
    } else {
        ("xdg-open", vec![path.as_os_str()])
    };
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| format!("could not run {cmd}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd} exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_chromium_bridge_targets_are_ours() {
        assert!(is_our_target(Path::new(
            "/Applications/Chromium Bridge.app/Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge"
        )));
        assert!(is_our_target(Path::new("/w/target/debug/chromium-bridge")));
        assert!(!is_our_target(Path::new("/usr/local/bin/other-tool")));
        assert!(!is_our_target(Path::new("/x/chromium-bridge-desktop")));
    }

    #[test]
    fn snippet_quotes_the_bundle_path() {
        assert_eq!(shell_quote("/a/plain"), "'/a/plain'");
        assert_eq!(
            shell_quote("/Applications/Chromium Bridge.app/x"),
            "'/Applications/Chromium Bridge.app/x'"
        );
        assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    }

    #[cfg(unix)]
    #[test]
    fn remove_verified_link_is_fail_closed() {
        // Fixtures in a temp tree, never the real ~/.local/bin.
        let root = std::env::temp_dir().join(format!("bb-clitool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Missing: nothing to remove, not an error.
        assert_eq!(remove_verified_link(&root.join("absent")), Ok(false));

        // A regular file with the right name is refused and left in place.
        let regular = root.join(LINK_NAME);
        std::fs::write(&regular, b"#!/bin/sh\n").unwrap();
        assert!(remove_verified_link(&regular).is_err());
        assert!(regular.exists());

        // A symlink to something that is not a chromium-bridge binary is
        // refused and left in place.
        let foreign = root.join("foreign-link");
        std::os::unix::fs::symlink(root.join("other-tool"), &foreign).unwrap();
        assert!(remove_verified_link(&foreign).is_err());
        assert!(std::fs::symlink_metadata(&foreign).is_ok());

        // A symlink to a chromium-bridge binary (even dangling) is ours and
        // is removed.
        let ours = root.join("ours-link");
        std::os::unix::fs::symlink(root.join("bundle/chromium-bridge"), &ours).unwrap();
        assert_eq!(remove_verified_link(&ours), Ok(true));
        assert!(std::fs::symlink_metadata(&ours).is_err());

        std::fs::remove_dir_all(&root).unwrap();
    }
}
