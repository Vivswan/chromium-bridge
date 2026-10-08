//! The wrapper scripts Unix manifests launch: the shell quoting that writes them, and the exact trampoline
//! shape by which `uninstall` recognizes one as ours before deleting it.

use std::fs;
use std::path::Path;

use super::{Removal, WRAPPER_MARKER, WRAPPER_SHEBANG};
use crate::browsers::Browser;

/// Split one line of wrapper shell into its literal tokens. Understands only
/// what our generators ever emit: bare words, backslash escapes, and
/// single-quoted segments. Any construct with evaluation semantics in an
/// unquoted context (`$`, backticks, `;`, `&`, `|`, parens, redirection,
/// double quotes) returns `None`: the line is not shell-literal, so it cannot
/// be one of ours.
fn split_shell_literal(line: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => current.push(ch),
                        None => return None, // unterminated quote
                    }
                }
            }
            '\\' => {
                in_token = true;
                current.push(chars.next()?);
            }
            // Evaluation semantics (substitution, control operators,
            // redirection) and word expansion (glob, brace, tilde, history):
            // any of these unquoted means the line is not shell-literal.
            '$' | '`' | ';' | '&' | '|' | '(' | ')' | '<' | '>' | '"' | '*' | '?' | '[' | ']'
            | '{' | '}' | '~' | '!' => return None,
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            c => {
                in_token = true;
                current.push(c);
            }
        }
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

/// Whether wrapper-script `contents` are something this project wrote: the
/// bash shebang, the marker line, optionally further comment/blank lines, and
/// exactly ONE payload line whose literal tokens are exactly
/// `exec <path> --native-host [--label <valid-label>]` -- the trampoline
/// shape this engine generates, and nothing that does more than launch the host.
pub(super) fn wrapper_is_ours(contents: &str) -> bool {
    let mut lines = contents.lines();
    if lines.next() != Some(WRAPPER_SHEBANG) {
        return false;
    }
    if lines.next() != Some(WRAPPER_MARKER) {
        return false;
    }
    let mut seen_trampoline = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(tokens) = split_shell_literal(trimmed) else {
            return false;
        };
        let is_trampoline = match tokens.as_slice() {
            [exec, _path, flag] => exec == "exec" && flag == "--native-host",
            [exec, _path, flag, label_flag, label] => {
                exec == "exec"
                    && flag == "--native-host"
                    && label_flag == "--label"
                    && crate::ipc::validate_label(label)
            }
            _ => false,
        };
        if !is_trampoline || seen_trampoline {
            return false;
        }
        seen_trampoline = true;
    }
    seen_trampoline
}

/// Remove the wrapper scripts this engine writes (exact, project-unique names
/// only), each verified by [`wrapper_is_ours`] before deletion.
pub fn remove_wrappers(install_dir: &Path) -> Removal {
    let mut removal = Removal::default();
    let mut names = vec!["run-host.sh".to_string()];
    names.extend(
        Browser::ALL
            .iter()
            .map(|b| format!("run-host-{}.sh", b.key())),
    );
    for name in names {
        let path = install_dir.join(name);
        let contents = match fs::read_to_string(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                removal.refused.push(format!(
                    "could not read {}: {e} (left in place)",
                    path.display()
                ));
                continue;
            }
            Ok(c) => c,
        };
        if wrapper_is_ours(&contents) {
            match fs::remove_file(&path) {
                Ok(()) => removal
                    .lines
                    .push(format!("removed wrapper {}", path.display())),
                Err(e) => removal
                    .failed
                    .push(format!("could not remove {}: {e}", path.display())),
            }
        } else {
            removal.refused.push(format!(
                "refusing to remove {}: not a genkan wrapper (left in place)",
                path.display()
            ));
        }
    }
    // Drop the dir only when now empty; remove_dir never deletes contents.
    let _ = fs::remove_dir(install_dir);
    removal
}

/// Quote `s` for safe inclusion in the wrapper's bash `exec` line: wrapped in
/// single quotes, embedded single quotes escaped as `'\''`.
pub(super) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
